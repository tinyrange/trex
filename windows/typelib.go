package windows

import (
	"encoding/binary"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"strings"

	"go.starlark.net/starlark"
)

const (
	msftTypeLibHeaderSize   = 0x54
	msftTypeLibSegmentCount = 15
	msftTypeInfoSize        = 0x64
	msftTypeInfoSegment     = 0
	msftGUIDSegment         = 5
	msftNameSegment         = 7
	msftStringSegment       = 8
	msftTypeKindDispatch    = 4
	msftTypeFlagDual        = 0x40
	msftTypeFlagAutomation  = 0x100
	msftTypeLibHelpDLLFlag  = 0x100
)

type msftTypeLibSegment struct {
	offset int
	length int
}

type msftTypeInfo struct {
	guid  string
	name  string
	kind  uint32
	flags uint32
}

type msftTypeLib struct {
	guid        string
	name        string
	description string
	major       uint16
	minor       uint16
	language    uint32
	lcid        uint32
	flags       uint32
	syskind     uint32
	typeInfo    []msftTypeInfo
}

func peTypeLibsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("pe_typelibs", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("pe_typelibs: got %s, want file", value.Type())
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, err
	}
	libraries, err := msftTypeLibsFromPE(data)
	if err != nil {
		return nil, fmt.Errorf("pe_typelibs: %w", err)
	}
	values := make([]starlark.Value, 0, len(libraries))
	for _, library := range libraries {
		types := make([]starlark.Value, 0, len(library.typeInfo))
		for _, info := range library.typeInfo {
			row := starlark.NewDict(4)
			for name, value := range map[string]starlark.Value{
				"guid":  starlark.String(info.guid),
				"name":  starlark.String(info.name),
				"kind":  starlark.MakeUint(uint(info.kind)),
				"flags": starlark.MakeUint(uint(info.flags)),
			} {
				if err := row.SetKey(starlark.String(name), value); err != nil {
					return nil, err
				}
			}
			types = append(types, row)
		}
		row := starlark.NewDict(10)
		for name, value := range map[string]starlark.Value{
			"guid":        starlark.String(library.guid),
			"name":        starlark.String(library.name),
			"description": starlark.String(library.description),
			"major":       starlark.MakeUint(uint(library.major)),
			"minor":       starlark.MakeUint(uint(library.minor)),
			"language":    starlark.MakeUint(uint(library.language)),
			"lcid":        starlark.MakeUint(uint(library.lcid)),
			"flags":       starlark.MakeUint(uint(library.flags)),
			"syskind":     starlark.MakeUint(uint(library.syskind)),
			"types":       starlark.NewList(types),
		} {
			if err := row.SetKey(starlark.String(name), value); err != nil {
				return nil, err
			}
		}
		values = append(values, row)
	}
	return starlark.NewList(values), nil
}

func msftTypeLibsFromPE(data []byte) ([]msftTypeLib, error) {
	resources, err := peResources(data)
	if err != nil {
		return nil, err
	}
	var libraries []msftTypeLib
	for _, resource := range resources {
		if !strings.EqualFold(resource.typ, "TYPELIB") || len(resource.data) < 4 || string(resource.data[:4]) != "MSFT" {
			continue
		}
		library, err := parseMSFTTypeLib(resource.data)
		if err != nil {
			return nil, fmt.Errorf("TYPELIB %s: %w", resource.name, err)
		}
		libraries = append(libraries, library)
	}
	return libraries, nil
}

func parseMSFTTypeLib(data []byte) (msftTypeLib, error) {
	if len(data) < msftTypeLibHeaderSize || string(data[:4]) != "MSFT" {
		return msftTypeLib{}, fmt.Errorf("invalid MSFT type library header")
	}
	typeCount := int(binary.LittleEndian.Uint32(data[0x20:]))
	if typeCount < 0 || typeCount > 0x10000 {
		return msftTypeLib{}, fmt.Errorf("invalid type information count %d", typeCount)
	}
	segmentOffset := msftTypeLibHeaderSize + typeCount*4
	varFlags := binary.LittleEndian.Uint32(data[0x14:])
	if varFlags&msftTypeLibHelpDLLFlag != 0 {
		segmentOffset += 4
	}
	segments, err := readMSFTTypeLibSegments(data, segmentOffset)
	if err != nil {
		return msftTypeLib{}, err
	}
	guidOffset := int(int32(binary.LittleEndian.Uint32(data[0x08:])))
	nameOffset := int(int32(binary.LittleEndian.Uint32(data[0x38:])))
	guid, err := msftTypeLibGUID(data, segments, guidOffset)
	if err != nil {
		return msftTypeLib{}, fmt.Errorf("library GUID: %w", err)
	}
	name, err := msftTypeLibName(data, segments, nameOffset)
	if err != nil {
		return msftTypeLib{}, fmt.Errorf("library name: %w", err)
	}
	description := name
	descriptionOffset := int(int32(binary.LittleEndian.Uint32(data[0x24:])))
	if descriptionOffset >= 0 {
		description, err = msftTypeLibString(data, segments, descriptionOffset)
		if err != nil {
			return msftTypeLib{}, fmt.Errorf("library description: %w", err)
		}
	}
	version := binary.LittleEndian.Uint32(data[0x18:])
	library := msftTypeLib{
		guid:        guid,
		name:        name,
		description: description,
		major:       uint16(version),
		minor:       uint16(version >> 16),
		language:    binary.LittleEndian.Uint32(data[0x0c:]),
		lcid:        binary.LittleEndian.Uint32(data[0x10:]),
		flags:       binary.LittleEndian.Uint32(data[0x1c:]),
		syskind:     varFlags & 0x0f,
	}
	typeSegment := segments[msftTypeInfoSegment]
	if typeSegment.length < typeCount*msftTypeInfoSize {
		return msftTypeLib{}, fmt.Errorf("type information segment is too short")
	}
	for index := 0; index < typeCount; index++ {
		offset := typeSegment.offset + index*msftTypeInfoSize
		entry := data[offset : offset+msftTypeInfoSize]
		entryGUIDOffset := int(int32(binary.LittleEndian.Uint32(entry[0x2c:])))
		entryNameOffset := int(int32(binary.LittleEndian.Uint32(entry[0x34:])))
		entryGUID := ""
		if entryGUIDOffset >= 0 {
			entryGUID, err = msftTypeLibGUID(data, segments, entryGUIDOffset)
			if err != nil {
				return msftTypeLib{}, fmt.Errorf("type %d GUID: %w", index, err)
			}
		}
		entryName, err := msftTypeLibName(data, segments, entryNameOffset)
		if err != nil {
			return msftTypeLib{}, fmt.Errorf("type %d name: %w", index, err)
		}
		library.typeInfo = append(library.typeInfo, msftTypeInfo{
			guid:  entryGUID,
			name:  entryName,
			kind:  binary.LittleEndian.Uint32(entry) & 0x0f,
			flags: binary.LittleEndian.Uint32(entry[0x30:]),
		})
	}
	return library, nil
}

func readMSFTTypeLibSegments(data []byte, offset int) ([msftTypeLibSegmentCount]msftTypeLibSegment, error) {
	var segments [msftTypeLibSegmentCount]msftTypeLibSegment
	if offset < 0 || offset+msftTypeLibSegmentCount*16 > len(data) {
		return segments, fmt.Errorf("segment directory is outside the type library")
	}
	for index := range segments {
		entry := data[offset+index*16:]
		segmentOffset := int(int32(binary.LittleEndian.Uint32(entry)))
		segmentLength := int(int32(binary.LittleEndian.Uint32(entry[4:])))
		if segmentOffset == -1 && segmentLength == 0 {
			segments[index] = msftTypeLibSegment{offset: -1}
			continue
		}
		if segmentOffset < 0 || segmentLength < 0 || segmentOffset > len(data) || segmentLength > len(data)-segmentOffset {
			return segments, fmt.Errorf("segment %d is outside the type library", index)
		}
		segments[index] = msftTypeLibSegment{offset: segmentOffset, length: segmentLength}
	}
	return segments, nil
}

func msftTypeLibGUID(data []byte, segments [msftTypeLibSegmentCount]msftTypeLibSegment, offset int) (string, error) {
	segment := segments[msftGUIDSegment]
	if segment.offset < 0 || offset < 0 || offset+16 > segment.length {
		return "", fmt.Errorf("offset %#x is outside the GUID segment", offset)
	}
	var raw [16]byte
	copy(raw[:], data[segment.offset+offset:segment.offset+offset+16])
	return windowsGUIDString(raw), nil
}

func msftTypeLibName(data []byte, segments [msftTypeLibSegmentCount]msftTypeLibSegment, offset int) (string, error) {
	segment := segments[msftNameSegment]
	if segment.offset < 0 || offset < 0 || offset+12 > segment.length {
		return "", fmt.Errorf("offset %#x is outside the name segment", offset)
	}
	entry := segment.offset + offset
	length := int(binary.LittleEndian.Uint32(data[entry+8:]) & 0xff)
	if offset+12+length > segment.length {
		return "", fmt.Errorf("entry at %#x extends outside the name segment", offset)
	}
	return string(data[entry+12 : entry+12+length]), nil
}

func msftTypeLibString(data []byte, segments [msftTypeLibSegmentCount]msftTypeLibSegment, offset int) (string, error) {
	segment := segments[msftStringSegment]
	if segment.offset < 0 || offset < 0 || offset+2 > segment.length {
		return "", fmt.Errorf("offset %#x is outside the string segment", offset)
	}
	entry := segment.offset + offset
	length := int(binary.LittleEndian.Uint16(data[entry:]))
	if offset+2+length > segment.length {
		return "", fmt.Errorf("entry at %#x extends outside the string segment", offset)
	}
	return string(data[entry+2 : entry+2+length]), nil
}
