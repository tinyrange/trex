package windows

import (
	"encoding/binary"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"strings"

	"go.starlark.net/starlark"
)

const (
	win9xVXDMaximum        = 16 << 20
	win9xW4ChunkSize       = 8192
	win9xW4MaxChunks       = 1024
	win9xW3HeaderSize      = 0x400
	win9xW3MemberAlignment = 0x1000
)

func win9xVXDUnpackBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var file starfile.File
	if err := starlark.UnpackArgs("win9x_vxd_unpack", args, kwargs, "file", &file); err != nil {
		return nil, err
	}
	if file.Size() < 0 || file.Size() > win9xVXDMaximum {
		return nil, fmt.Errorf("win9x_vxd_unpack: file size %d exceeds %d", file.Size(), win9xVXDMaximum)
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("win9x_vxd_unpack: %w", err)
	}
	data, _, err = unpackWin9xW4(data)
	if err != nil {
		return nil, fmt.Errorf("win9x_vxd_unpack: %w", err)
	}
	return &starfile.Bytes{Name: "unpacked-win9x-vxd", Data: data}, nil
}

type win9xW3Member struct {
	name       string
	offset     int
	headerSize uint32
}

func win9xVXDLibraryMembersBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var file starfile.File
	if err := starlark.UnpackArgs("win9x_vxd_library_members", args, kwargs, "file", &file); err != nil {
		return nil, err
	}
	if file.Size() < 0 || file.Size() > win9xVXDMaximum {
		return nil, fmt.Errorf("win9x_vxd_library_members: file size %d exceeds %d", file.Size(), win9xVXDMaximum)
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("win9x_vxd_library_members: %w", err)
	}
	data, _, err = unpackWin9xW4(data)
	if err != nil {
		return nil, fmt.Errorf("win9x_vxd_library_members: %w", err)
	}
	names, err := parseWin9xW3Members(data)
	if err != nil {
		return nil, fmt.Errorf("win9x_vxd_library_members: %w", err)
	}
	values := make([]starlark.Value, len(names))
	for index, name := range names {
		values[index] = starlark.String(name)
	}
	return starlark.NewList(values), nil
}

func win9xVXDLibraryBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var base starfile.File
	var values *starlark.List
	var excludeValues *starlark.List
	if err := starlark.UnpackArgs("win9x_vxd_library", args, kwargs, "base", &base, "members", &values, "exclude?", &excludeValues); err != nil {
		return nil, err
	}
	if base.Size() < 0 || base.Size() > win9xVXDMaximum {
		return nil, fmt.Errorf("win9x_vxd_library: base size %d exceeds %d", base.Size(), win9xVXDMaximum)
	}
	baseData, err := starfile.ReadAll(base)
	if err != nil {
		return nil, fmt.Errorf("win9x_vxd_library: %w", err)
	}
	baseData, _, err = unpackWin9xW4(baseData)
	if err != nil {
		return nil, fmt.Errorf("win9x_vxd_library: %w", err)
	}
	headerOffset, baseMembers, err := parseWin9xW3(baseData)
	if err != nil {
		return nil, fmt.Errorf("win9x_vxd_library: %w", err)
	}

	type inputMember struct {
		name, source   string
		data           []byte
		headerSize     uint32
		dataPagesDelta uint32
		oldOffset      int
	}
	excluded := make(map[string]struct{})
	if excludeValues != nil {
		for index := 0; index < excludeValues.Len(); index++ {
			name, ok := starlark.AsString(excludeValues.Index(index))
			if !ok {
				return nil, fmt.Errorf("win9x_vxd_library: exclude[%d] is %s, want string", index, excludeValues.Index(index).Type())
			}
			name = strings.TrimSuffix(strings.ToUpper(name), ".VXD")
			if name == "" || len(name) > 8 || strings.ContainsAny(name, " /\\") {
				return nil, fmt.Errorf("win9x_vxd_library: invalid excluded member name %q", name)
			}
			excluded[name] = struct{}{}
		}
	}
	inputs := make([]inputMember, 0, len(baseMembers)+values.Len())
	seen := make(map[string]struct{}, len(baseMembers)+values.Len())
	for index, member := range baseMembers {
		if _, skip := excluded[member.name]; skip {
			continue
		}
		end := len(baseData)
		if index+1 < len(baseMembers) {
			end = baseMembers[index+1].offset
		}
		inputs = append(inputs, inputMember{name: member.name, source: "base", data: append([]byte(nil), baseData[member.offset:end]...), headerSize: member.headerSize, oldOffset: member.offset})
		seen[member.name] = struct{}{}
	}
	for index := 0; index < values.Len(); index++ {
		dict, ok := values.Index(index).(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("win9x_vxd_library: members[%d] is %s, want dict", index, values.Index(index).Type())
		}
		nameValue, found, err := dict.Get(starlark.String("name"))
		if err != nil || !found {
			return nil, fmt.Errorf("win9x_vxd_library: members[%d] is missing name", index)
		}
		name, ok := starlark.AsString(nameValue)
		if !ok {
			return nil, fmt.Errorf("win9x_vxd_library: members[%d] name is %s, want string", index, nameValue.Type())
		}
		name = strings.TrimSuffix(strings.ToUpper(name), ".VXD")
		if name == "" || len(name) > 8 || strings.ContainsAny(name, " /\\") {
			return nil, fmt.Errorf("win9x_vxd_library: invalid member name %q", name)
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, fmt.Errorf("win9x_vxd_library: duplicate member %q", name)
		}
		fileValue, found, err := dict.Get(starlark.String("file"))
		if err != nil || !found {
			return nil, fmt.Errorf("win9x_vxd_library: members[%d] is missing file", index)
		}
		file, ok := fileValue.(starfile.File)
		if !ok {
			return nil, fmt.Errorf("win9x_vxd_library: members[%d] file is %s, want file", index, fileValue.Type())
		}
		if file.Size() < 0 || file.Size() > win9xVXDMaximum {
			return nil, fmt.Errorf("win9x_vxd_library: member %q size %d is invalid", name, file.Size())
		}
		standalone, err := starfile.ReadAll(file)
		if err != nil {
			return nil, fmt.Errorf("win9x_vxd_library: member %q: %w", name, err)
		}
		if len(standalone) < 0x40 || string(standalone[:2]) != "MZ" {
			return nil, fmt.Errorf("win9x_vxd_library: member %q is missing MZ header", name)
		}
		leOffset := int(binary.LittleEndian.Uint32(standalone[0x3c:0x40]))
		if leOffset < 0x40 || leOffset+0x8c > len(standalone) || string(standalone[leOffset:leOffset+2]) != "LE" {
			return nil, fmt.Errorf("win9x_vxd_library: member %q has invalid LE header", name)
		}
		dataPages := int(binary.LittleEndian.Uint32(standalone[leOffset+0x80 : leOffset+0x84]))
		if dataPages < leOffset || dataPages > len(standalone) {
			return nil, fmt.Errorf("win9x_vxd_library: member %q has invalid data pages offset %#x", name, dataPages)
		}
		// The W3 table records the logical LE header length, excluding alignment
		// between the fixup section and enumerated data pages.  Using the latter's
		// rounded file offset makes the VMM loader consume padding as fixup data.
		// An LE loader section begins immediately after the fixed 0xc4-byte header
		// and is followed by the fixup section.
		loaderSize := uint64(binary.LittleEndian.Uint32(standalone[leOffset+0x38 : leOffset+0x3c]))
		fixupSize := uint64(binary.LittleEndian.Uint32(standalone[leOffset+0x30 : leOffset+0x34]))
		headerSize64 := uint64(0xc4) + loaderSize + fixupSize
		if headerSize64 > uint64(dataPages-leOffset) {
			return nil, fmt.Errorf("win9x_vxd_library: member %q logical header size %#x exceeds data pages offset %#x", name, headerSize64, dataPages-leOffset)
		}
		inputs = append(inputs, inputMember{
			name: name, source: "standalone", data: append([]byte(nil), standalone[leOffset:]...),
			headerSize: uint32(headerSize64), dataPagesDelta: uint32(dataPages - leOffset), oldOffset: leOffset,
		})
		seen[name] = struct{}{}
	}
	if 16+len(inputs)*16 > win9xW3HeaderSize {
		return nil, fmt.Errorf("win9x_vxd_library: %d members exceed W3 header capacity", len(inputs))
	}

	output := make([]byte, headerOffset+win9xW3HeaderSize)
	copy(output, baseData[:headerOffset])
	copy(output[headerOffset:], "W3")
	copy(output[headerOffset+2:headerOffset+4], baseData[headerOffset+2:headerOffset+4])
	binary.LittleEndian.PutUint16(output[headerOffset+4:headerOffset+6], uint16(len(inputs)))
	for index, member := range inputs {
		if index > 0 {
			aligned := alignWin9x(len(output), win9xW3MemberAlignment)
			output = append(output, make([]byte, aligned-len(output))...)
		}
		memberOffset := len(output)
		data := append([]byte(nil), member.data...)
		if len(data) < 0x8c || string(data[:2]) != "LE" {
			return nil, fmt.Errorf("win9x_vxd_library: member %q has invalid embedded LE data", member.name)
		}
		if member.source == "base" {
			delta := int64(memberOffset - member.oldOffset)
			dataPages := int64(binary.LittleEndian.Uint32(data[0x80:0x84])) + delta
			if dataPages < 0 || dataPages > int64(^uint32(0)) {
				return nil, fmt.Errorf("win9x_vxd_library: member %q relocation overflows", member.name)
			}
			binary.LittleEndian.PutUint32(data[0x80:0x84], uint32(dataPages))
			if nonresident := binary.LittleEndian.Uint32(data[0x88:0x8c]); nonresident != 0 {
				binary.LittleEndian.PutUint32(data[0x88:0x8c], uint32(int64(nonresident)+delta))
			}
		} else {
			binary.LittleEndian.PutUint32(data[0x80:0x84], uint32(memberOffset)+member.dataPagesDelta)
			if nonresident := binary.LittleEndian.Uint32(data[0x88:0x8c]); nonresident != 0 {
				relative := int64(nonresident) - int64(member.oldOffset)
				if relative < 0 || int64(memberOffset)+relative > int64(^uint32(0)) {
					return nil, fmt.Errorf("win9x_vxd_library: member %q has invalid nonresident table offset", member.name)
				}
				binary.LittleEndian.PutUint32(data[0x88:0x8c], uint32(int64(memberOffset)+relative))
			}
		}
		entry := output[headerOffset+16+index*16 : headerOffset+32+index*16]
		copy(entry[:8], "        ")
		copy(entry[:8], member.name)
		binary.LittleEndian.PutUint32(entry[8:12], uint32(memberOffset))
		binary.LittleEndian.PutUint32(entry[12:16], member.headerSize)
		output = append(output, data...)
	}
	if len(output) > win9xVXDMaximum {
		return nil, fmt.Errorf("win9x_vxd_library: output size %d exceeds %d", len(output), win9xVXDMaximum)
	}
	return &starfile.Bytes{Name: "vmm32.vxd", Data: output}, nil
}

func alignWin9x(value, alignment int) int { return (value + alignment - 1) &^ (alignment - 1) }

func parseWin9xW3Members(data []byte) ([]string, error) {
	_, members, err := parseWin9xW3(data)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(members))
	for index, member := range members {
		names[index] = member.name + ".VXD"
	}
	return names, nil
}

func parseWin9xW3(data []byte) (int, []win9xW3Member, error) {
	if len(data) < 0x40 || string(data[:2]) != "MZ" {
		return 0, nil, fmt.Errorf("W3: missing MZ header")
	}
	headerOffset := int(binary.LittleEndian.Uint32(data[0x3c:0x40]))
	if headerOffset < 0x40 || headerOffset+16 > len(data) || string(data[headerOffset:headerOffset+2]) != "W3" {
		return 0, nil, fmt.Errorf("W3: missing library header")
	}
	count := int(binary.LittleEndian.Uint16(data[headerOffset+4 : headerOffset+6]))
	if count <= 0 || count >= 4096 || headerOffset+16+count*16 > len(data) {
		return 0, nil, fmt.Errorf("W3: invalid member count %d", count)
	}
	members := make([]win9xW3Member, 0, count)
	previousOffset := headerOffset + 16 + count*16
	seen := make(map[string]struct{}, count)
	for index := 0; index < count; index++ {
		entry := data[headerOffset+16+index*16 : headerOffset+32+index*16]
		name := strings.TrimRight(string(entry[:8]), "\x00 ")
		if name == "" {
			return 0, nil, fmt.Errorf("W3: member %d has an empty name", index)
		}
		for _, character := range name {
			if character < 0x21 || character > 0x7e || character == '/' || character == '\\' {
				return 0, nil, fmt.Errorf("W3: member %d has invalid name %q", index, name)
			}
		}
		name = strings.ToUpper(name)
		if _, exists := seen[name]; exists {
			return 0, nil, fmt.Errorf("W3: duplicate member %q", name)
		}
		seen[name] = struct{}{}
		memberOffset := int(binary.LittleEndian.Uint32(entry[8:12]))
		if memberOffset < previousOffset || memberOffset+2 > len(data) || string(data[memberOffset:memberOffset+2]) != "LE" {
			return 0, nil, fmt.Errorf("W3: member %q has invalid offset %#x", name, memberOffset)
		}
		previousOffset = memberOffset
		members = append(members, win9xW3Member{name: name, offset: memberOffset, headerSize: binary.LittleEndian.Uint32(entry[12:16])})
	}
	return headerOffset, members, nil
}

// unpackWin9xW4 converts a compressed Windows 9x W4 VxD library to the W3
// representation accepted by the same loader. The bytes before e_lfanew are
// the DOS loader stub and are intentionally retained verbatim.
func unpackWin9xW4(data []byte) ([]byte, bool, error) {
	if len(data) < 0x40 || string(data[:2]) != "MZ" {
		return data, false, nil
	}
	headerOffset := int(binary.LittleEndian.Uint32(data[0x3c:0x40]))
	if headerOffset < 0x40 || headerOffset+16 > len(data) || string(data[headerOffset:headerOffset+2]) != "W4" {
		return data, false, nil
	}
	chunkSize := int(binary.LittleEndian.Uint16(data[headerOffset+4 : headerOffset+6]))
	chunkCount := int(binary.LittleEndian.Uint16(data[headerOffset+6 : headerOffset+8]))
	if chunkSize != win9xW4ChunkSize {
		return nil, true, fmt.Errorf("W4: unsupported chunk size %d", chunkSize)
	}
	if chunkCount <= 0 || chunkCount >= win9xW4MaxChunks {
		return nil, true, fmt.Errorf("W4: invalid chunk count %d", chunkCount)
	}
	if string(data[headerOffset+8:headerOffset+10]) != "DS" {
		return nil, true, fmt.Errorf("W4: unsupported compression %q", data[headerOffset+8:headerOffset+10])
	}
	tableEnd := headerOffset + 16 + chunkCount*4
	if tableEnd > len(data) {
		return nil, true, fmt.Errorf("W4: truncated chunk table")
	}

	output := make([]byte, headerOffset, headerOffset+chunkCount*chunkSize)
	copy(output, data[:headerOffset])
	previous := tableEnd
	for index := 0; index < chunkCount; index++ {
		start := int(binary.LittleEndian.Uint32(data[headerOffset+16+index*4 : headerOffset+20+index*4]))
		end := len(data)
		if index+1 < chunkCount {
			end = int(binary.LittleEndian.Uint32(data[headerOffset+20+index*4 : headerOffset+24+index*4]))
		}
		if start < tableEnd || start < previous || end < start || end > len(data) {
			return nil, true, fmt.Errorf("W4: invalid chunk %d extent [%d,%d)", index, start, end)
		}
		previous = end
		compressed := data[start:end]
		if len(compressed) == chunkSize {
			output = append(output, compressed...)
			continue
		}
		decoded, err := decompressWin9xDS(compressed, chunkSize)
		if err != nil {
			return nil, true, fmt.Errorf("W4: chunk %d: %w", index, err)
		}
		output = append(output, decoded...)
	}
	if len(output) < headerOffset+2 || string(output[headerOffset:headerOffset+2]) != "W3" {
		return nil, true, fmt.Errorf("W4: decompressed library does not start with W3")
	}
	return output, true, nil
}

type win9xLSBReader struct {
	data []byte
	bit  int
}

func (r *win9xLSBReader) read(count int) (uint32, error) {
	if count < 0 || count > 32 || r.bit+count > len(r.data)*8 {
		return 0, fmt.Errorf("truncated bitstream at bit %d", r.bit)
	}
	var value uint32
	for index := 0; index < count; index++ {
		value |= uint32((r.data[r.bit>>3]>>(r.bit&7))&1) << index
		r.bit++
	}
	return value, nil
}

func decompressWin9xDS(data []byte, maximum int) ([]byte, error) {
	reader := win9xLSBReader{data: data}
	output := make([]byte, 0, maximum)
	for len(output) < maximum {
		prefix, err := reader.read(2)
		if err != nil {
			return nil, err
		}
		if prefix == 1 || prefix == 2 {
			literal, err := reader.read(7)
			if err != nil {
				return nil, err
			}
			if prefix == 1 {
				literal |= 0x80
			}
			output = append(output, byte(literal))
			continue
		}

		var distance uint32
		switch prefix {
		case 0:
			value, err := reader.read(6)
			if err != nil {
				return nil, err
			}
			distance = value
		case 3:
			selector, err := reader.read(1)
			if err != nil {
				return nil, err
			}
			if selector == 0 {
				value, err := reader.read(8)
				if err != nil {
					return nil, err
				}
				distance = value + 64
			} else {
				value, err := reader.read(12)
				if err != nil {
					return nil, err
				}
				distance = value + 320
				if distance == 4415 { // 512-byte boundary marker.
					continue
				}
			}
		}
		if distance == 0 {
			return output, nil
		}
		if int(distance) > len(output) {
			return nil, fmt.Errorf("copy distance %d exceeds %d output bytes", distance, len(output))
		}

		zeroes := 0
		for ; zeroes < 9; zeroes++ {
			bit, err := reader.read(1)
			if err != nil {
				return nil, err
			}
			if bit != 0 {
				break
			}
		}
		if zeroes == 9 {
			return nil, fmt.Errorf("invalid copy length")
		}
		extra, err := reader.read(zeroes)
		if err != nil {
			return nil, err
		}
		count := (1 << zeroes) + int(extra) + 1
		if len(output)+count > maximum {
			return nil, fmt.Errorf("copy length %d exceeds chunk boundary", count)
		}
		for index := 0; index < count; index++ {
			output = append(output, output[len(output)-int(distance)])
		}
	}
	return output, nil
}
