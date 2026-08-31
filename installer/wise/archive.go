// Package wise reads self-extracting Wise installer overlays without staging
// their contents on the host filesystem.
package wise

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"path"
	"strings"

	mszipcompression "github.com/tinyrange/trex/compression/mszip"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

const (
	minimumOverlayHeader = int64(81)
	wiseFlagPKZIP        = uint32(0x00000100)
)

// FileInfo describes one decoded member without exposing host paths.
type FileInfo struct {
	Name string
	Size int64
}

type overlayHeader struct {
	offset           int64
	compressedData   int64
	flags            uint32
	scriptInflated   uint32
	scriptDeflated   uint32
	wiseDLLDeflated  uint32
	ctl3DDeflated    uint32
	data4Deflated    uint32
	registerDeflated uint32
	progressDeflated uint32
	data7Deflated    uint32
	data8Deflated    uint32
	data9Deflated    uint32
	data10Deflated   uint32
	finalDeflated    uint32
	finalInflated    uint32
	dibDeflated      uint32
	dibInflated      uint32
	installDeflated  uint32
}

type member struct {
	name string
	file starfile.File
}

// Archive is a decoded Wise overlay. Members remain ordinary trex files and
// can flow directly into image construction.
type Archive struct {
	header  overlayHeader
	script  *wiseScript
	members []member
	index   map[string]int
}

// Open locates and decodes a Wise overlay from a DOS or PE executable.
func Open(file starfile.File, maximum int64) (*Archive, error) {
	overlay, err := peOverlayOffset(file)
	if err != nil {
		return nil, err
	}
	header, err := parseOverlayHeader(file, overlay, maximum)
	if err != nil {
		return nil, err
	}
	if header.flags&wiseFlagPKZIP != 0 {
		return nil, fmt.Errorf("wise: PKZIP-wrapped payloads are not supported")
	}

	cursor := header.compressedData
	decode := func(name string, compressed, expanded uint32) (starfile.File, error) {
		if compressed == 0 {
			return nil, nil
		}
		if int64(compressed) > file.Size()-cursor {
			return nil, fmt.Errorf("wise: %s compressed stream is out of bounds", name)
		}
		decoded, decodeErr := inflate(file, cursor, int64(compressed), int64(expanded), maximum)
		cursor += int64(compressed)
		if decodeErr != nil {
			return nil, fmt.Errorf("wise: decode %s: %w", name, decodeErr)
		}
		return &starfile.Bytes{Name: name, Data: decoded}, nil
	}

	members := make([]member, 0, 12)
	add := func(name string, compressed, expanded uint32) error {
		value, addErr := decode(name, compressed, expanded)
		if addErr != nil {
			return addErr
		}
		if value != nil {
			members = append(members, member{name: "/" + name, file: value})
		}
		return nil
	}
	addOptional := func(name string, compressed uint32) error {
		if compressed == 0 {
			return nil
		}
		start := cursor
		value, decodeErr := decode(name, compressed, 0)
		if decodeErr != nil {
			value = &starfile.Slice{Name: name + ".compressed", Base: file, Offset: start, Length: int64(compressed)}
			name += ".compressed"
		}
		members = append(members, member{name: "/" + name, file: value})
		return nil
	}
	if err := add("WiseColors.dib", header.dibDeflated, header.dibInflated); err != nil {
		return nil, err
	}
	script, err := decode("WiseScript.bin", header.scriptDeflated, header.scriptInflated)
	if err != nil {
		return nil, err
	}
	if script == nil {
		return nil, fmt.Errorf("wise: installer has no script")
	}
	parsedScript, err := parseScript(script)
	if err != nil {
		return nil, err
	}
	members = append(members, member{name: "/WiseScript.bin", file: script})
	for _, support := range []struct {
		name       string
		compressed uint32
	}{{"WISE0001.DLL", header.wiseDLLDeflated}, {"CTL3D32.DLL", header.ctl3DDeflated}, {"FILE0004", header.data4Deflated}, {"OCXREG32.EXE", header.registerDeflated}, {"PROGRESS.DLL", header.progressDeflated}, {"FILE0007", header.data7Deflated}, {"FILE0008", header.data8Deflated}, {"FILE0009", header.data9Deflated}, {"FILE000A", header.data10Deflated}, {"INSTALL_SCRIPT", header.installDeflated}} {
		if err := addOptional(support.name, support.compressed); err != nil {
			return nil, err
		}
	}
	if err := addOptional("FILE00XX.DAT", header.finalDeflated); err != nil {
		return nil, err
	}
	payloadOffset, err := selectPayloadOffset(file, parsedScript, cursor, maximum)
	if err != nil {
		return nil, err
	}
	for fileIndex, entry := range parsedScript.files {
		if entry.end <= entry.start || int64(entry.end) > file.Size()-payloadOffset {
			return nil, fmt.Errorf("wise: payload file %d has invalid stream range %d:%d", fileIndex, entry.start, entry.end)
		}
		decoded, decodeErr := inflate(file, payloadOffset+int64(entry.start), int64(entry.end-entry.start), int64(entry.expanded), maximum)
		if decodeErr != nil {
			return nil, fmt.Errorf("wise: decode payload file %d %q: %w", fileIndex, entry.destination, decodeErr)
		}
		if entry.crc != 0 && crc32.ChecksumIEEE(decoded) != entry.crc {
			return nil, fmt.Errorf("wise: payload file %d %q checksum mismatch", fileIndex, entry.destination)
		}
		base := path.Base(strings.ReplaceAll(entry.destination, `\`, "/"))
		if base == "." || base == "/" || base == "" {
			base = fmt.Sprintf("WISE%04d", fileIndex+1)
		}
		entry.member = fmt.Sprintf("/payload/%04d/%s", fileIndex+1, base)
		members = append(members, member{name: entry.member, file: &starfile.Bytes{Name: base, Data: decoded}})
	}
	index := make(map[string]int, len(members))
	for i, entry := range members {
		index[strings.ToLower(entry.name)] = i
	}
	return &Archive{header: header, script: parsedScript, members: members, index: index}, nil
}

func selectPayloadOffset(file starfile.File, script *wiseScript, sequential, maximum int64) (int64, error) {
	if len(script.files) == 0 {
		return sequential, nil
	}
	candidates := []int64{sequential}
	if script.payloadSize != 0 && int64(script.payloadSize) <= file.Size() {
		hinted := file.Size() - int64(script.payloadSize)
		if hinted != sequential {
			candidates = append(candidates, hinted)
		}
	}
	first := script.files[0]
	for _, candidate := range candidates {
		if first.end <= first.start || candidate < 0 || int64(first.end) > file.Size()-candidate {
			continue
		}
		decoded, err := inflate(file, candidate+int64(first.start), int64(first.end-first.start), int64(first.expanded), maximum)
		if err != nil {
			continue
		}
		if first.crc == 0 || crc32.ChecksumIEEE(decoded) == first.crc {
			return candidate, nil
		}
	}
	return 0, fmt.Errorf("wise: neither sequential nor script-declared payload offset validates the first file")
}

func peOverlayOffset(file starfile.File) (int64, error) {
	if file.Size() < 64 {
		return 0, fmt.Errorf("wise: executable is too short")
	}
	header := make([]byte, 64)
	if _, err := starfile.ReadFullAt(file, header, 0); err != nil {
		return 0, fmt.Errorf("wise: read DOS header: %w", err)
	}
	if string(header[:2]) != "MZ" {
		return 0, fmt.Errorf("wise: input is not a DOS or PE executable")
	}
	peOffset := int64(binary.LittleEndian.Uint32(header[0x3c:0x40]))
	if peOffset < 0 || peOffset > file.Size()-24 {
		return 0, fmt.Errorf("wise: invalid PE header offset")
	}
	peHeader := make([]byte, 24)
	if _, err := starfile.ReadFullAt(file, peHeader, peOffset); err != nil {
		return 0, fmt.Errorf("wise: read PE header: %w", err)
	}
	if string(peHeader[:4]) != "PE\x00\x00" {
		return 0, fmt.Errorf("wise: executable is not PE")
	}
	sections := int(binary.LittleEndian.Uint16(peHeader[6:8]))
	optionalSize := int64(binary.LittleEndian.Uint16(peHeader[20:22]))
	if sections <= 0 || sections > 96 {
		return 0, fmt.Errorf("wise: invalid PE section count %d", sections)
	}
	sectionOffset := peOffset + 24 + optionalSize
	if sectionOffset > file.Size()-int64(sections*40) {
		return 0, fmt.Errorf("wise: PE section table is truncated")
	}
	overlay := int64(0)
	section := make([]byte, 40)
	for index := 0; index < sections; index++ {
		if _, err := starfile.ReadFullAt(file, section, sectionOffset+int64(index*40)); err != nil {
			return 0, fmt.Errorf("wise: read PE section %d: %w", index, err)
		}
		end := int64(binary.LittleEndian.Uint32(section[20:24])) + int64(binary.LittleEndian.Uint32(section[16:20]))
		if end > overlay {
			overlay = end
		}
	}
	if overlay <= 0 || overlay > file.Size()-minimumOverlayHeader {
		return 0, fmt.Errorf("wise: executable has no bounded overlay")
	}
	return overlay, nil
}

func parseOverlayHeader(file starfile.File, offset, maximum int64) (overlayHeader, error) {
	limit := file.Size() - offset
	if limit < minimumOverlayHeader {
		return overlayHeader{}, fmt.Errorf("wise: overlay header is truncated")
	}
	readSize := limit
	if readSize > 4096 {
		readSize = 4096
	}
	data := make([]byte, readSize)
	if _, err := starfile.ReadFullAt(file, data, offset); err != nil {
		return overlayHeader{}, fmt.Errorf("wise: read overlay header: %w", err)
	}
	cursor := 0
	take := func(size int) ([]byte, error) {
		if size < 0 || cursor > len(data)-size {
			return nil, io.ErrUnexpectedEOF
		}
		value := data[cursor : cursor+size]
		cursor += size
		return value, nil
	}
	nameLength := int(data[cursor])
	cursor++
	if nameLength != 0 {
		name, err := take(nameLength)
		if err != nil {
			return overlayHeader{}, fmt.Errorf("wise: DLL name: %w", err)
		}
		if bytes.IndexByte(name, 0) >= 0 {
			return overlayHeader{}, fmt.Errorf("wise: invalid DLL name")
		}
		if _, err := take(4); err != nil {
			return overlayHeader{}, fmt.Errorf("wise: DLL size: %w", err)
		}
	}
	block, err := take(4 + 12 + 8 + 14*4)
	if err != nil {
		return overlayHeader{}, fmt.Errorf("wise: fixed header: %w", err)
	}
	values := block[24:]
	header := overlayHeader{
		offset:           offset,
		flags:            binary.LittleEndian.Uint32(block[:4]),
		scriptInflated:   binary.LittleEndian.Uint32(values[0:4]),
		scriptDeflated:   binary.LittleEndian.Uint32(values[4:8]),
		wiseDLLDeflated:  binary.LittleEndian.Uint32(values[8:12]),
		ctl3DDeflated:    binary.LittleEndian.Uint32(values[12:16]),
		data4Deflated:    binary.LittleEndian.Uint32(values[16:20]),
		registerDeflated: binary.LittleEndian.Uint32(values[20:24]),
		progressDeflated: binary.LittleEndian.Uint32(values[24:28]),
		data7Deflated:    binary.LittleEndian.Uint32(values[28:32]),
		data8Deflated:    binary.LittleEndian.Uint32(values[32:36]),
		data9Deflated:    binary.LittleEndian.Uint32(values[36:40]),
		data10Deflated:   binary.LittleEndian.Uint32(values[40:44]),
		finalDeflated:    binary.LittleEndian.Uint32(values[44:48]),
		finalInflated:    binary.LittleEndian.Uint32(values[48:52]),
	}
	if header.scriptDeflated == 0 || header.scriptInflated == 0 || header.scriptDeflated > header.scriptInflated || int64(header.scriptInflated) > maximum {
		return overlayHeader{}, fmt.Errorf("wise: invalid script sizes %d/%d", header.scriptDeflated, header.scriptInflated)
	}
	peek, err := take(4)
	if err != nil {
		return overlayHeader{}, fmt.Errorf("wise: graphics size or endianness: %w", err)
	}
	dibDeflated := binary.LittleEndian.Uint32(peek)
	if dibDeflated <= uint32(limit) {
		header.dibDeflated = dibDeflated
		value, readErr := take(4)
		if readErr != nil {
			return overlayHeader{}, fmt.Errorf("wise: expanded graphics size: %w", readErr)
		}
		header.dibInflated = binary.LittleEndian.Uint32(value)
		if header.dibDeflated > header.dibInflated || int64(header.dibInflated) > maximum {
			return overlayHeader{}, fmt.Errorf("wise: invalid graphics sizes %d/%d", header.dibDeflated, header.dibInflated)
		}
		endian := binary.LittleEndian.Uint16(data[cursor : cursor+2])
		if endian != 0x0008 && endian != 0x0800 {
			value, readErr = take(4)
			if readErr != nil {
				return overlayHeader{}, fmt.Errorf("wise: install script size: %w", readErr)
			}
			header.installDeflated = binary.LittleEndian.Uint32(value)
			if _, readErr = take(4); readErr != nil {
				return overlayHeader{}, fmt.Errorf("wise: character set: %w", readErr)
			}
		}
		value, readErr = take(2)
		if readErr != nil {
			return overlayHeader{}, fmt.Errorf("wise: endianness: %w", readErr)
		}
		endian = binary.LittleEndian.Uint16(value)
		if endian != 0x0008 && endian != 0x0800 {
			return overlayHeader{}, fmt.Errorf("wise: invalid endianness %#x", endian)
		}
		length, readErr := take(1)
		if readErr != nil {
			return overlayHeader{}, fmt.Errorf("wise: initialization text length: %w", readErr)
		}
		if _, readErr = take(int(length[0])); readErr != nil {
			return overlayHeader{}, fmt.Errorf("wise: initialization text: %w", readErr)
		}
	} else {
		cursor -= 4
	}
	header.compressedData = offset + int64(cursor)
	compressedTotal := uint64(header.dibDeflated) + uint64(header.scriptDeflated) + uint64(header.wiseDLLDeflated) + uint64(header.ctl3DDeflated) + uint64(header.data4Deflated) + uint64(header.registerDeflated) + uint64(header.progressDeflated) + uint64(header.data7Deflated) + uint64(header.data8Deflated) + uint64(header.data9Deflated) + uint64(header.data10Deflated) + uint64(header.installDeflated) + uint64(header.finalDeflated)
	if compressedTotal > uint64(file.Size()-header.compressedData) {
		return overlayHeader{}, fmt.Errorf("wise: header-defined streams exceed the executable")
	}
	return header, nil
}

func inflate(file starfile.File, offset, compressed, expected, maximum int64) ([]byte, error) {
	if compressed <= 0 || compressed > maximum || expected > maximum {
		return nil, fmt.Errorf("invalid bounded stream sizes %d/%d", compressed, expected)
	}
	reader := flate.NewReader(io.NewSectionReader(file, offset, compressed))
	defer reader.Close()
	limit := maximum
	if expected > 0 {
		limit = expected
	}
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		if expected <= 0 {
			return nil, err
		}
		compressedData := make([]byte, compressed)
		if _, readErr := starfile.ReadFullAt(file, compressedData, offset); readErr != nil {
			return nil, readErr
		}
		compatible, compatibleErr := mszipcompression.Inflate(compressedData, nil, int(expected))
		if compatibleErr != nil {
			return nil, fmt.Errorf("strict inflate: %v; compatible inflate: %w", err, compatibleErr)
		}
		return compatible, nil
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("expanded data exceeds %d bytes", limit)
	}
	if expected > 0 && int64(len(data)) != expected {
		return nil, fmt.Errorf("expanded to %d bytes, want %d", len(data), expected)
	}
	return data, nil
}

func (a *Archive) Files() []FileInfo {
	files := make([]FileInfo, len(a.members))
	for index, entry := range a.members {
		files[index] = FileInfo{Name: entry.name, Size: entry.file.Size()}
	}
	return files
}

func (a *Archive) Lookup(name string) (starfile.File, error) {
	clean := strings.ToLower(path.Clean("/" + strings.TrimPrefix(name, "/")))
	index, found := a.index[clean]
	if !found {
		return nil, fmt.Errorf("wise: member %q not found", name)
	}
	return a.members[index].file, nil
}

func (a *Archive) String() string        { return fmt.Sprintf("<wise files=%d>", len(a.members)) }
func (*Archive) Type() string            { return "wise" }
func (*Archive) Freeze()                 {}
func (*Archive) Truth() starlark.Bool    { return starlark.True }
func (a *Archive) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", a.Type()) }
func (a *Archive) Get(key starlark.Value) (starlark.Value, bool, error) {
	name, ok := starlark.AsString(key)
	if !ok {
		return nil, false, fmt.Errorf("wise: key is %s, want string", key.Type())
	}
	value, err := a.Lookup(name)
	if err != nil {
		return nil, false, nil
	}
	return value, true, nil
}
func (a *Archive) AttrNames() []string { return []string{"actions", "files", "find", "script"} }
func (a *Archive) Attr(name string) (starlark.Value, error) {
	switch name {
	case "actions":
		return a.script.actionValues(), nil
	case "files":
		values := make([]starlark.Value, len(a.members))
		for index, entry := range a.members {
			values[index] = starlark.String(entry.name)
		}
		return starlark.NewList(values), nil
	case "find":
		return starlark.NewBuiltin("wise.find", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var value string
			if err := starlark.UnpackArgs("wise.find", args, kwargs, "path", &value); err != nil {
				return nil, err
			}
			file, err := a.Lookup(value)
			if err != nil {
				return starlark.None, nil
			}
			return file, nil
		}), nil
	case "script":
		return a.script.file, nil
	default:
		return nil, nil
	}
}
