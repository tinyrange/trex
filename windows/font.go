package windows

import (
	"encoding/binary"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"sort"
	"strings"
	"unicode/utf16"

	"go.starlark.net/starlark"
)

type fontNameRecord struct {
	name  string
	score int
}

// fontNamesBuiltin returns the preferred full names from an OpenType font or
// collection. Registry naming and installation policy belong to Starlark.
func fontNamesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("font_names", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("font_names: got %s, want file", value.Type())
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, err
	}
	names, err := openTypeFullNames(data)
	if err != nil {
		return nil, fmt.Errorf("font_names: %w", err)
	}
	values := make([]starlark.Value, len(names))
	for index, name := range names {
		values[index] = starlark.String(name)
	}
	return starlark.NewList(values), nil
}

func openTypeFullNames(data []byte) ([]string, error) {
	offsets := []uint32{0}
	if len(data) >= 12 && string(data[:4]) == "ttcf" {
		count := binary.BigEndian.Uint32(data[8:12])
		if count == 0 || count > 4096 || uint64(12)+uint64(count)*4 > uint64(len(data)) {
			return nil, fmt.Errorf("invalid TrueType collection header")
		}
		offsets = make([]uint32, count)
		for i := range offsets {
			offsets[i] = binary.BigEndian.Uint32(data[12+i*4 : 16+i*4])
		}
	}
	best := make(map[string]fontNameRecord)
	for _, offset := range offsets {
		records, err := openTypeFaceFullNames(data, offset)
		if err != nil {
			return nil, err
		}
		if len(records) == 0 {
			continue
		}
		faceName := records[0]
		for _, record := range records[1:] {
			if record.score > faceName.score {
				faceName = record
			}
		}
		identity := strings.ToLower(faceName.name)
		if current, ok := best[identity]; !ok || faceName.score > current.score {
			best[identity] = faceName
		}
	}
	if len(best) == 0 {
		return nil, fmt.Errorf("font has no usable full-name record")
	}
	names := make([]string, 0, len(best))
	for _, record := range best {
		names = append(names, record.name)
	}
	sort.Slice(names, func(i, j int) bool { return strings.ToLower(names[i]) < strings.ToLower(names[j]) })
	return names, nil
}

func openTypeFaceFullNames(data []byte, faceOffset uint32) ([]fontNameRecord, error) {
	if uint64(faceOffset)+12 > uint64(len(data)) {
		return nil, fmt.Errorf("font face offset %#x is outside file", faceOffset)
	}
	numTables := binary.BigEndian.Uint16(data[faceOffset+4 : faceOffset+6])
	directoryEnd := uint64(faceOffset) + 12 + uint64(numTables)*16
	if directoryEnd > uint64(len(data)) {
		return nil, fmt.Errorf("font table directory is truncated")
	}
	var nameOffset, nameLength uint32
	for i := uint16(0); i < numTables; i++ {
		record := faceOffset + 12 + uint32(i)*16
		if string(data[record:record+4]) == "name" {
			nameOffset = binary.BigEndian.Uint32(data[record+8 : record+12])
			nameLength = binary.BigEndian.Uint32(data[record+12 : record+16])
			break
		}
	}
	if nameOffset == 0 || nameLength < 6 || uint64(nameOffset)+uint64(nameLength) > uint64(len(data)) {
		return nil, fmt.Errorf("font has no valid naming table")
	}
	table := data[nameOffset : nameOffset+nameLength]
	count := binary.BigEndian.Uint16(table[2:4])
	storage := binary.BigEndian.Uint16(table[4:6])
	if uint64(6)+uint64(count)*12 > uint64(len(table)) || uint64(storage) > uint64(len(table)) {
		return nil, fmt.Errorf("font naming table is truncated")
	}
	var out []fontNameRecord
	for i := uint16(0); i < count; i++ {
		record := table[6+i*12 : 18+i*12]
		platform := binary.BigEndian.Uint16(record[0:2])
		encoding := binary.BigEndian.Uint16(record[2:4])
		language := binary.BigEndian.Uint16(record[4:6])
		nameID := binary.BigEndian.Uint16(record[6:8])
		length := binary.BigEndian.Uint16(record[8:10])
		offset := binary.BigEndian.Uint16(record[10:12])
		if nameID != 4 || uint64(storage)+uint64(offset)+uint64(length) > uint64(len(table)) {
			continue
		}
		text := decodeOpenTypeName(platform, table[uint32(storage)+uint32(offset):uint32(storage)+uint32(offset)+uint32(length)])
		text = strings.TrimSpace(strings.TrimRight(text, "\x00"))
		if text == "" {
			continue
		}
		score := 0
		if platform == 3 {
			score += 100
			if encoding == 1 || encoding == 10 {
				score += 10
			}
		} else if platform == 0 {
			score += 80
		}
		if language == 0x0409 {
			score += 20
		}
		out = append(out, fontNameRecord{name: text, score: score})
	}
	return out, nil
}

func decodeOpenTypeName(platform uint16, data []byte) string {
	if platform == 0 || platform == 3 {
		units := make([]uint16, len(data)/2)
		for i := range units {
			units[i] = binary.BigEndian.Uint16(data[i*2 : i*2+2])
		}
		return string(utf16.Decode(units))
	}
	return string(data)
}
