package windows

import (
	"encoding/binary"
	"fmt"

	starvalue "github.com/tinyrange/trex/script/value"
	"go.starlark.net/starlark"
)

// windowsNEExport describes an original NE entry, before loader relocation.
// FileOffset is -1 for constants and unbacked segment allocations.
type windowsNEExport struct {
	Ordinal, Segment, Offset, Flags int
	FileOffset, Available           int
	Movable, Constant               bool
	Names                           []string
}

func parseWindowsNEExports(data []byte) ([]windowsNEExport, error) {
	m, err := parseWindowsNEModule(data)
	if err != nil {
		return nil, err
	}
	start := m.ne + int(binary.LittleEndian.Uint16(data[m.ne+4:]))
	size := int(binary.LittleEndian.Uint16(data[m.ne+6:]))
	if start < m.ne+64 || start > len(data) || size > len(data)-start {
		return nil, fmt.Errorf("invalid NE entry table")
	}
	table := data[start : start+size]
	var exports []windowsNEExport
	byOrdinal := make(map[int]int)
	ordinal := 1
	terminated := size == 0
	for pos := 0; pos < len(table); {
		count := int(table[pos])
		pos++
		if count == 0 {
			terminated = true
			break
		}
		if pos == len(table) || ordinal+count > 65536 {
			return nil, fmt.Errorf("truncated or overflowing NE entry bundle")
		}
		kind := int(table[pos])
		pos++
		if kind == 0 {
			ordinal += count
			continue
		}
		entrySize := 3
		if kind == 255 {
			entrySize = 6
		}
		if count > (len(table)-pos)/entrySize {
			return nil, fmt.Errorf("truncated NE entry bundle")
		}
		for range count {
			e := windowsNEExport{Ordinal: ordinal, Segment: kind, Flags: int(table[pos]), FileOffset: -1, Movable: kind == 255, Constant: kind == 254}
			if e.Movable {
				e.Segment = int(table[pos+3])
			}
			e.Offset = int(binary.LittleEndian.Uint16(table[pos+entrySize-2:]))
			if e.Constant {
				e.Segment = 0
			} else {
				if e.Segment == 0 || e.Segment > m.segmentCount {
					return nil, fmt.Errorf("NE ordinal %d has invalid segment %d", ordinal, e.Segment)
				}
				segment := m.segments + (e.Segment-1)*8
				sector := uint64(binary.LittleEndian.Uint16(data[segment:]))
				length := windowsNEExpandedLength(binary.LittleEndian.Uint16(data[segment+2:]))
				flags := binary.LittleEndian.Uint16(data[segment+4:])
				if sector != 0 {
					base := sector << m.alignShift
					if base > uint64(len(data)) || length > uint64(len(data))-base {
						return nil, fmt.Errorf("NE segment %d exceeds input", e.Segment)
					}
					// Iterated segments have no direct on-disk address for an entry.
					if flags&8 == 0 && uint64(e.Offset) < length {
						e.FileOffset = int(base) + e.Offset
						e.Available = int(length) - e.Offset
					}
				}
			}
			byOrdinal[ordinal] = len(exports)
			exports = append(exports, e)
			pos += entrySize
			ordinal++
		}
	}
	if !terminated {
		return nil, fmt.Errorf("unterminated NE entry table")
	}
	readNames := func(names []byte) error {
		for len(names) != 0 {
			length := int(names[0])
			if length == 0 {
				return nil
			}
			if length > len(names)-3 {
				return fmt.Errorf("truncated NE export name")
			}
			ordinal := int(binary.LittleEndian.Uint16(names[length+1:]))
			if index, ok := byOrdinal[ordinal]; ok {
				exports[index].Names = append(exports[index].Names, string(names[1:length+1]))
			}
			names = names[length+3:]
		}
		return fmt.Errorf("unterminated NE export names")
	}
	if err := readNames(data[m.resident:m.nonresident]); err != nil {
		return nil, err
	}
	if m.nonresidentSize != 0 {
		if err := readNames(data[m.nonresident : m.nonresident+m.nonresidentSize]); err != nil {
			return nil, err
		}
	}
	return exports, nil
}

func windowsNEExportsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	maximum := windowsNEFastBootMaximum
	if err := starlark.UnpackArgs("ne_exports", args, kwargs, "source", &source, "maximum?", &maximum); err != nil {
		return nil, err
	}
	if maximum <= 0 {
		return nil, fmt.Errorf("ne_exports: maximum must be positive")
	}
	data, err := bytesForBinaryValueLimited(source, int64(maximum))
	if err != nil {
		return nil, err
	}
	exports, err := parseWindowsNEExports(data)
	if err != nil {
		return nil, fmt.Errorf("ne_exports: %w", err)
	}
	values := make([]starlark.Value, len(exports))
	for i, e := range exports {
		names := make([]starlark.Value, len(e.Names))
		for j, name := range e.Names {
			names[j] = starlark.String(name)
		}
		fileOffset := starlark.Value(starlark.None)
		if e.FileOffset >= 0 {
			fileOffset = starlark.MakeInt(e.FileOffset)
		}
		values[i] = starvalue.NewRecord(starlark.StringDict{
			"ordinal": starlark.MakeInt(e.Ordinal), "names": starlark.NewList(names),
			"segment": starlark.MakeInt(e.Segment), "offset": starlark.MakeInt(e.Offset),
			"flags": starlark.MakeInt(e.Flags), "movable": starlark.Bool(e.Movable),
			"constant": starlark.Bool(e.Constant), "file_offset": fileOffset,
			"available": starlark.MakeInt(e.Available),
		})
	}
	return starlark.NewList(values), nil
}
