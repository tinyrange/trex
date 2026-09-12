// Package aws reads AWS tape images, preserving logical records and tape marks.
// The six-byte physical header stores little-endian current/previous lengths
// followed by NEWREC (0x80), TAPEMARK (0x40), ENDREC (0x20) and a reserved byte.
package aws

import (
	"encoding/binary"
	"fmt"
	filesystem "github.com/tinyrange/trex/filesystem"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// Record is one complete logical tape record, potentially spanning physical
// blocks. A tape mark has nil Data. Offset identifies its first physical header.
type Record struct {
	Data     starfile.File
	Offset   int64
	Blocks   int
	TapeMark bool
}

// Open rejects broken framing, previous-length chains and incomplete records.
// It retains views of payload bytes rather than copying or flattening tape marks.
func Open(file starfile.File, maximumRecords int) ([]Record, error) {
	if maximumRecords <= 0 {
		return nil, fmt.Errorf("aws: maximum_records must be positive")
	}
	var result []Record
	var previous uint16
	var active bool
	var pieces []filesystem.ExtentSpec
	var start, size int64
	var blocks int
	for off := int64(0); off < file.Size(); {
		var h [6]byte
		if _, err := starfile.ReadFullAt(file, h[:], off); err != nil {
			return nil, fmt.Errorf("aws: header at %d: %w", off, err)
		}
		length := binary.LittleEndian.Uint16(h[:2])
		prev := binary.LittleEndian.Uint16(h[2:4])
		flags := h[4]
		if prev != previous {
			return nil, fmt.Errorf("aws: previous length at %d is %d, expected %d", off, prev, previous)
		}
		if h[5] != 0 || flags & ^byte(0xe0) != 0 {
			return nil, fmt.Errorf("aws: unsupported flags %02x%02x at %d", flags, h[5], off)
		}
		if int64(length) > file.Size()-off-6 {
			return nil, fmt.Errorf("aws: truncated block at %d", off)
		}
		if flags&0x40 != 0 {
			if flags != 0x40 || length != 0 || active {
				return nil, fmt.Errorf("aws: invalid tape mark at %d", off)
			}
			result = append(result, Record{Offset: off, Blocks: 1, TapeMark: true})
		} else {
			if flags&0x80 != 0 {
				if active {
					return nil, fmt.Errorf("aws: new record before prior end at %d", off)
				}
				active = true
				start = off
				size = 0
				blocks = 0
				pieces = nil
			}
			if !active {
				return nil, fmt.Errorf("aws: continuation without record at %d", off)
			}
			if length > 0 {
				pieces = append(pieces, filesystem.ExtentSpec{Start: size, Size: int64(length), File: file, Offset: off + 6})
			}
			size += int64(length)
			blocks++
			if flags&0x20 != 0 {
				result = append(result, Record{Data: filesystem.NewGeneratedImage("aws record", size, pieces), Offset: start, Blocks: blocks})
				active = false
			}
		}
		if len(result) > maximumRecords {
			return nil, fmt.Errorf("aws: record limit exceeded")
		}
		// Bound physical segments even if a malicious input never ends its record.
		if blocks > maximumRecords {
			return nil, fmt.Errorf("aws: segment limit exceeded")
		}
		previous = length
		off += 6 + int64(length)
	}
	if active {
		return nil, fmt.Errorf("aws: unfinished record")
	}
	return result, nil
}

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximum := 1000000
	if err := starlark.UnpackArgs("aws", args, kwargs, "file", &value, "maximum_records?", &maximum); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("aws: expected file")
	}
	records, err := Open(file, maximum)
	if err != nil {
		return nil, err
	}
	values := make([]starlark.Value, len(records))
	for i, r := range records {
		var data starlark.Value = starlark.None
		if r.Data != nil {
			data = r.Data
		}
		values[i] = starfile.NewRecord(starlark.StringDict{"data": data, "offset": starlark.MakeInt64(r.Offset), "blocks": starlark.MakeInt(r.Blocks), "tape_mark": starlark.Bool(r.TapeMark)})
	}
	return starfile.NewRecord(starlark.StringDict{"records": starlark.NewList(values)}), nil
}
