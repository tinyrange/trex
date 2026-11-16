// Package simh reads SIMH magnetic-tape images without extracting records.
// Format: Bob Supnik, SIMH Magtape Representation and Handling, 17 Jan 2022,
// https://simh.trailing-edge.com/docs/simh_magtape.pdf.
package simh

import (
	"encoding/binary"
	"fmt"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// Record retains data records of every extended-format class and metadata
// markers. Data is nil for markers. Bad records retain any recovered data.
// Offset is the leading word's position in the original image.
type Record struct {
	Data          starfile.File
	Offset        int64
	Class         byte
	Marker        uint32
	TapeMark, Bad bool
	// FramingError is a mismatched trailer discovered while indexing. Tape
	// devices report it when the guest reaches the record, not at load point.
	FramingError string
}

// Open checks framing and matching trailers, including odd-length padding.
// It preserves private records/markers and gaps for inspection, and stops at
// logical EOM (which may precede physical EOF). maximumObjects bounds all
// objects, including gaps and private metadata, not just visible tape records.
func Open(file starfile.File, maximumObjects int) ([]Record, error) {
	return index(file, maximumObjects, true)
}

// Index retains a damaged record with FramingError if its length still permits
// positioning. Unlike Open, it defers a mismatched trailer to the consumer.
// Unpositionable/truncated frames are always errors. Consumers must check
// FramingError before delivering a record as valid data.
func Index(file starfile.File, maximumObjects int) ([]Record, error) {
	return index(file, maximumObjects, false)
}

func index(file starfile.File, maximumObjects int, strict bool) ([]Record, error) {
	if maximumObjects <= 0 {
		return nil, fmt.Errorf("simh: maximum_objects must be positive")
	}
	var records []Record
	for off := int64(0); off < file.Size(); {
		if len(records) >= maximumObjects {
			return nil, fmt.Errorf("simh: object limit exceeded")
		}
		var h [4]byte
		if _, err := starfile.ReadFullAt(file, h[:], off); err != nil {
			return nil, fmt.Errorf("simh: header at %d: %w", off, err)
		}
		word := binary.LittleEndian.Uint32(h[:])
		r := Record{Offset: off, Class: byte(word >> 28)}
		if word == 0 || r.Class == 7 || r.Class == 15 {
			r.Marker, r.TapeMark = word, word == 0
			if word >= 0xfffe0000 && word < 0xfffeffff || word >= 0xffff0000 && word < 0xfffffffe {
				return nil, fmt.Errorf("simh: invalid forward marker %08x at %d", word, off)
			}
			records = append(records, r)
			if word == 0xffffffff {
				break
			}
			if word == 0xfffeffff {
				off += 2
			} else {
				off += 4
			}
			continue
		}
		n := int64(word & 0x0fffffff)
		padded := (n + 1) &^ 1
		if file.Size()-off < 8+padded {
			return nil, fmt.Errorf("simh: truncated record at %d", off)
		}
		if _, err := starfile.ReadFullAt(file, h[:], off+4+padded); err != nil {
			return nil, fmt.Errorf("simh: trailer at %d: %w", off, err)
		}
		if binary.LittleEndian.Uint32(h[:]) != word {
			r.FramingError = fmt.Sprintf("simh: record at %d has header %08x, trailer %08x at %d", off, word, binary.LittleEndian.Uint32(h[:]), off+4+padded)
			if strict {
				return nil, fmt.Errorf("%s", r.FramingError)
			}
		}
		r.Data = &starfile.Slice{Name: "SIMH record", Base: file, Offset: off + 4, Length: n}
		r.Bad = r.Class == 8
		records = append(records, r)
		off += 8 + padded
	}
	return records, nil
}

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximum := 1000000
	strict := true
	if err := starlark.UnpackArgs("simh", args, kwargs, "file", &value, "maximum_objects?", &maximum, "strict?", &strict); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("simh: expected file")
	}
	records, err := index(file, maximum, strict)
	if err != nil {
		return nil, err
	}
	values := make([]starlark.Value, len(records))
	for i, r := range records {
		var data starlark.Value = starlark.None
		if r.Data != nil {
			data = r.Data
		}
		values[i] = starfile.NewRecord(starlark.StringDict{
			"data": data, "offset": starlark.MakeInt64(r.Offset),
			"class": starlark.MakeInt(int(r.Class)), "marker": starlark.MakeUint(uint(r.Marker)),
			"tape_mark": starlark.Bool(r.TapeMark), "bad": starlark.Bool(r.Bad),
			"framing_error": starlark.String(r.FramingError),
		})
	}
	return starfile.NewRecord(starlark.StringDict{"records": starlark.NewList(values)}), nil
}
