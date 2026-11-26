// Package ibm9020 reads records from IBM 9020 diagnostic libraries.
package ibm9020

import (
	"encoding/binary"
	"fmt"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// Relocation describes one address constant in a diagnostic text record.
type Relocation struct {
	Address  uint32
	Width    int
	Subtract bool
}

// ReadRelocations reads one tape relocation dictionary record. The returned
// identifier retains the relocation record's type bits. See D0D50A00.SPT,
// LOP020 through LOP065 in the FAA 9020 diagnostic source listings.
func ReadRelocations(file starfile.File) (uint32, []Relocation, error) {
	size := file.Size()
	if size < 4 || size > 400 || size%4 != 0 {
		return 0, nil, fmt.Errorf("IBM 9020 relocation record: invalid length %d", size)
	}
	data := make([]byte, size)
	if _, err := starfile.ReadFullAt(file, data, 0); err != nil {
		return 0, nil, fmt.Errorf("IBM 9020 relocation record: %w", err)
	}
	id := binary.BigEndian.Uint32(data[:4])
	if id&3 != 3 {
		return 0, nil, fmt.Errorf("IBM 9020 relocation record: invalid identifier %08X", id)
	}
	entries := make([]Relocation, 0, (size-4)/4)
	for offset := 4; offset < len(data); offset += 4 {
		word := binary.BigEndian.Uint32(data[offset : offset+4])
		flags := byte(word >> 24)
		width := int(flags>>2) + 1
		if width > 4 {
			return 0, nil, fmt.Errorf("IBM 9020 relocation record: invalid address width %d at byte %d", width, offset)
		}
		entries = append(entries, Relocation{
			Address:  word & 0x00ffffff,
			Width:    width,
			Subtract: flags&2 != 0,
		})
	}
	return id, entries, nil
}

func RelocationsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("ibm9020_rld", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("ibm9020_rld: expected file")
	}
	id, entries, err := ReadRelocations(file)
	if err != nil {
		return nil, err
	}
	values := make([]starlark.Value, len(entries))
	for i, entry := range entries {
		values[i] = starfile.NewRecord(starlark.StringDict{
			"address":  starlark.MakeUint(uint(entry.Address)),
			"width":    starlark.MakeInt(entry.Width),
			"subtract": starlark.Bool(entry.Subtract),
		})
	}
	return starfile.NewRecord(starlark.StringDict{
		"id":      starlark.MakeUint(uint(id)),
		"entries": starlark.NewList(values),
	}), nil
}
