package mipscoff

import (
	"fmt"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// Builtin inspects the archive-backed image without loading it into a machine.
func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	includeSymbols := true
	if err := starlark.UnpackArgs("mips_coff", args, kwargs, "file", &value, "symbols?", &includeSymbols); err != nil {
		return nil, err
	}
	file, ok := value.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("mips_coff: expected file, got %s", value.Type())
	}
	image, err := Open(file)
	if err != nil {
		return nil, err
	}
	u32 := func(value uint32) starlark.Int { return starlark.MakeUint64(uint64(value)) }
	sections := make([]starlark.Value, 0, len(image.Sections))
	for _, s := range image.Sections {
		sections = append(sections, starfile.NewRecord(starlark.StringDict{
			"name": starlark.String(s.Name), "address": u32(s.Address), "size": u32(s.Size),
			"offset": u32(s.Offset), "flags": u32(s.Flags), "zero_fill": starlark.Bool(s.ZeroFill()),
		}))
	}
	var symbols []starlark.Value
	if includeSymbols {
		table, err := image.Symbols()
		if err != nil {
			return nil, err
		}
		symbols = make([]starlark.Value, 0, len(table))
		for _, s := range table {
			symbols = append(symbols, starfile.NewRecord(starlark.StringDict{
				"name": starlark.String(s.Name), "address": u32(s.Address), "section": starlark.MakeInt(int(s.Section)),
				"type": starlark.MakeInt(int(s.Type)), "class": starlark.MakeInt(int(s.Class)),
			}))
		}
	}
	return starfile.NewRecord(starlark.StringDict{
		"rom": starlark.Bool(image.ROM), "base": u32(image.Base), "entry": u32(image.Entry), "sections": starlark.NewList(sections), "symbols": starlark.NewList(symbols),
	}), nil
}

// MessageLengthsBuiltin returns file-relative length patches for early NT.
func MessageLengthsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("mips_coff_message_lengths", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("mips_coff_message_lengths: expected file, got %s", value.Type())
	}
	image, err := Open(file)
	if err != nil {
		return nil, err
	}
	patches, err := image.MessageLengthPatches()
	if err != nil {
		return nil, err
	}
	out := make([]starlark.Value, 0, len(patches))
	for _, patch := range patches {
		out = append(out, starfile.NewRecord(starlark.StringDict{
			"offset": starlark.MakeInt64(patch.Offset),
			"before": starlark.MakeInt(int(patch.Before)),
			"after":  starlark.MakeInt(int(patch.After)),
		}))
	}
	return starlark.NewList(out), nil
}
