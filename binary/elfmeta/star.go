package elfmeta

import (
	"debug/elf"
	"fmt"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	options := Options{MaximumSymbols: 1000000, MaximumStringBytes: 16 << 20}
	if err := starlark.UnpackArgs("elf_symbols", args, kwargs, "file", &source, "maximum_symbols?", &options.MaximumSymbols, "maximum_string_bytes?", &options.MaximumStringBytes, "maximum_relocations?", &options.MaximumRelocations); err != nil {
		return nil, err
	}
	if options.MaximumSymbols <= 0 || options.MaximumStringBytes <= 0 {
		return nil, fmt.Errorf("elf_symbols: limits must be positive")
	}
	r, ok := source.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("elf_symbols: expected file")
	}
	image, err := Open(r, options)
	if err != nil {
		return nil, err
	}
	symbols := make([]starlark.Value, len(image.Symbols))
	for i, s := range image.Symbols {
		symbols[i] = starfile.NewRecord(starlark.StringDict{
			"name": starlark.String(s.Name), "address": starlark.MakeUint64(s.Value), "size": starlark.MakeUint64(s.Size),
			"section": starlark.MakeUint(uint(s.Section)), "binding": starlark.MakeUint(uint(s.Info >> 4)), "type": starlark.MakeUint(uint(s.Info & 15)),
			"visibility": starlark.MakeUint(uint(s.Other & 3)), "dynamic": starlark.Bool(s.Dynamic),
		})
	}
	segments := make([]starlark.Value, len(image.Segments))
	for i, p := range image.Segments {
		segments[i] = segmentValue(p)
	}
	var tls starlark.Value = starlark.None
	if image.TLS != nil {
		tls = segmentValue(*image.TLS)
	}
	relocations := make([]starlark.Value, len(image.Relocations))
	for i, r := range image.Relocations {
		relocations[i] = starfile.NewRecord(starlark.StringDict{
			"address": starlark.MakeUint64(r.Address), "type": starlark.MakeUint64(uint64(r.Type)),
			"symbol": starlark.String(r.Symbol), "addend": starlark.MakeInt64(r.Addend),
			"implicit_addend": starlark.Bool(r.ImplicitAddend),
		})
	}
	return starfile.NewRecord(starlark.StringDict{
		"type": starlark.MakeUint(uint(image.Type)), "machine": starlark.MakeUint(uint(image.Machine)),
		"entry": starlark.MakeUint64(image.Entry), "little_endian": starlark.Bool(image.LittleEndian),
		"symbols": starlark.NewList(symbols), "segments": starlark.NewList(segments), "relocations": starlark.NewList(relocations), "tls": tls,
	}), nil
}

func segmentValue(p elf.ProgHeader) starlark.Value {
	return starfile.NewRecord(starlark.StringDict{
		"address": starlark.MakeUint64(p.Vaddr), "offset": starlark.MakeUint64(p.Off),
		"file_size": starlark.MakeUint64(p.Filesz), "memory_size": starlark.MakeUint64(p.Memsz),
		"alignment": starlark.MakeUint64(p.Align), "flags": starlark.MakeUint(uint(p.Flags)),
	})
}

func StructsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	var requested *starlark.List
	if err := starlark.UnpackArgs("elf_structs", args, kwargs, "file", &source, "names", &requested); err != nil {
		return nil, err
	}
	file, ok := source.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("elf_structs: expected an ELF file")
	}
	if requested.Len() == 0 || requested.Len() > 64 {
		return nil, fmt.Errorf("elf_structs: expected 1..64 structure names")
	}
	names := make([]string, requested.Len())
	for i := range names {
		name, ok := starlark.AsString(requested.Index(i))
		if !ok {
			return nil, fmt.Errorf("elf_structs: structure names must be strings")
		}
		names[i] = name
	}
	layouts, err := StructLayouts(file, names)
	if err != nil {
		return nil, err
	}
	out := starlark.NewDict(len(names))
	for _, name := range names {
		layout := layouts[name]
		fields := make(starlark.StringDict, len(layout.Fields))
		for field, offset := range layout.Fields {
			fields[field] = starlark.MakeUint64(offset)
		}
		if err := out.SetKey(starlark.String(name), starfile.NewRecord(starlark.StringDict{
			"size": starlark.MakeUint64(layout.Size), "fields": starfile.NewRecord(fields),
		})); err != nil {
			return nil, err
		}
	}
	out.Freeze()
	return out, nil
}
