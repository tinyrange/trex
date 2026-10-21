package elfmeta

import (
	"fmt"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	options := Options{MaximumSymbols: 1000000, MaximumStringBytes: 16 << 20}
	if err := starlark.UnpackArgs("elf_symbols", args, kwargs, "file", &source, "maximum_symbols?", &options.MaximumSymbols, "maximum_string_bytes?", &options.MaximumStringBytes); err != nil {
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
		segments[i] = starfile.NewRecord(starlark.StringDict{"address": starlark.MakeUint64(p.Vaddr), "offset": starlark.MakeUint64(p.Off), "file_size": starlark.MakeUint64(p.Filesz), "memory_size": starlark.MakeUint64(p.Memsz), "flags": starlark.MakeUint(uint(p.Flags))})
	}
	return starfile.NewRecord(starlark.StringDict{"type": starlark.MakeUint(uint(image.Type)), "machine": starlark.MakeUint(uint(image.Machine)), "entry": starlark.MakeUint64(image.Entry), "little_endian": starlark.Bool(image.LittleEndian), "symbols": starlark.NewList(symbols), "segments": starlark.NewList(segments)}), nil
}
