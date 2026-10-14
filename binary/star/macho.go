package star

import (
	"fmt"
	"github.com/tinyrange/trex/binary/macho"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func machoBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var input starlark.Value
	architecture := "x86_64"
	var subtype starlark.Value = starlark.None
	if err := starlark.UnpackArgs("macho", args, kwargs, "file", &input, "architecture?", &architecture, "cpu_subtype?", &subtype); err != nil {
		return nil, err
	}
	file, ok := input.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("macho: expected file")
	}
	var cpu uint32
	switch architecture {
	case "x86_64":
		cpu = macho.AMD64
	case "arm64":
		cpu = macho.ARM64
	default:
		return nil, fmt.Errorf("macho: expected x86_64 or arm64 architecture")
	}
	var image *macho.Image
	var err error
	if subtype == starlark.None {
		image, err = macho.Open(file, cpu)
	} else {
		var value uint32
		if err := starlark.AsInt(subtype, &value); err != nil {
			return nil, fmt.Errorf("macho: cpu_subtype: %w", err)
		}
		image, err = macho.OpenSubtype(file, cpu, value)
	}
	if err != nil {
		return nil, err
	}
	return machoValue(image, architecture)
}

func machoValue(image *macho.Image, architecture string) (starlark.Value, error) {
	symbols := make([]starlark.Value, 0, len(image.Symbols))
	for _, s := range image.Symbols {
		symbols = append(symbols, starfile.NewRecord(starlark.StringDict{"name": starlark.String(s.Name), "address": starlark.MakeUint64(s.Address), "type": starlark.MakeInt(int(s.Type)), "section": starlark.MakeInt(int(s.Section)), "description": starlark.MakeInt(int(s.Description))}))
	}
	segments := make([]starlark.Value, 0, len(image.Segments))
	exports := make([]starlark.Value, 0, len(image.Exports))
	imports := make([]starlark.Value, 0, len(image.Imports))
	for _, i := range image.Imports {
		imports = append(imports, starfile.NewRecord(starlark.StringDict{"name": starlark.String(i.Name), "kind": starlark.String(i.Kind), "address": starlark.MakeUint64(i.Address), "size": starlark.MakeUint64(i.Size)}))
	}
	for _, e := range image.Exports {
		exports = append(exports, starfile.NewRecord(starlark.StringDict{"name": starlark.String(e.Name), "address": starlark.MakeUint64(e.Address), "flags": starlark.MakeUint64(e.Flags), "resolver": starlark.MakeUint64(e.Resolver), "reexport_ordinal": starlark.MakeUint64(e.ReexportOrdinal), "import_name": starlark.String(e.ImportName)}))
	}
	for _, s := range image.Segments {
		segments = append(segments, starfile.NewRecord(starlark.StringDict{"name": starlark.String(s.Name), "address": starlark.MakeUint64(s.Address), "size": starlark.MakeUint64(s.Size), "file_offset": starlark.MakeUint64(s.Offset), "file_size": starlark.MakeUint64(s.FileSize), "flags": starlark.MakeUint(uint(s.Flags)), "data": starfile.NewReader(s.Name, s.Data)}))
	}
	entries := make([]starlark.Value, 0, len(image.FilesetEntries))
	for _, e := range image.FilesetEntries {
		entries = append(entries, starfile.NewRecord(starlark.StringDict{"name": starlark.String(e.Name), "address": starlark.MakeUint64(e.Address), "file_offset": starlark.MakeUint64(e.Offset)}))
	}
	at := starlark.NewBuiltin("macho.at", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var address, size uint64
		if err := starlark.UnpackArgs("at", args, kwargs, "address", &address, "size", &size); err != nil {
			return nil, err
		}
		r, err := image.At(address, size)
		if err != nil {
			return nil, err
		}
		return starfile.NewReader("macho virtual bytes", r), nil
	})
	fileset := starlark.NewBuiltin("macho.fileset", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var name string
		if err := starlark.UnpackArgs("fileset", args, kwargs, "name", &name); err != nil {
			return nil, err
		}
		entry, err := image.Fileset(name)
		if err != nil {
			return nil, err
		}
		return machoValue(entry, architecture)
	})
	return starfile.NewRecord(starlark.StringDict{"architecture": starlark.String(architecture), "cpu_subtype": starlark.MakeUint(uint(image.Subtype)), "type": starlark.MakeUint(uint(image.Type)), "entry": starlark.MakeUint64(image.Entry), "file": starfile.NewReader("macho selected image", image.Source), "segments": starlark.NewList(segments), "symbols": starlark.NewList(symbols), "exports": starlark.NewList(exports), "imports": starlark.NewList(imports), "fileset_entries": starlark.NewList(entries), "fileset": fileset, "at": at}), nil
}
