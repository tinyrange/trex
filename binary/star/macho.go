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
	if architecture != "x86_64" {
		return nil, fmt.Errorf("macho: only x86_64 inspection supported")
	}
	var image *macho.Image
	var err error
	if subtype == starlark.None {
		image, err = macho.Open(file, macho.AMD64)
	} else {
		var value uint32
		if err := starlark.AsInt(subtype, &value); err != nil {
			return nil, fmt.Errorf("macho: cpu_subtype: %w", err)
		}
		image, err = macho.OpenSubtype(file, macho.AMD64, value)
	}
	if err != nil {
		return nil, err
	}
	symbols := make([]starlark.Value, 0, len(image.Symbols))
	for _, s := range image.Symbols {
		symbols = append(symbols, starfile.NewRecord(starlark.StringDict{"name": starlark.String(s.Name), "address": starlark.MakeUint64(s.Address), "type": starlark.MakeInt(int(s.Type)), "section": starlark.MakeInt(int(s.Section)), "description": starlark.MakeInt(int(s.Description))}))
	}
	segments := make([]starlark.Value, 0, len(image.Segments))
	for _, s := range image.Segments {
		segments = append(segments, starfile.NewRecord(starlark.StringDict{"name": starlark.String(s.Name), "address": starlark.MakeUint64(s.Address), "size": starlark.MakeUint64(s.Size), "file_offset": starlark.MakeUint64(s.Offset), "file_size": starlark.MakeUint64(s.FileSize), "flags": starlark.MakeUint(uint(s.Flags)), "data": starfile.NewReader(s.Name, s.Data)}))
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
	return starfile.NewRecord(starlark.StringDict{"architecture": starlark.String(architecture), "cpu_subtype": starlark.MakeUint(uint(image.Subtype)), "type": starlark.MakeUint(uint(image.Type)), "file": starfile.NewReader("macho selected image", image.Source), "segments": starlark.NewList(segments), "symbols": starlark.NewList(symbols), "at": at}), nil
}
