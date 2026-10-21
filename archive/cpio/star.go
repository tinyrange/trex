package cpio

import (
	"fmt"
	"github.com/tinyrange/trex/filesystem/unixfs"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func BuildBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("cpio_build", args, kwargs, "entries", &value); err != nil {
		return nil, err
	}
	entries, err := unixfs.ParseEntries(value)
	if err != nil {
		return nil, err
	}
	r, err := Build(entries)
	if err != nil {
		return nil, err
	}
	return starfile.NewReader("initramfs.cpio", r), nil
}
func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	max := 100000
	var appleDouble bool
	if err := starlark.UnpackArgs("cpio", args, kwargs, "file", &value, "maximum_entries?", &max, "apple_double?", &appleDouble); err != nil {
		return nil, err
	}
	r, ok := value.(storage.Reader)
	if !ok || max <= 0 {
		return nil, fmt.Errorf("cpio: expected file and positive maximum_entries")
	}
	entries, err := Read(r, max)
	if err != nil {
		return nil, err
	}
	if appleDouble {
		entries, err = WithAppleDouble(entries)
		if err != nil {
			return nil, err
		}
	}
	out := make([]starlark.Value, 0, len(entries))
	for _, e := range entries {
		d := starlark.NewDict(len(e.Attributes) + 3)
		d.SetKey(starlark.String("path"), starlark.String(e.Name))
		d.SetKey(starlark.String("kind"), starlark.String(e.Kind))
		for k, v := range e.Attributes {
			switch v := v.(type) {
			case uint64:
				d.SetKey(starlark.String(k), starlark.MakeUint64(v))
			case string:
				d.SetKey(starlark.String(k), starlark.String(v))
			case storage.Reader:
				d.SetKey(starlark.String(k), starfile.NewReader(k, v))
			case map[string]storage.Reader:
				attrs := starlark.NewDict(len(v))
				for name, data := range v {
					attrs.SetKey(starlark.String(name), starfile.NewReader(name, data))
				}
				d.SetKey(starlark.String(k), attrs)
			}
		}
		if e.Reader != nil {
			d.SetKey(starlark.String("data"), starfile.NewReader(e.Name, e.Reader))
		}
		out = append(out, d)
	}
	return starlark.NewList(out), nil
}
