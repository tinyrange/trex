package cpio

import (
	"fmt"
	"github.com/tinyrange/trex/auto"
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
	if err := starlark.UnpackArgs("cpio", args, kwargs, "file", &value, "maximum_entries?", &max); err != nil {
		return nil, err
	}
	r, ok := value.(storage.Reader)
	if !ok || max <= 0 {
		return nil, fmt.Errorf("cpio: expected file and positive maximum_entries")
	}
	var prefix [6]byte
	if _, err := r.ReadAt(prefix[:], 0); err != nil {
		return nil, err
	}
	view, err := Open(prefix[:], r, auto.Options{MaxEntries: max})
	if err != nil {
		return nil, err
	}
	// Return flat records rather than losing Unix metadata in a directory adapter.
	entries, err := view.Entries()
	if err != nil {
		return nil, err
	}
	var out []starlark.Value
	var walk func([]auto.Entry, string) error
	walk = func(items []auto.Entry, base string) error {
		for _, e := range items {
			name := e.Name
			if base != "" {
				name = base + "/" + name
			}
			d := starlark.NewDict(8)
			d.SetKey(starlark.String("path"), starlark.String(name))
			d.SetKey(starlark.String("kind"), starlark.String(e.Kind))
			for k, v := range e.Attributes {
				switch v := v.(type) {
				case uint64:
					d.SetKey(starlark.String(k), starlark.MakeUint64(v))
				case string:
					d.SetKey(starlark.String(k), starlark.String(v))
				}
			}
			if e.Reader != nil {
				d.SetKey(starlark.String("data"), starfile.NewReader(name, e.Reader))
			}
			out = append(out, d)
			if e.View != nil {
				children, err := e.View.Entries()
				if err != nil {
					return err
				}
				if err := walk(children, name); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(entries, ""); err != nil {
		return nil, err
	}
	return starlark.NewList(out), nil
}
