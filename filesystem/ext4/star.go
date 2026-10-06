package ext4

import (
	"encoding/hex"
	"fmt"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/filesystem/unixfs"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func BuildBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	var options BuildOptions
	uuid := ""
	if err := starlark.UnpackArgs("ext4_build", args, kwargs, "entries", &value, "size", &options.Size, "label?", &options.Label, "uuid?", &uuid); err != nil {
		return nil, err
	}
	if uuid != "" {
		data, err := hex.DecodeString(uuid)
		if err != nil || len(data) != 16 {
			return nil, fmt.Errorf("ext4_build: uuid must be 32 hex digits")
		}
		copy(options.UUID[:], data)
	}
	entries, err := unixfs.ParseEntries(value)
	if err != nil {
		return nil, err
	}
	r, err := Build(entries, options)
	if err != nil {
		return nil, err
	}
	return starfile.NewReader("ext4 image", r), nil
}
func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	options := auto.Options{MaxEntries: 100000, MaxDepth: 32}
	if err := starlark.UnpackArgs("ext4", args, kwargs, "file", &value, "maximum_entries?", &options.MaxEntries, "maximum_depth?", &options.MaxDepth); err != nil {
		return nil, err
	}
	source, ok := value.(storage.Reader)
	if !ok || options.MaxEntries <= 0 || options.MaxDepth <= 0 {
		return nil, fmt.Errorf("ext4: expected file and positive limits")
	}
	v, err := Read(source, options)
	if err != nil {
		return nil, err
	}
	root := &dirView{volume: v, id: 2, ancestors: map[uint32]bool{2: true}}
	var entries []starlark.Value
	var files []starlark.Value
	var walk func(auto.View, string) error
	walk = func(view auto.View, base string) error {
		items, err := view.Entries()
		if err != nil {
			return err
		}
		for _, e := range items {
			if len(entries) >= options.MaxEntries {
				return auto.ErrLimit
			}
			name := e.Name
			if base != "" {
				name = base + "/" + name
			}
			attrs := starlark.StringDict{"path": starlark.String(name), "kind": starlark.String(e.Kind)}
			for k, val := range e.Attributes {
				switch val := val.(type) {
				case uint32:
					attrs[k] = starlark.MakeUint(uint(val))
				case string:
					attrs[k] = starlark.String(val)
				}
			}
			attrs["data"] = starlark.None
			if e.Reader != nil {
				attrs["data"] = starfile.NewReader(name, e.Reader)
				files = append(files, starlark.String(name))
			}
			entries = append(entries, starfile.NewRecord(attrs))
			if e.View != nil {
				if err := walk(e.View, name); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(root, ""); err != nil {
		return nil, err
	}
	return starfile.NewRecord(starlark.StringDict{"entries": starlark.NewList(entries), "files": starlark.NewList(files), "label": starlark.String(v.label), "block_size": starlark.MakeUint64(v.block)}), nil
}
