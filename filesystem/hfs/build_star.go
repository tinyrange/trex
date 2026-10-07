package hfs

import (
	"fmt"
	"github.com/tinyrange/trex/filesystem/unixfs"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func BuildBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var input starlark.Value
	options := BuildOptions{Label: "Untitled"}
	if err := starlark.UnpackArgs("hfs_build", args, kwargs, "entries", &input, "size", &options.Size, "label?", &options.Label); err != nil {
		return nil, err
	}
	iter := starlark.Iterate(input)
	if iter == nil {
		return nil, fmt.Errorf("hfs_build: expected entries iterable")
	}
	defer iter.Done()
	var entries []BuildEntry
	var v starlark.Value
	for iter.Next(&v) {
		if len(entries) >= 1000000 {
			return nil, fmt.Errorf("hfs_build: entry limit")
		}
		d, ok := v.(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("hfs_build: entries must be dictionaries")
		}
		plain := starlark.NewDict(d.Len())
		var e BuildEntry
		for _, pair := range d.Items() {
			name, ok := starlark.AsString(pair[0])
			if !ok {
				return nil, fmt.Errorf("hfs_build: invalid field")
			}
			switch name {
			case "finder_info":
				b, err := starfile.BytesForValue(pair[1], 32)
				if err != nil {
					return nil, err
				}
				e.FinderInfo = b
			case "resource":
				var err error
				e.Resource, err = buildPayload(pair[1])
				if err != nil {
					return nil, err
				}
			case "owner_flags", "admin_flags":
				var n uint8
				if err := starlark.AsInt(pair[1], &n); err != nil {
					return nil, err
				}
				if name == "owner_flags" {
					e.OwnerFlags = n
				} else {
					e.AdminFlags = n
				}
			case "xattrs":
				attrs, ok := pair[1].(*starlark.Dict)
				if !ok {
					return nil, fmt.Errorf("hfs_build: xattrs must be dict")
				}
				e.Xattrs = map[string]storage.Reader{}
				for _, item := range attrs.Items() {
					key, ok := starlark.AsString(item[0])
					if !ok {
						return nil, fmt.Errorf("hfs_build: attribute name must be string")
					}
					r, err := buildPayload(item[1])
					if err != nil {
						return nil, err
					}
					e.Xattrs[key] = r
				}
			default:
				if err := plain.SetKey(pair[0], pair[1]); err != nil {
					return nil, err
				}
			}
		}
		parsed, err := unixfs.ParseEntries(starlark.NewList([]starlark.Value{plain}))
		if err != nil {
			return nil, err
		}
		e.Entry = parsed[0]
		entries = append(entries, e)
	}
	r, err := Build(entries, options)
	if err != nil {
		return nil, err
	}
	return starfile.NewReader("HFSX volume", r), nil
}
func buildPayload(v starlark.Value) (storage.Reader, error) {
	switch v := v.(type) {
	case storage.Reader:
		return v, nil
	case starlark.String:
		return &starfile.Bytes{Data: []byte(v)}, nil
	case starlark.Bytes:
		return &starfile.Bytes{Data: []byte(v)}, nil
	default:
		return nil, fmt.Errorf("hfs_build: expected file, string or bytes")
	}
}
