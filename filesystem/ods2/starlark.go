package ods2

import (
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type starFile struct{ *File }

func (*starFile) String() string                             { return "<ods2 file>" }
func (*starFile) Type() string                               { return "file" }
func (*starFile) Freeze()                                    {}
func (*starFile) Truth() starlark.Bool                       { return starlark.True }
func (*starFile) Hash() (uint32, error)                      { return 0, fmt.Errorf("unhashable: file") }
func (f *starFile) Attr(name string) (starlark.Value, error) { return starfile.Attr(f, name), nil }
func (*starFile) AttrNames() []string                        { return starfile.AttrNames() }

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximum, depth := 1000000, 64
	if err := starlark.UnpackArgs("ods2", args, kwargs, "file", &value, "maximum_entries?", &maximum, "maximum_depth?", &depth); err != nil {
		return nil, err
	}
	f, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("ods2: expected file")
	}
	v, err := Open(f)
	if err != nil {
		return nil, err
	}
	rows, err := v.Walk(maximum, depth)
	if err != nil {
		return nil, err
	}
	entries, paths := []starlark.Value{}, []starlark.Value{}
	index := map[string]starlark.Value{}
	for _, e := range rows {
		kind := "file"
		if e.Directory {
			kind = "directory"
		}
		r := starfile.NewRecord(starlark.StringDict{
			"path": starlark.String(e.Path), "name": starlark.Bytes(e.Name), "version": starlark.MakeUint(uint(e.Version)),
			"entry_type": starlark.String(kind), "directory_link": starlark.Bool(e.DirectoryLink),
			"file_number": starlark.MakeUint(uint(e.Header.ID.Number)), "sequence": starlark.MakeUint(uint(e.Header.ID.Sequence)),
			"header": starlark.Bytes(e.Header.Raw), "record_attributes": starlark.Bytes(e.Header.RecordAttributes),
			"characteristics": starlark.MakeUint(uint(e.Header.Characteristics)), "size": starlark.MakeInt64(e.Data.Size()), "data": &starFile{e.Data},
		})
		entries = append(entries, r)
		paths = append(paths, starlark.String(e.Path))
		index[e.Path] = r
	}
	find := starlark.NewBuiltin("ods2.find", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var path string
		if err := starlark.UnpackArgs("find", args, kwargs, "path", &path); err != nil {
			return nil, err
		}
		if v := index[path]; v != nil {
			return v, nil
		}
		return starlark.None, nil
	})
	return starfile.NewRecord(starlark.StringDict{"entries": starlark.NewList(entries), "files": starlark.NewList(paths), "find": find, "home": starlark.Bytes(v.Home.Raw), "volume_name": starlark.Bytes(v.Home.VolumeName)}), nil
}
