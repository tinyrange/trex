package rar

import (
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"strings"
)

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var v starlark.Value
	maximum := 100000
	if e := starlark.UnpackArgs("rar", args, kwargs, "file", &v, "maximum_entries?", &maximum); e != nil {
		return nil, e
	}
	f, ok := v.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("rar: expected file")
	}
	return Open(f, maximum)
}
func (a *Archive) String() string        { return fmt.Sprintf("<rar %d entries>", len(a.Files)) }
func (a *Archive) Type() string          { return "rar" }
func (a *Archive) Freeze()               {}
func (a *Archive) Truth() starlark.Bool  { return starlark.True }
func (a *Archive) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: rar") }
func (a *Archive) Get(key starlark.Value) (starlark.Value, bool, error) {
	name, ok := starlark.AsString(key)
	if !ok {
		return nil, false, fmt.Errorf("rar: expected path string")
	}
	for _, f := range a.Files {
		if strings.TrimPrefix(f.Name, "/") == strings.TrimPrefix(name, "/") {
			return f, true, nil
		}
	}
	return nil, false, nil
}
func (a *Archive) AttrNames() []string { return []string{"entries", "files"} }
func (a *Archive) Attr(name string) (starlark.Value, error) {
	if name != "files" && name != "entries" {
		return nil, nil
	}
	out := make([]starlark.Value, 0, len(a.Files))
	for _, f := range a.Files {
		if name == "entries" {
			out = append(out, f)
		} else if !f.Directory {
			out = append(out, starlark.String(f.Name))
		}
	}
	return starlark.NewList(out), nil
}
func (f *File) String() string                     { return fmt.Sprintf("<rar.file %q size=%d>", f.Name, f.Size()) }
func (f *File) Type() string                       { return "file" }
func (f *File) Freeze()                            {}
func (f *File) Truth() starlark.Bool               { return starlark.True }
func (f *File) Hash() (uint32, error)              { return 0, fmt.Errorf("unhashable: file") }
func (f *File) WriteAt([]byte, int64) (int, error) { return 0, fmt.Errorf("rar: read-only file") }
func (f *File) AttrNames() []string {
	return append([]string{"name", "is_dir", "solid", "packed_size"}, starfile.AttrNames()...)
}
func (f *File) Attr(name string) (starlark.Value, error) {
	switch name {
	case "name":
		return starlark.String(f.Name), nil
	case "is_dir":
		return starlark.Bool(f.Directory), nil
	case "solid":
		return starlark.Bool(f.Solid), nil
	case "packed_size":
		return starlark.MakeInt64(f.PackedSize), nil
	}
	return starfile.Attr(f, name), nil
}
