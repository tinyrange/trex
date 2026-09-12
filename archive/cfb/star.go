package cfb

import (
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var file starfile.File
	if err := starlark.UnpackArgs("cfb", args, kwargs, "file", &file); err != nil {
		return nil, err
	}
	return Open(file)
}
func (a *Archive) String() string      { return fmt.Sprintf("<cfb streams=%d>", len(a.streams)) }
func (*Archive) Type() string          { return "cfb" }
func (*Archive) Freeze()               {}
func (*Archive) Truth() starlark.Bool  { return starlark.True }
func (*Archive) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: cfb") }
func (a *Archive) Get(key starlark.Value) (starlark.Value, bool, error) {
	name, ok := starlark.AsString(key)
	if !ok {
		return nil, false, fmt.Errorf("cfb: stream name must be a string")
	}
	s := a.Lookup(name)
	if s == nil {
		return nil, false, nil
	}
	return s, true, nil
}
func (*Archive) AttrNames() []string { return []string{"files", "find", "class_id"} }
func (a *Archive) Attr(name string) (starlark.Value, error) {
	switch name {
	case "class_id":
		return starlark.Bytes(a.ClassID[:]), nil
	case "files":
		names := a.Files()
		values := make([]starlark.Value, len(names))
		for i, n := range names {
			values[i] = starlark.String(n)
		}
		return starlark.NewList(values), nil
	case "find":
		return starlark.NewBuiltin("cfb.find", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var name string
			if err := starlark.UnpackArgs("cfb.find", args, kwargs, "name", &name); err != nil {
				return nil, err
			}
			s := a.Lookup(name)
			if s == nil {
				return starlark.None, nil
			}
			return s, nil
		}), nil
	}
	return nil, nil
}
