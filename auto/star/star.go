// Package star exposes the Go auto registry and nodes to Starlark.
package star

import (
	"errors"
	"fmt"
	"io/fs"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	_ "github.com/tinyrange/trex/auto/imports"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type Value struct{ Node *auto.Node }

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	name := ""
	options := auto.Options{MaxExpandedBytes: 512 << 20, MaxEntries: 100000, MaxDepth: 32}
	if err := starlark.UnpackArgs("auto", args, kwargs, "source", &source, "name?", &name, "maximum?", &options.MaxExpandedBytes, "maximum_entries?", &options.MaxEntries, "maximum_depth?", &options.MaxDepth); err != nil {
		return nil, err
	}
	if options.MaxExpandedBytes <= 0 || options.MaxEntries <= 0 || options.MaxDepth <= 0 {
		return nil, fmt.Errorf("auto: limits must be positive")
	}
	if v, ok := source.(*Value); ok {
		return v, nil
	}
	if reader, ok := source.(storage.Reader); ok {
		return &Value{auto.Open(reader, name, options)}, nil
	}
	switch source := source.(type) {
	case starlark.Bytes:
		return &Value{auto.Open(&starfile.Bytes{Data: []byte(source)}, name, options)}, nil
	case starlark.String:
		return &Value{auto.Open(&starfile.Bytes{Data: []byte(source)}, name, options)}, nil
	}
	var view auto.View
	var err error
	if directory, ok := source.(interface {
		AutoView(auto.Options) (auto.View, error)
	}); ok {
		view, err = directory.AutoView(options)
	} else {
		view, err = adapter.Parsed(source, options)
	}
	if err != nil {
		return nil, fmt.Errorf("auto: expected byte view, file or filesystem: %w", err)
	}
	return &Value{auto.FromView(view, name, options)}, nil
}
func (*Value) String() string        { return "<auto>" }
func (*Value) Type() string          { return "auto" }
func (*Value) Freeze()               {}
func (*Value) Truth() starlark.Bool  { return starlark.True }
func (*Value) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable auto view") }
func (v *Value) Get(key starlark.Value) (starlark.Value, bool, error) {
	name, ok := starlark.AsString(key)
	if !ok {
		return nil, false, fmt.Errorf("auto path must be a string")
	}
	n, err := v.Node.Resolve(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return &Value{n}, true, nil
}
func (v *Value) Attr(name string) (starlark.Value, error) {
	switch name {
	case "name":
		return starlark.String(v.Node.Name()), nil
	case "file":
		if v.Node.Reader() == nil {
			return starlark.None, nil
		}
		return adapter.File(v.Node.Reader()), nil
	case "metadata":
		m, err := v.Node.Metadata()
		if err != nil {
			return nil, err
		}
		return Metadata(m), nil
	case "files":
		children, err := v.Node.Children()
		if err != nil {
			return nil, err
		}
		out := make([]starlark.Value, len(children))
		for i, c := range children {
			out[i] = &Value{c}
		}
		return starlark.NewList(out), nil
	case "find":
		return starlark.NewBuiltin("auto.find", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var name string
			if err := starlark.UnpackArgs("find", args, kwargs, "path", &name); err != nil {
				return nil, err
			}
			result, found, err := v.Get(starlark.String(name))
			if !found && err == nil {
				return starlark.None, nil
			}
			return result, err
		}), nil
	}
	if v.Node.Reader() != nil {
		return starfile.Attr(adapter.File(v.Node.Reader()), name), nil
	}
	return nil, nil
}
func (*Value) AttrNames() []string {
	return append(starfile.AttrNames(), "file", "files", "find", "metadata", "name")
}
func Metadata(m auto.Metadata) *starlark.Dict {
	d := starlark.NewDict(6)
	for k, v := range map[string]starlark.Value{"name": starlark.String(m.Name), "kind": starlark.String(m.Kind), "size": starlark.MakeInt64(m.Size), "format": starlark.String(m.Format), "container": starlark.Bool(m.Container), "readable": starlark.Bool(m.Readable)} {
		_ = d.SetKey(starlark.String(k), v)
	}
	return d
}
