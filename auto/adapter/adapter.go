// Package adapter bridges existing parser values to the portable auto.View interface.
package adapter

import (
	"fmt"
	"path"
	"strings"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type adapter struct {
	options auto.Options
	folded  bool
}

func File(r storage.Reader) starfile.File { return &readFile{r} }

type Builtin func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error)

func Parse(fn Builtin, r storage.Reader, options auto.Options) (auto.View, error) {
	value, err := fn(nil, nil, starlark.Tuple{File(r)}, nil)
	if err != nil {
		return nil, err
	}
	return Parsed(value, options)
}

type readFile struct{ storage.Reader }

func (*readFile) WriteAt([]byte, int64) (int, error)         { return 0, fmt.Errorf("read-only file") }
func (*readFile) String() string                             { return "<auto.file>" }
func (*readFile) Type() string                               { return "file" }
func (*readFile) Freeze()                                    {}
func (*readFile) Truth() starlark.Bool                       { return starlark.True }
func (*readFile) Hash() (uint32, error)                      { return 0, fmt.Errorf("unhashable file") }
func (f *readFile) Attr(name string) (starlark.Value, error) { return starfile.Attr(f, name), nil }
func (*readFile) AttrNames() []string                        { return starfile.AttrNames() }

func attr(v starlark.Value, name string) starlark.Value {
	if a, ok := v.(starlark.HasAttrs); ok {
		value, _ := a.Attr(name)
		return value
	}
	return nil
}
func textAttr(v starlark.Value, name string) string {
	value := attr(v, name)
	if s, ok := starlark.AsString(value); ok {
		return s
	}
	return ""
}
func values(v starlark.Value) []starlark.Value {
	var out []starlark.Value
	if seq, ok := v.(starlark.Iterable); ok {
		it := seq.Iterate()
		defer it.Done()
		var value starlark.Value
		for it.Next(&value) {
			out = append(out, value)
		}
	}
	return out
}

func Parsed(value starlark.Value, options auto.Options) (auto.View, error) {
	n := &adapter{options: options, folded: value.Type() == "fat" || value.Type() == "ntfs" || value.Type() == "iso" || value.Type() == "udf"}
	mapping, ok := value.(starlark.Mapping)
	if !ok {
		return nil, fmt.Errorf("%s has no file mapping", value.Type())
	}
	entries := attr(value, "entries")
	if entries != nil {
		var items []auto.Entry
		for _, v := range values(entries) {
			original := textAttr(v, "name")
			for _, part := range strings.Split(strings.ReplaceAll(original, "\\", "/"), "/") {
				if part == ".." || strings.ContainsRune(part, 0) {
					return nil, fmt.Errorf("unsafe archive path %q", original)
				}
			}
			name := textAttr(v, "path")
			if name == "" {
				name = original
			}
			kind := textAttr(v, "entry_type")
			if kind == "" {
				kind = "file"
			}
			reader, _ := v.(storage.Reader)
			if kind != "file" && kind != "hardlink" {
				reader = nil
			}
			attributes := map[string]any{}
			for _, key := range []string{"link", "mode", "uid", "gid", "mtime", "crc32", "stored_size"} {
				a := attr(v, key)
				switch a := a.(type) {
				case starlark.String:
					attributes[key] = string(a)
				case starlark.Int:
					if x, ok := a.Int64(); ok {
						attributes[key] = x
					}
				}
			}
			items = append(items, auto.Entry{Name: name, Kind: kind, Reader: reader, Attributes: attributes})
		}
		return auto.Tree(items, n.options)
	}
	root, found, err := mapping.Get(starlark.String("/"))
	if err != nil {
		return nil, err
	}
	if found && root != nil && hasAttr(root, "files") {
		return n.dirView(mapping, root), nil
	}
	var items []auto.Entry
	for _, nameValue := range values(attr(value, "files")) {
		name, ok := starlark.AsString(nameValue)
		if !ok {
			return nil, fmt.Errorf("invalid file name in %s", value.Type())
		}
		v, found, err := mapping.Get(starlark.String(name))
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("missing indexed file %q", name)
		}
		reader, _ := v.(storage.Reader)
		kind := "file"
		if reader == nil {
			kind = "directory"
		}
		items = append(items, auto.Entry{Name: name, Kind: kind, Reader: reader})
	}
	return auto.Tree(items, n.options)
}
func (n *adapter) mappedChildren(mapping starlark.Mapping, dir starlark.Value) ([]auto.Entry, error) {
	var out []auto.Entry
	files, err := dir.(starlark.HasAttrs).Attr("files")
	if err != nil {
		return nil, err
	}
	for _, v := range values(files) {
		name, ok := starlark.AsString(v)
		if !ok {
			return nil, fmt.Errorf("invalid directory entry")
		}
		value, found, err := mapping.Get(starlark.String(name))
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("missing directory member %q", name)
		}
		child := auto.Entry{Name: path.Base(name), Kind: "file"}
		if reader, ok := value.(storage.Reader); ok {
			child.Reader = reader
		} else {
			child.Kind = "directory"
			child.View = n.dirView(mapping, value)
		}
		out = append(out, child)
		if len(out) > n.options.MaxEntries {
			return nil, fmt.Errorf("%w: directory entries", auto.ErrLimit)
		}
	}
	return out, nil
}

func hasAttr(value starlark.Value, name string) bool {
	a, ok := value.(starlark.HasAttrs)
	if !ok {
		return false
	}
	for _, n := range a.AttrNames() {
		if n == name {
			return true
		}
	}
	return false
}

func (n *adapter) dirView(mapping starlark.Mapping, dir starlark.Value) auto.View {
	var view auto.View = auto.ViewFunc(func() ([]auto.Entry, error) { return n.mappedChildren(mapping, dir) })
	if n.folded {
		return &auto.FoldedView{View: view}
	}
	return view
}
