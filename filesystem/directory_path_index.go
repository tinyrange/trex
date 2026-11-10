package filesystem

import (
	"fmt"
	"go.starlark.net/starlark"
	"sort"
	"sync"
)

// pathIndex owns an immutable namespace snapshot, independent of file contents.
// Lookup does not construct Starlark hash tables or sort enumeration keys.
type pathIndex struct {
	names map[string]string
	once  sync.Once
	keys  []string
}

var _ starlark.IterableMapping = (*pathIndex)(nil)

func (p *pathIndex) String() string       { return fmt.Sprintf("<path_index: %d paths>", p.Len()) }
func (*pathIndex) Type() string           { return "path_index" }
func (*pathIndex) Freeze()                {}
func (p *pathIndex) Truth() starlark.Bool { return starlark.Bool(p.Len() != 0) }
func (*pathIndex) Hash() (uint32, error)  { return 0, fmt.Errorf("unhashable: path_index") }
func (p *pathIndex) Len() int             { return len(p.names) }
func (p *pathIndex) Get(key starlark.Value) (starlark.Value, bool, error) {
	name, ok := starlark.AsString(key)
	if !ok {
		return nil, false, fmt.Errorf("path_index: key must be a string, got %s", key.Type())
	}
	value, found := p.names[name]
	if !found {
		return nil, false, nil
	}
	return starlark.String(value), true, nil
}
func (p *pathIndex) sortedKeys() []string {
	p.once.Do(func() {
		p.keys = make([]string, 0, len(p.names))
		for key := range p.names {
			p.keys = append(p.keys, key)
		}
		sort.Strings(p.keys)
	})
	return p.keys
}
func (p *pathIndex) Items() []starlark.Tuple {
	items := make([]starlark.Tuple, 0, p.Len())
	for _, key := range p.sortedKeys() {
		items = append(items, starlark.Tuple{starlark.String(key), starlark.String(p.names[key])})
	}
	return items
}
func (p *pathIndex) Iterate() starlark.Iterator { return &pathIndexIterator{keys: p.sortedKeys()} }

type pathIndexIterator struct {
	keys []string
	pos  int
}

func (i *pathIndexIterator) Next(v *starlark.Value) bool {
	if i.pos == len(i.keys) {
		return false
	}
	*v = starlark.String(i.keys[i.pos])
	i.pos++
	return true
}
func (*pathIndexIterator) Done()       {}
func (*pathIndex) AttrNames() []string { return []string{"get", "items", "keys", "values"} }
func (p *pathIndex) Attr(name string) (starlark.Value, error) {
	switch name {
	case "get":
		return starlark.NewBuiltin(name, func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var key starlark.Value
			var fallback starlark.Value = starlark.None
			if err := starlark.UnpackArgs("path_index.get", args, kwargs, "key", &key, "default?", &fallback); err != nil {
				return nil, err
			}
			value, found, err := p.Get(key)
			if err != nil {
				return nil, err
			}
			if !found {
				return fallback, nil
			}
			return value, nil
		}), nil
	case "keys", "values", "items":
		return starlark.NewBuiltin(name, func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs("path_index."+name, args, kwargs); err != nil {
				return nil, err
			}
			values := make([]starlark.Value, 0, p.Len())
			for _, key := range p.sortedKeys() {
				switch name {
				case "keys":
					values = append(values, starlark.String(key))
				case "values":
					values = append(values, starlark.String(p.names[key]))
				case "items":
					values = append(values, starlark.Tuple{starlark.String(key), starlark.String(p.names[key])})
				}
			}
			return starlark.NewList(values), nil
		}), nil
	}
	return nil, nil
}
func (d *Directory) pathIndex(lower, includeEmpty bool) (*pathIndex, error) {
	slot := 0
	if lower {
		slot |= 1
	}
	if includeEmpty {
		slot |= 2
	}
	if d.pathIndexes[slot] == nil {
		index, err := d.buildPathIndex(lower, includeEmpty)
		if err != nil {
			return nil, err
		}
		d.pathIndexes[slot] = index
	}
	return d.pathIndexes[slot], nil
}
func (d *Directory) pathIndexBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	lower, includeEmpty := false, true
	if err := starlark.UnpackArgs("path_index", args, kwargs, "lower?", &lower, "include_empty?", &includeEmpty); err != nil {
		return nil, err
	}
	return d.pathIndex(lower, includeEmpty)
}
