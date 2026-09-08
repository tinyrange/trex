// Package imports provides immutable, architecture-independent import queries.
package imports

import (
	"fmt"
	"strings"

	"go.starlark.net/starlark"
)

type entry struct {
	name  string
	value starlark.Value
}

// Index preserves the machine's import order and original record spelling.
// Rebuild it when modules add imports; it contains no mutable guest state.
type Index struct{ entries []entry }

func New(records *starlark.List) *Index {
	index := &Index{entries: make([]entry, records.Len())}
	for i := range index.entries {
		value := records.Index(i)
		name, _ := value.(starlark.HasAttrs).Attr("name")
		text, _ := starlark.AsString(name)
		index.entries[i] = entry{strings.ToLower(text), value}
	}
	return index
}

// Named accepts a sequence or dictionary of names and returns an independently
// mutable list, retaining duplicates in different modules and IAT slots.
func (index *Index) Named(args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var names starlark.Iterable
	if err := starlark.UnpackArgs("imports_named", args, kwargs, "names", &names); err != nil {
		return nil, err
	}
	selected := make(map[string]bool)
	iterator := names.Iterate()
	defer iterator.Done()
	var value starlark.Value
	for iterator.Next(&value) {
		name, ok := starlark.AsString(value)
		if !ok {
			return nil, fmt.Errorf("imports_named: names must be strings")
		}
		selected[strings.ToLower(name)] = true
	}
	var out []starlark.Value
	for _, item := range index.entries {
		if selected[item.name] {
			out = append(out, item.value)
		}
	}
	return starlark.NewList(out), nil
}
