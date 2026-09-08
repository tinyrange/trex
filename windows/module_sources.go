package windows

import (
	"fmt"
	"strings"

	"go.starlark.net/starlark"
)

func sourceModuleName(path string) string {
	if i := strings.LastIndexAny(path, "/\\"); i >= 0 {
		path = path[i+1:]
	}
	name := strings.ToLower(path)
	if !strings.Contains(name, ".") {
		name += ".dll"
	}
	return name
}

// Index names only: source values are retained without reading or parsing them.
func moduleSourcesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var files *starlark.Dict
	var exclude starlark.Iterable = starlark.Tuple{}
	if err := starlark.UnpackArgs("module_sources", args, kwargs, "files", &files, "exclude?", &exclude); err != nil {
		return nil, err
	}
	excluded := make(map[string]bool)
	iterator := exclude.Iterate()
	var value starlark.Value
	for iterator.Next(&value) {
		name, ok := starlark.AsString(value)
		if !ok {
			iterator.Done()
			return nil, fmt.Errorf("module_sources: excluded names must be strings")
		}
		excluded[sourceModuleName(name)] = true
	}
	iterator.Done()
	out := starlark.NewDict(0)
	seen := make(map[string]bool)
	for value, source := range files.Entries() {
		path, ok := starlark.AsString(value)
		if !ok {
			return nil, fmt.Errorf("module_sources: paths must be strings")
		}
		name := sourceModuleName(path)
		if !strings.HasSuffix(name, ".dll") || excluded[name] || seen[name] {
			continue
		}
		if err := out.SetKey(starlark.String(name), source); err != nil {
			return nil, err
		}
		seen[name] = true
	}
	return out, nil
}
