package msi

import (
	"go.starlark.net/starlark"
	"sort"
)

// These are static planning facts, not executable installation effects. Unknown
// query-dependent properties must not be mistaken for resolved values.
func stringMap(values map[string]string) *starlark.Dict {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := starlark.NewDict(len(keys))
	for _, key := range keys {
		_ = result.SetKey(starlark.String(key), starlark.String(values[key]))
	}
	return result
}
func knownProperties(values map[string]string, unknown map[string]bool) *starlark.Dict {
	known := make(map[string]string, len(values))
	for key, value := range values {
		if !unknown[key] {
			known[key] = value
		}
	}
	return stringMap(known)
}
func selectedNames(values map[string]bool) *starlark.List {
	keys := []string{}
	for key, selected := range values {
		if selected {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	result := make([]starlark.Value, len(keys))
	for i, key := range keys {
		result[i] = starlark.String(key)
	}
	return starlark.NewList(result)
}
