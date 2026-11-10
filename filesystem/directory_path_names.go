package filesystem

import (
	"fmt"
	"go.starlark.net/starlark"
	"strings"
)

// pathNamesBuiltin snapshots the namespace without touching file contents.
// Parent spelling follows the first sorted descendant, as file-based image
// importers historically expose it. Empty directories fill remaining entries.
func (d *Directory) pathNamesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	lower := false
	includeEmpty := true
	readonly := false
	if err := starlark.UnpackArgs("path_names", args, kwargs, "lower?", &lower, "include_empty?", &includeEmpty, "readonly?", &readonly); err != nil {
		return nil, err
	}
	slot := 0
	if lower {
		slot |= 1
	}
	if includeEmpty {
		slot |= 2
	}
	if d.pathNames[slot] == nil {
		snapshot, err := d.buildPathNames(lower, includeEmpty)
		if err != nil {
			return nil, err
		}
		snapshot.Freeze()
		d.pathNames[slot] = snapshot
	}
	snapshot := d.pathNames[slot]
	if readonly {
		return snapshot, nil
	}
	result := starlark.NewDict(snapshot.Len())
	iter := snapshot.Iterate()
	defer iter.Done()
	var key starlark.Value
	for iter.Next(&key) {
		value, _, _ := snapshot.Get(key)
		if err := result.SetKey(key, value); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (d *Directory) buildPathIndex(lower, includeEmpty bool) (*pathIndex, error) {
	names := make(map[string]string, len(d.files)+len(d.dirs))
	names["/"] = "/"
	// Track the lexically first full descendant for each implied ancestor.
	// This preserves sorted-file precedence without sorting the file set.
	first := make(map[string]string, len(d.dirs))
	for file := range d.files {
		name, key := file, file
		if lower {
			key = strings.ToLower(key)
		}
		if previous, found := names[key]; found && previous != file {
			if _, realFile := d.files[previous]; realFile {
				left, right := previous, file
				if left > right {
					left, right = right, left
				}
				return nil, fmt.Errorf("path_names: ambiguous lowercase files %q and %q", left, right)
			}
		}
		names[key] = file
		delete(first, key)
		for {
			end := strings.LastIndexByte(name, '/')
			if end <= 0 {
				break
			}
			name = name[:end]
			key = key[:strings.LastIndexByte(key, '/')]
			if previous, found := names[key]; found {
				if _, realFile := d.files[previous]; realFile {
					continue
				}
				if first[key] <= file {
					break
				}
			}
			names[key], first[key] = name, file
		}
	}
	if includeEmpty {
		for name := range d.dirs {
			key := name
			if lower {
				key = strings.ToLower(key)
			}
			previous, found := names[key]
			if !found {
				names[key] = name
				continue
			}
			if _, implied := first[key]; implied {
				continue
			}
			if _, file := d.files[previous]; file {
				continue
			}
			if name < previous {
				names[key] = name
			}
		}
	}
	return &pathIndex{names: names}, nil
}

func (d *Directory) buildPathNames(lower, includeEmpty bool) (*starlark.Dict, error) {
	index, err := d.pathIndex(lower, includeEmpty)
	if err != nil {
		return nil, err
	}
	result := starlark.NewDict(index.Len())
	for _, key := range index.sortedKeys() {
		if err := result.SetKey(starlark.String(key), starlark.String(index.names[key])); err != nil {
			return nil, err
		}
	}
	return result, nil
}
