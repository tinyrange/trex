package filesystem

import (
	"fmt"
	"go.starlark.net/starlark"
	"sort"
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

func (d *Directory) buildPathNames(lower, includeEmpty bool) (*starlark.Dict, error) {
	names := make(map[string]string, len(d.files)+len(d.dirs))
	names["/"] = "/"
	files := d.sortedFileNames()
	fileKeys := make(map[string]string, len(files))
	for _, name := range files {
		key := name
		if lower {
			key = strings.ToLower(key)
		}
		if previous, found := fileKeys[key]; found && previous != name {
			return nil, fmt.Errorf("path_names: ambiguous lowercase files %q and %q", previous, name)
		}
		fileKeys[key] = name
		names[key] = name
		for {
			end := strings.LastIndexByte(name, '/')
			if end <= 0 {
				break
			}
			name = name[:end]
			key = key[:strings.LastIndexByte(key, '/')]
			if _, found := names[key]; found {
				break
			}
			names[key] = name
		}
	}
	dirs := make([]string, 0, len(d.dirs))
	if includeEmpty {
		for name := range d.dirs {
			dirs = append(dirs, name)
		}
	}
	sort.Strings(dirs)
	for _, name := range dirs {
		key := name
		if lower {
			key = strings.ToLower(key)
		}
		if _, found := names[key]; !found {
			names[key] = name
		}
	}
	keys := make([]string, 0, len(names))
	for key := range names {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := starlark.NewDict(len(names))
	for _, key := range keys {
		if err := result.SetKey(starlark.String(key), starlark.String(names[key])); err != nil {
			return nil, err
		}
	}
	return result, nil
}
