package windows

import (
	"fmt"
	"go.starlark.net/starlark"
)

// Copy the two mutable dictionary layers, retaining lazy sources and other
// payloads exactly as a Starlark {path: dict(entry)} comprehension does.
func cloneFileEntriesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var entries *starlark.Dict
	if err := starlark.UnpackArgs("clone_file_entries", args, kwargs, "entries", &entries); err != nil {
		return nil, err
	}
	result := starlark.NewDict(entries.Len())
	for path, value := range entries.Entries() {
		entry, ok := value.(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("clone_file_entries: entries must be dictionaries")
		}
		copy, err := copyEntryFields(entry)
		if err != nil {
			return nil, err
		}
		if err := result.SetKey(path, copy); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func copyEntryFields(entry *starlark.Dict) (*starlark.Dict, error) {
	result := starlark.NewDict(entry.Len())
	for key, value := range entry.Entries() {
		if err := result.SetKey(key, value); err != nil {
			return nil, err
		}
	}
	return result, nil
}
