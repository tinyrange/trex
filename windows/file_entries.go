package windows

import (
	"fmt"
	"go.starlark.net/starlark"
)

// Copy the namespace, object and EA metadata layers, retaining lazy sources and other
// payloads. Names that share an entry (hard links) must share one new entry in
// the clone, without sharing that mutable entry with the source namespace.
func cloneFileEntriesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var entries *starlark.Dict
	if err := starlark.UnpackArgs("clone_file_entries", args, kwargs, "entries", &entries); err != nil {
		return nil, err
	}
	result := starlark.NewDict(entries.Len())
	objects := make(map[*starlark.Dict]*starlark.Dict)
	for path, value := range entries.Entries() {
		entry, ok := value.(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("clone_file_entries: entries must be dictionaries")
		}
		copy := objects[entry]
		if copy == nil {
			var err error
			copy, err = copyEntryFields(entry)
			if err != nil {
				return nil, err
			}
			objects[entry] = copy
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
		if key == starlark.String("extended_attributes") {
			list, ok := value.(*starlark.List)
			if !ok {
				return nil, fmt.Errorf("clone_file_entries: extended_attributes must be a list")
			}
			copied := make([]starlark.Value, 0, list.Len())
			for i := 0; i < list.Len(); i++ {
				ea, ok := list.Index(i).(*starlark.Dict)
				if !ok {
					return nil, fmt.Errorf("clone_file_entries: EA must be a dictionary")
				}
				clone := starlark.NewDict(ea.Len())
				for k, v := range ea.Entries() {
					switch v.(type) {
					case starlark.String, starlark.Int, starlark.Bytes:
					default:
						return nil, fmt.Errorf("clone_file_entries: EA fields must be immutable")
					}
					if err := clone.SetKey(k, v); err != nil {
						return nil, err
					}
				}
				copied = append(copied, clone)
			}
			value = starlark.NewList(copied)
		}
		if err := result.SetKey(key, value); err != nil {
			return nil, err
		}
	}
	return result, nil
}
