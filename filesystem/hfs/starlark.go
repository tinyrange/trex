package hfs

import (
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximum := 1000000
	if err := starlark.UnpackArgs("hfs", args, kwargs, "file", &value, "maximum_entries?", &maximum); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("hfs: expected file")
	}
	volume, err := Open(file, maximum)
	if err != nil {
		return nil, err
	}
	entries := make([]starlark.Value, len(volume.Entries))
	paths := make([]starlark.Value, len(entries))
	index := map[string]starlark.Value{}
	for i, e := range volume.Entries {
		var data, resource starlark.Value = starlark.None, starlark.None
		var size, resourceSize int64
		if e.Data != nil {
			data = e.Data
			size = e.Data.Size()
		}
		if e.Resource != nil {
			resource = e.Resource
			resourceSize = e.Resource.Size()
		}
		record := starfile.NewRecord(starlark.StringDict{"path": starlark.String(e.Path), "name": starlark.Bytes(e.Name), "entry_type": starlark.String(e.Kind), "id": starlark.MakeUint(uint(e.ID)), "parent_id": starlark.MakeUint(uint(e.Parent)), "created": starlark.MakeUint(uint(e.Created)), "modified": starlark.MakeUint(uint(e.Modified)), "backup": starlark.MakeUint(uint(e.Backup)), "flags": starlark.MakeUint(uint(e.Flags)), "finder_info": starlark.Bytes(e.FinderInfo), "data": data, "resource": resource, "size": starlark.MakeInt64(size), "resource_size": starlark.MakeInt64(resourceSize)})
		entries[i] = record
		paths[i] = starlark.String(e.Path)
		index[e.Path] = record
	}
	find := starlark.NewBuiltin("hfs.find", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var name string
		if err := starlark.UnpackArgs("find", args, kwargs, "path", &name); err != nil {
			return nil, err
		}
		if entry := index[name]; entry != nil {
			return entry, nil
		}
		return starlark.None, nil
	})
	return starfile.NewRecord(starlark.StringDict{"name": starlark.Bytes(volume.Name), "entries": starlark.NewList(entries), "files": starlark.NewList(paths), "find": find}), nil
}
