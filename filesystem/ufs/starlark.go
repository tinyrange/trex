package ufs

import (
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"path"
)

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximum, blocks := 1000000, 1000000
	if err := starlark.UnpackArgs("ufs", args, kwargs, "file", &value, "maximum_entries?", &maximum, "maximum_blocks?", &blocks); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("ufs: expected file")
	}
	volume, err := Open(file, maximum, blocks)
	if err != nil {
		return nil, err
	}
	return EntryRecord(volume.Entries, starlark.StringDict{"block_size": starlark.MakeUint(uint(volume.BlockSize)), "fragment_size": starlark.MakeUint(uint(volume.FragmentSize)), "groups": starlark.MakeUint(uint(volume.Groups))}), nil
}

// EntryRecord exposes the common historical inode tree for UFS and BSD dumps.
func EntryRecord(source []Entry, fields starlark.StringDict) starlark.Value {
	entries := make([]starlark.Value, len(source))
	paths := make([]starlark.Value, len(entries))
	index := map[string]starlark.Value{}
	for i, e := range source {
		record := starfile.NewRecord(starlark.StringDict{
			"path": starlark.String(e.Path), "entry_type": starlark.String(e.Kind),
			"inode": starlark.MakeUint(uint(e.Inode)), "mode": starlark.MakeUint(uint(e.Mode)),
			"links": starlark.MakeUint(uint(e.Links)), "uid": starlark.MakeUint(uint(e.UID)), "gid": starlark.MakeUint(uint(e.GID)),
			"accessed": starlark.MakeUint(uint(e.Accessed)), "modified": starlark.MakeUint(uint(e.Modified)), "changed": starlark.MakeUint(uint(e.Changed)),
			"flags": starlark.MakeUint(uint(e.Flags)), "device": starlark.MakeUint(uint(e.Device)),
			"size": starlark.MakeInt64(e.Data.Size()), "data": e.Data,
		})
		entries[i] = record
		paths[i] = starlark.String(e.Path)
		index[e.Path] = record
	}
	find := starlark.NewBuiltin("ufs.find", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var name string
		if err := starlark.UnpackArgs("find", args, kwargs, "path", &name); err != nil {
			return nil, err
		}
		value := index[path.Clean("/"+name)]
		if value == nil {
			return starlark.None, nil
		}
		return value, nil
	})
	fields["entries"] = starlark.NewList(entries)
	fields["files"] = starlark.NewList(paths)
	fields["find"] = find
	return starfile.NewRecord(fields)
}
