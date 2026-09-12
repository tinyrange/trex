package xfs

import (
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"path"
)

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximum := 1000000
	if err := starlark.UnpackArgs("xfs", args, kwargs, "file", &value, "maximum_entries?", &maximum); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("xfs: expected file")
	}
	volume, err := Open(file, maximum)
	if err != nil {
		return nil, err
	}
	entries := make([]starlark.Value, 0, len(volume.Entries))
	paths := make([]starlark.Value, 0, len(volume.Entries))
	index := map[string]starlark.Value{}
	for _, e := range volume.Entries {
		var data starlark.Value = starlark.None
		var size int64
		if e.Data != nil {
			data = e.Data
			size = e.Data.Size()
		}
		record := starfile.NewRecord(starlark.StringDict{"path": starlark.String(e.Path), "entry_type": starlark.String(e.Kind), "inode": starlark.MakeUint64(e.Inode), "mode": starlark.MakeUint(uint(e.Mode)), "uid": starlark.MakeUint(uint(e.UID)), "gid": starlark.MakeUint(uint(e.GID)), "modified": starlark.MakeUint(uint(e.Modified)), "size": starlark.MakeInt64(size), "data": data})
		entries = append(entries, record)
		paths = append(paths, starlark.String(e.Path))
		index[e.Path] = record
	}
	find := starlark.NewBuiltin("xfs.find", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var name string
		if err := starlark.UnpackArgs("find", args, kwargs, "path", &name); err != nil {
			return nil, err
		}
		if entry := index[path.Clean("/"+name)]; entry != nil {
			return entry, nil
		}
		return starlark.None, nil
	})
	return starfile.NewRecord(starlark.StringDict{"entries": starlark.NewList(entries), "files": starlark.NewList(paths), "find": find}), nil
}
