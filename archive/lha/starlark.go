package lha

import (
	"fmt"
	"path"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximum := 1000000
	var bytes int64 = 256 << 20
	if err := starlark.UnpackArgs("lha", args, kwargs, "file", &value, "maximum_entries?", &maximum, "maximum_decoded_bytes?", &bytes); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("lha: expected file")
	}
	a, err := Open(file, maximum, bytes)
	if err != nil {
		return nil, err
	}
	entries := make([]starlark.Value, len(a.Entries))
	paths := make([]starlark.Value, len(entries))
	index := map[string]starlark.Value{}
	for i, e := range a.Entries {
		r := starfile.NewRecord(starlark.StringDict{"path": starlark.String(e.Path), "name": starlark.Bytes(e.Name), "header": starlark.Bytes(e.Header), "entry_type": starlark.String("file"), "method": starlark.String(e.Method), "timestamp": starlark.MakeUint(uint(e.Timestamp)), "attributes": starlark.MakeUint(uint(e.Attributes)), "crc": starlark.MakeUint(uint(e.CRC)), "size": starlark.MakeInt64(e.Data.Size()), "data": e.Data, "stored": e.Stored})
		entries[i] = r
		paths[i] = starlark.String(e.Path)
		index[e.Path] = r
	}
	find := starlark.NewBuiltin("lha.find", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var name string
		if err := starlark.UnpackArgs("find", args, kwargs, "path", &name); err != nil {
			return nil, err
		}
		if v := index[path.Clean("/"+name)]; v != nil {
			return v, nil
		}
		return starlark.None, nil
	})
	return starfile.NewRecord(starlark.StringDict{"entries": starlark.NewList(entries), "files": starlark.NewList(paths), "find": find}), nil
}
