package os2

import (
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// ProfileBuiltin accepts [(application, key, bytes), ...].
func ProfileBuiltin(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var values *starlark.List
	if e := starlark.UnpackArgs(fn.Name(), args, kwargs, "entries", &values); e != nil {
		return nil, e
	}
	var entries []Entry
	for i := 0; i < values.Len(); i++ {
		row, ok := values.Index(i).(starlark.Tuple)
		if !ok || len(row) != 3 {
			return nil, fmt.Errorf("profile entry must be an application/key/bytes tuple")
		}
		app, a := starlark.AsString(row[0])
		key, k := starlark.AsString(row[1])
		data, d := row[2].(starlark.Bytes)
		if !a || !k || !d {
			return nil, fmt.Errorf("profile entry requires string, string, bytes")
		}
		entries = append(entries, Entry{app, key, []byte(data)})
	}
	b, e := Profile(entries)
	if e != nil {
		return nil, e
	}
	return &starfile.Bytes{Data: b}, nil
}
