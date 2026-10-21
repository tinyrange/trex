package applearchive

import (
	"fmt"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximum := 100000
	if err := starlark.UnpackArgs("apple_archive", args, kwargs, "file", &value, "maximum_entries?", &maximum); err != nil {
		return nil, err
	}
	r, ok := value.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("apple_archive: expected file")
	}
	entries, err := Read(r, maximum)
	if err != nil {
		return nil, err
	}
	out := make([]starlark.Value, 0, len(entries))
	for _, e := range entries {
		fields := starlark.NewDict(len(e.Fields))
		for k, v := range e.Fields {
			var val starlark.Value
			switch v := v.(type) {
			case uint64:
				val = starlark.MakeUint64(v)
			case string:
				val = starlark.String(v)
			case Timestamp:
				val = starfile.NewRecord(starlark.StringDict{"seconds": starlark.MakeInt64(v.Seconds), "nanoseconds": starlark.MakeUint64(uint64(v.Nanoseconds))})
			case storage.Reader:
				val = starfile.NewReader(k, v)
			}
			if val != nil {
				fields.SetKey(starlark.String(k), val)
			}
		}
		var data starlark.Value = starlark.None
		if e.Data != nil {
			data = starfile.NewReader(e.Path, e.Data)
		}
		out = append(out, starfile.NewRecord(starlark.StringDict{"path": starlark.String(e.Path), "kind": starlark.String(e.Kind), "fields": fields, "data": data}))
	}
	return starlark.NewList(out), nil
}
