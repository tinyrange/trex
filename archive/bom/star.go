package bom

import (
	"fmt"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximum := 1000000
	if err := starlark.UnpackArgs("bom", args, kwargs, "file", &value, "maximum_entries?", &maximum); err != nil {
		return nil, err
	}
	source, ok := value.(storage.Reader)
	if !ok || maximum <= 0 {
		return nil, fmt.Errorf("bom: expected file and positive maximum_entries")
	}
	entries, err := Read(source, maximum)
	if err != nil {
		return nil, err
	}
	result := make([]starlark.Value, len(entries))
	for i, e := range entries {
		record := starlark.StringDict{"path": starlark.String(e.Name), "kind": starlark.String(e.Kind)}
		for k, v := range e.Attributes {
			switch v := v.(type) {
			case uint32:
				record[k] = starlark.MakeUint64(uint64(v))
			case uint16:
				record[k] = starlark.MakeUint64(uint64(v))
			case string:
				record[k] = starlark.String(v)
			case bool:
				record[k] = starlark.Bool(v)
			}
		}
		result[i] = starfile.NewRecord(record)
	}
	return starlark.NewList(result), nil
}
