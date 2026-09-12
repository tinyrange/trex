package rms

import (
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func VariableBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	var attrs starlark.Bytes
	maximum := 1000000
	if err := starlark.UnpackArgs("rms_variable", args, kwargs, "file", &value, "attributes", &attrs, "maximum_records?", &maximum); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("rms: expected file")
	}
	records, err := VariableRecords(file, []byte(attrs), maximum)
	if err != nil {
		return nil, err
	}
	values := make([]starlark.Value, 0, len(records))
	for _, r := range records {
		values = append(values, starfile.NewRecord(starlark.StringDict{
			"offset":  starlark.MakeInt64(r.Offset),
			"control": &starfile.Slice{Name: "RMS control", Base: file, Offset: r.Offset + 2, Length: r.Control.Size()},
			"data":    &starfile.Slice{Name: "RMS record", Base: file, Offset: r.Offset + 2 + r.Control.Size(), Length: r.Data.Size()},
		}))
	}
	return starfile.NewRecord(starlark.StringDict{"records": starlark.NewList(values)}), nil
}
