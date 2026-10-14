package mtree

import (
	"fmt"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximum := 100000
	if err := starlark.UnpackArgs("mtree", args, kwargs, "file", &value, "maximum_entries?", &maximum); err != nil {
		return nil, err
	}
	source, ok := value.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("mtree: expected file")
	}
	entries, err := Read(source, maximum)
	if err != nil {
		return nil, err
	}
	out := make([]starlark.Value, len(entries))
	for i, e := range entries {
		attrs := starlark.NewDict(len(e.Attributes))
		for k, v := range e.Attributes {
			if err := attrs.SetKey(starlark.String(k), starlark.String(v)); err != nil {
				return nil, err
			}
		}
		out[i] = starfile.NewRecord(starlark.StringDict{"path": starlark.String(e.Path), "attributes": attrs})
	}
	return starlark.NewList(out), nil
}
