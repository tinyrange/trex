package berkeleydb

import (
	"fmt"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximum := 1000000
	if err := starlark.UnpackArgs("berkeley_db", args, kwargs, "file", &value, "maximum_entries?", &maximum); err != nil {
		return nil, err
	}
	r, ok := value.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("berkeley_db: expected file")
	}
	f, err := Open(r, maximum)
	if err != nil {
		return nil, err
	}
	entries := make([]starlark.Value, 0, len(f.Entries))
	for _, e := range f.Entries {
		entries = append(entries, starfile.NewRecord(starlark.StringDict{"key": starfile.NewReader("key", e.Key), "value": starfile.NewReader("value", e.Value)}))
	}
	return starfile.NewRecord(starlark.StringDict{"page_size": starlark.MakeUint64(uint64(f.PageSize)), "little_endian": starlark.Bool(f.LittleEndian), "entries": starlark.NewList(entries)}), nil
}
