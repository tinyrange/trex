package bsddump

import (
	"fmt"

	"github.com/tinyrange/trex/filesystem/ufs"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximum := 1000000
	var bytes int64 = 256 << 20
	if err := starlark.UnpackArgs("bsd_dump", args, kwargs, "file", &value, "maximum_entries?", &maximum, "maximum_decoded_bytes?", &bytes); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("bsd_dump: expected file")
	}
	a, err := Open(file, maximum, bytes)
	if err != nil {
		return nil, err
	}
	return ufs.EntryRecord(a.Entries, starlark.StringDict{"date": starlark.MakeUint(uint(a.Date)), "allocated_map": a.AllocatedMap, "dumped_map": a.DumpedMap}), nil
}
