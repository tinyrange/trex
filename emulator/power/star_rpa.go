package power

import (
	"bytes"
	"github.com/tinyrange/trex/binary/rpa"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func (v *machineValue) rpaBlockListBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var address uint64
	maximum := uint64(16 << 20)
	if err := starlark.UnpackArgs("rpa_block_list", args, kwargs, "address", &address, "maximum_capacity?", &maximum); err != nil {
		return nil, err
	}
	list, err := rpa.ReadBlockList(bytes.NewReader(v.m.Mem), address, maximum)
	if err != nil {
		return nil, err
	}
	entries := make([]starlark.Value, len(list.Entries))
	for i, e := range list.Entries {
		entries[i] = starfile.NewRecord(starlark.StringDict{"address": starlark.MakeUint64(e.Address), "real": starlark.MakeUint64(e.Real), "size": starlark.MakeUint64(e.Size)})
	}
	return starfile.NewRecord(starlark.StringDict{"capacity": starlark.MakeUint64(list.Capacity), "entries": starlark.NewList(entries)}), nil
}
