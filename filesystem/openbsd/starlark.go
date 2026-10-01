package openbsd

import (
	"encoding/hex"
	"fmt"

	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	labelOffset := int64(512)
	if err := starlark.UnpackArgs("openbsd_label", args, kwargs, "file", &value, "label_offset?", &labelOffset); err != nil {
		return nil, err
	}
	source, ok := value.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("openbsd label: expected file")
	}
	l, err := Open(source, labelOffset)
	if err != nil {
		return nil, err
	}
	values := make([]starlark.Value, len(l.Partitions))
	for i, p := range l.Partitions {
		var data starlark.Value = starlark.None
		if p.Data != nil {
			data = adapter.File(p.Data)
		}
		values[i] = starfile.NewRecord(starlark.StringDict{
			"index": starlark.MakeInt(p.Index), "name": starlark.String(p.Name),
			"start_sector": starlark.MakeUint64(p.Start), "sectors": starlark.MakeUint64(p.Sectors),
			"type": starlark.MakeUint(uint(p.Type)), "data": data,
			"block_size": starlark.MakeUint(uint(p.BlockSize)), "fragment_size": starlark.MakeUint(uint(p.FragmentSize)),
			"cylinders_per_group": starlark.MakeUint(uint(p.CylindersPerGroup)),
		})
	}
	return starfile.NewRecord(starlark.StringDict{
		"sector_size": starlark.MakeUint(uint(l.SectorSize)), "total_sectors": starlark.MakeUint64(l.Sectors),
		"bound_start": starlark.MakeUint64(l.BoundStart), "bound_end": starlark.MakeUint64(l.BoundEnd),
		"uid":       starlark.String(hex.EncodeToString(l.UID[:])),
		"type_name": starlark.String(l.TypeName), "pack_name": starlark.String(l.PackName),
		"partitions": starlark.NewList(values),
	}), nil
}
