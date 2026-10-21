package androidlp

import (
	"fmt"

	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var file starlark.Value
	var slot uint32
	var devices *starlark.Dict
	if err := starlark.UnpackArgs("android_super", args, kwargs, "file", &file, "slot?", &slot, "devices?", &devices); err != nil {
		return nil, err
	}
	source, ok := file.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("android_super: expected file")
	}
	readers := map[string]storage.Reader{}
	if devices != nil {
		for _, item := range devices.Items() {
			n, ok := starlark.AsString(item[0])
			r, valid := item[1].(storage.Reader)
			if !ok || !valid {
				return nil, fmt.Errorf("android_super: devices must map names to files")
			}
			readers[n] = r
		}
	}
	v, err := Open(source, slot, readers)
	if err != nil {
		return nil, err
	}
	parts := make([]starlark.Value, len(v.Partitions))
	for i, p := range v.Partitions {
		exts := make([]starlark.Value, len(p.Extents))
		for j, e := range p.Extents {
			exts[j] = starfile.NewRecord(starlark.StringDict{
				"sectors": starlark.MakeUint64(e.Sectors), "sector": starlark.MakeUint64(e.Sector),
				"target_type": starlark.MakeUint(uint(e.Type)), "source": starlark.MakeUint(uint(e.Source)),
			})
		}
		parts[i] = starfile.NewRecord(starlark.StringDict{
			"name": starlark.String(p.Name), "attributes": starlark.MakeUint(uint(p.Attributes)),
			"group_index": starlark.MakeUint(uint(p.GroupIndex)), "file": adapter.File(p.Data),
			"size": starlark.MakeInt64(p.Data.Size()), "extents": starlark.NewList(exts),
		})
	}
	groups := make([]starlark.Value, len(v.Groups))
	for i, g := range v.Groups {
		groups[i] = starfile.NewRecord(starlark.StringDict{
			"name": starlark.String(g.Name), "flags": starlark.MakeUint(uint(g.Flags)), "maximum_size": starlark.MakeUint64(g.MaximumSize),
		})
	}
	devs := make([]starlark.Value, len(v.Devices))
	for i, d := range v.Devices {
		devs[i] = starfile.NewRecord(starlark.StringDict{
			"name": starlark.String(d.Name), "flags": starlark.MakeUint(uint(d.Flags)), "size": starlark.MakeUint64(d.Size),
			"first_sector": starlark.MakeUint64(d.FirstSector), "alignment": starlark.MakeUint(uint(d.Alignment)),
			"alignment_offset": starlark.MakeUint(uint(d.AlignmentOffset)),
		})
	}
	return starfile.NewRecord(starlark.StringDict{
		"major_version": starlark.MakeUint(uint(v.Major)), "minor_version": starlark.MakeUint(uint(v.Minor)),
		"slot": starlark.MakeUint(uint(v.Slot)), "slot_count": starlark.MakeUint(uint(v.Geometry.SlotCount)),
		"metadata_max_size": starlark.MakeUint(uint(v.Geometry.MetadataMaxSize)), "block_size": starlark.MakeUint(uint(v.Geometry.BlockSize)),
		"flags": starlark.MakeUint(uint(v.Flags)), "backup_geometry": starlark.Bool(v.BackupGeometry), "backup_metadata": starlark.Bool(v.BackupMetadata),
		"partitions": starlark.NewList(parts), "groups": starlark.NewList(groups), "devices": starlark.NewList(devs),
	}), nil
}
