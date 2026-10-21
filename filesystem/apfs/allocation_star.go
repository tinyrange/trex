package apfs

import (
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func allocationBuiltin(c *Container) *starlark.Builtin {
	return starlark.NewBuiltin("apfs.allocation", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		if err := starlark.UnpackArgs("allocation", args, kwargs); err != nil {
			return nil, err
		}
		a, err := c.Allocation()
		if err != nil {
			return nil, err
		}
		record := func(values map[string]uint64) starlark.Value {
			d := starlark.StringDict{}
			for k, v := range values {
				d[k] = starlark.MakeUint64(v)
			}
			return starfile.NewRecord(d)
		}
		span := func(r BlockRange) starlark.Value {
			return record(map[string]uint64{"start": r.Start, "count": r.Count})
		}
		mappings := make([]starlark.Value, 0, len(a.Mappings))
		for _, m := range a.Mappings {
			mappings = append(mappings, record(map[string]uint64{"type": uint64(m.Type), "subtype": uint64(m.Subtype), "size": uint64(m.Size), "filesystem": m.Filesystem, "id": m.ID, "address": m.Address}))
		}
		chunks := make([]starlark.Value, 0, len(a.Chunks))
		for _, ch := range a.Chunks {
			chunks = append(chunks, record(map[string]uint64{"transaction": ch.Transaction, "start": ch.Start, "count": ch.Count, "free": ch.Free, "bitmap_address": ch.BitmapAddress, "cib_address": ch.CIBAddress}))
		}
		ranges := make([]starlark.Value, 0, len(a.Free))
		for _, r := range a.Free {
			ranges = append(ranges, span(r))
		}
		return starfile.NewRecord(starlark.StringDict{
			"transaction": starlark.MakeUint64(a.Transaction), "superblock": starlark.MakeUint64(a.Superblock), "space_manager": starlark.MakeUint64(a.SpaceManager),
			"next_id": starlark.MakeUint64(a.NextID), "next_transaction": starlark.MakeUint64(a.NextTransaction), "free_blocks": starlark.MakeUint64(a.FreeBlocks),
			"descriptor_area": span(a.DescriptorArea), "data_area": span(a.DataArea), "internal_pool": span(a.InternalPool), "internal_pool_bitmaps": span(a.InternalPoolBitmaps),
			"descriptor_index": starlark.MakeUint64(uint64(a.DescriptorIndex)), "descriptor_length": starlark.MakeUint64(uint64(a.DescriptorLength)), "data_index": starlark.MakeUint64(uint64(a.DataIndex)), "data_length": starlark.MakeUint64(uint64(a.DataLength)),
			"blocks_per_chunk": starlark.MakeUint64(uint64(a.BlocksPerChunk)), "chunks_per_cib": starlark.MakeUint64(uint64(a.ChunksPerCIB)), "cibs_per_cab": starlark.MakeUint64(uint64(a.CIBsPerCAB)),
			"mappings": starlark.NewList(mappings), "chunks": starlark.NewList(chunks), "free_ranges": starlark.NewList(ranges),
		}), nil
	})
}
