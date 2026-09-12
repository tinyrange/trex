package apm

import (
	"fmt"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
)

func init() {
	auto.Register("apm", 20, func(p []byte, r storage.Reader, o auto.Options) (auto.View, error) {
		if len(p) < 2 || string(p[:2]) != "ER" {
			return nil, auto.ErrNoMatch
		}
		var maps []auto.Entry
		for _, blockSize := range []int{512, 1024, 2048} {
			// A later record in a smaller-block map also starts with PM.
			// Only the partition-map descriptor confirms a new geometry.
			if len(p) < blockSize+80 || string(p[blockSize:blockSize+2]) != "PM" || string(cstring(p[blockSize+48:blockSize+80])) != "Apple_partition_map" {
				continue
			}
			m, err := Open(adapter.File(r), blockSize, o.MaxEntries)
			if err != nil {
				return nil, err
			}
			var entries []auto.Entry
			for _, part := range m.Partitions {
				entries = append(entries, auto.Entry{Name: fmt.Sprintf("partition-%d", part.Index), Kind: "file", Reader: part.Data,
					Attributes: map[string]any{"name": part.Name, "partition_type": part.Type, "block_size": part.BlockSize, "start_block": part.Start, "blocks": part.Blocks, "complete": part.Data != nil}})
			}
			view := auto.ViewFunc(func() ([]auto.Entry, error) { return entries, nil })
			maps = append(maps, auto.Entry{Name: fmt.Sprintf("blocks-%d", blockSize), Kind: "directory", View: view})
		}
		if len(maps) == 0 {
			return nil, auto.ErrNoMatch
		}
		return auto.ViewFunc(func() ([]auto.Entry, error) { return maps, nil }), nil
	})
}
