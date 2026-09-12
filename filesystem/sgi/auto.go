package sgi

import (
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
)

func init() {
	auto.Register("sgi", 20, func(p []byte, r storage.Reader, o auto.Options) (auto.View, error) {
		if len(p) < 4 || binary.BigEndian.Uint32(p) != 0x0be5a941 {
			return nil, auto.ErrNoMatch
		}
		h, err := Open(adapter.File(r))
		if err != nil {
			return nil, err
		}
		var boot, entries []auto.Entry
		for _, f := range h.Files {
			boot = append(boot, auto.Entry{Name: f.Name, Kind: "file", Reader: f.Data})
		}
		bootView, err := auto.Tree(boot, o)
		if err != nil {
			return nil, err
		}
		entries = append(entries, auto.Entry{Name: "boot", Kind: "directory", View: bootView})
		for _, part := range h.Partitions {
			e := auto.Entry{Name: fmt.Sprintf("partition-%d", part.Index), Kind: "file", Reader: part.Data,
				Attributes: map[string]any{"partition_type": part.Type, "start_block": part.Start, "blocks": part.Blocks, "complete": part.Complete}}
			// The volume header and whole-volume slots contain this same header.
			// Retain their raw bytes but supply the known boot-directory context.
			if part.Start == 0 {
				e.View = bootView
			}
			entries = append(entries, e)
		}
		return auto.ViewFunc(func() ([]auto.Entry, error) { return entries, nil }), nil
	})
}
