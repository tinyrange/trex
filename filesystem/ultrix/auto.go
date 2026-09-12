package ultrix

import (
	"encoding/binary"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/filesystem/ufs"
	"github.com/tinyrange/trex/storage"
	"go.starlark.net/starlark"
)

func init() {
	auto.Register("ultrix_label", 20, func(p []byte, r storage.Reader, o auto.Options) (auto.View, error) {
		const offset = 31*512 + 440
		if len(p) < offset+4 || (binary.BigEndian.Uint32(p[offset:]) != 0x32957 && binary.LittleEndian.Uint32(p[offset:]) != 0x32957) {
			return nil, auto.ErrNoMatch
		}
		isUFS := len(p) >= 9568 && (binary.BigEndian.Uint32(p[9564:]) == 0x11954 || binary.LittleEndian.Uint32(p[9564:]) == 0x11954)
		// A standalone UFS partition can retain its parent disk's label in
		// the boot area. Geometry outside this source cannot identify it as
		// that complete disk; let the independent UFS parser validate it.
		if isUFS && len(p) >= offset+72 {
			var order binary.ByteOrder = binary.LittleEndian
			if order.Uint32(p[offset:]) != 0x32957 {
				order = binary.BigEndian
			}
			for i := 0; i < 8; i++ {
				blocks, start := int64(order.Uint32(p[offset+8+i*8:])), int64(order.Uint32(p[offset+12+i*8:]))
				if blocks > 0 && (start*512 > r.Size() || blocks*512 > r.Size()-start*512) {
					return nil, auto.ErrNoMatch
				}
			}
		}
		parts, err := Open(adapter.File(r))
		if err != nil {
			return nil, err
		}
		var entries []auto.Entry
		for _, part := range parts {
			e := auto.Entry{Name: string(rune('a' + part.Index)), Kind: "file", Attributes: map[string]any{"start_block": part.Start, "blocks": part.Blocks}}
			if part.Data != nil {
				e.Reader = part.Data
			}
			if part.Start == 0 && part.Data != nil {
				// A root filesystem includes the label itself. Parse its filesystem
				// directly instead of repeatedly treating it as another disk.
				if isUFS {
					e.View, err = adapter.Parse(ufs.Builtin, part.Data, o, starlark.Tuple{starlark.String("maximum_entries"), starlark.MakeInt(o.MaxEntries)}, starlark.Tuple{starlark.String("maximum_blocks"), starlark.MakeInt(o.MaxEntries)})
					if err != nil {
						return nil, err
					}
				} else {
					e.View = auto.ViewFunc(func() ([]auto.Entry, error) { return nil, nil })
					e.Attributes["contains_label"] = true
				}
			}
			entries = append(entries, e)
		}
		return auto.ViewFunc(func() ([]auto.Entry, error) { return entries, nil }), nil
	})
}
