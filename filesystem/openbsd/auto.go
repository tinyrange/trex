package openbsd

import (
	"encoding/binary"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/filesystem/ufs"
	"github.com/tinyrange/trex/storage"
)

func init() {
	auto.Register("openbsd_label", 20, func(prefix []byte, source storage.Reader, options auto.Options) (auto.View, error) {
		const offset = 512
		if len(prefix) < offset+4 || (binary.LittleEndian.Uint32(prefix[offset:]) != magic && binary.BigEndian.Uint32(prefix[offset:]) != magic) {
			return nil, auto.ErrNoMatch
		}
		label, err := readLabel(source, offset)
		if err != nil {
			return nil, err
		}
		isUFS := len(prefix) >= 9568 && (binary.LittleEndian.Uint32(prefix[9564:]) == 0x11954 || binary.BigEndian.Uint32(prefix[9564:]) == 0x11954)
		// An MBR partition/standalone volume may still contain the whole disk's
		// absolute label. It is not that disk; let the UFS detector open it.
		if isUFS && label.Sectors > uint64(source.Size())/uint64(label.SectorSize) {
			return nil, auto.ErrNoMatch
		}
		label, err = Open(source, offset)
		if err != nil {
			return nil, err
		}
		entries := make([]auto.Entry, len(label.Partitions))
		for i, p := range label.Partitions {
			e := auto.Entry{Name: p.Name, Kind: "file", Reader: p.Data, Attributes: map[string]any{
				"start_sector": p.Start, "sectors": p.Sectors, "type": p.Type, "sector_size": label.SectorSize,
				"block_size": p.BlockSize, "fragment_size": p.FragmentSize,
			}}
			if p.Data != nil && p.Start == 0 {
				if p.Type == 7 && isUFS && i != 2 {
					e.View, err = ufs.AutoView(p.Data, options)
					if err != nil {
						return nil, err
					}
				} else {
					// In particular, the raw c slot covers this label. Preserve its
					// bytes without recursively presenting another copy of the disk.
					e.View = auto.ViewFunc(func() ([]auto.Entry, error) { return nil, nil })
					e.Attributes["contains_label"] = true
				}
			}
			entries[i] = e
		}
		return &auto.DescribedView{View: auto.ViewFunc(func() ([]auto.Entry, error) { return entries, nil }), Format: "openbsd_label",
			Attributes: map[string]any{"sector_size": label.SectorSize, "total_sectors": label.Sectors, "partitions": len(entries)}}, nil
	})
}
