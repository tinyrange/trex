package powerfirmware

import (
	"encoding/binary"
	"fmt"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
)

func init() {
	auto.Register("power_firmware", 30, func(prefix []byte, source storage.Reader, o auto.Options) (auto.View, error) {
		if len(prefix) < 4 || string(prefix[:2]) != "UI" || binary.BigEndian.Uint16(prefix[2:]) != 3 {
			return nil, auto.ErrNoMatch
		}
		image, err := Open(source, o.MaxEntries/2, o.MaxExpandedBytes)
		if err != nil {
			return nil, err
		}
		entries := []auto.Entry{{Name: "header.bin", Kind: "file", Reader: image.Header}, {Name: "directory.bin", Kind: "file", Reader: image.Directory}}
		for _, e := range image.Entries {
			base := fmt.Sprintf("lids/%08x/", e.ID)
			entries = append(entries, auto.Entry{Name: base + "header.bin", Kind: "file", Reader: e.Header}, auto.Entry{Name: base + "payload.bin", Kind: "file", Reader: e.Payload, Attributes: map[string]any{"id": e.ID, "offset": e.Offset, "checksum_word": e.ChecksumWord, "checksum_verified": false}})
			if e.ID == 0x80a00001 {
				// Other marker generations are still available as raw payloads.
				if keyword, err := MIKeyword(e.Payload); err == nil {
					entries = append(entries, auto.Entry{Name: base + "mi_keyword.bin", Kind: "file", Reader: keyword})
				}
			}
		}
		tree, err := auto.Tree(entries, o)
		if err != nil {
			return nil, err
		}
		return &auto.DescribedView{View: tree, Format: "power_firmware", Attributes: map[string]any{"lid_count": len(image.Entries), "checksum_verified": false}}, nil
	})
}
