package ibmisave

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
)

func init() {
	auto.Register("ibmi_optical_transport", 29, func(p []byte, r storage.Reader, o auto.Options) (auto.View, error) {
		if len(p) <= pageSize || !bytes.Equal(p[0x96:0xae], descriptor) {
			return nil, auto.ErrNoMatch
		}
		// Establish compressed framing before claiming the source. Isolated
		// descriptors and ordinary plain streams belong to the save detector.
		found := false
		var head [pageSize]byte
		for off, steps := int64(0), 0; off < r.Size() && steps < o.MaxEntries; steps++ {
			if r.Size()-off < 14 {
				break
			}
			if _, err := starfile.ReadFullAt(r, head[:14], off); err != nil {
				return nil, err
			}
			if bytes.Equal(head[:8], terseTag) {
				found = true
				break
			}
			if head[0] == 0x40 {
				off += pageSize
				continue
			}
			if binary.BigEndian.Uint32(head[:]) != 0xffffffff || r.Size()-off < pageSize {
				break
			}
			if _, err := starfile.ReadFullAt(r, head[:], off); err != nil {
				return nil, err
			}
			n := int64(binary.BigEndian.Uint32(head[0xcc:])) * 512
			if n < pageSize || n%pageSize != 0 || n > r.Size()-off {
				break
			}
			off += n
		}
		if !found {
			return nil, auto.ErrNoMatch
		}
		t, err := OpenOpticalTransport(r, o.MaxEntries, o.MaxExpandedBytes)
		if err != nil {
			return nil, err
		}
		if t.CompressedRecords == 0 {
			return nil, auto.ErrNoMatch
		}
		meta, err := json.MarshalIndent(t, "", "  ")
		if err != nil {
			return nil, err
		}
		entries := []auto.Entry{{Name: "logical-prefix.bin", Kind: "file", Reader: t.Data, Attributes: map[string]any{"offset_domain": "expanded logical stream", "complete_transport": t.Complete}}, {Name: "transport.json", Kind: "file", Reader: &starfile.Bytes{Data: meta}}}
		if t.UnknownTail != nil {
			entries = append(entries, auto.Entry{Name: "opaque-tail.bin", Kind: "file", Reader: t.UnknownTail, Attributes: map[string]any{"format": "LD_LZ1", "interpretation": "unknown; retained byte-for-byte"}})
		}
		tree, err := auto.Tree(entries, o)
		if err != nil {
			return nil, err
		}
		return &auto.DescribedView{View: tree, Format: "ibmi_optical_transport", Attributes: map[string]any{"compressed_records": t.CompressedRecords, "complete": t.Complete, "logical_bytes": t.LogicalBytes}}, nil
	})
}
