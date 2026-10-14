package ibmiimd

import (
	"encoding/binary"
	"encoding/json"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
)

func init() {
	auto.Register("ibmi_packed", 31, func(prefix []byte, source storage.Reader, o auto.Options) (auto.View, error) {
		if len(prefix) < 20 || binary.BigEndian.Uint32(prefix[12:]) != 0 || binary.BigEndian.Uint32(prefix[16:]) != 0x03000080 {
			return nil, auto.ErrNoMatch
		}
		p, err := OpenPacked(source, o.MaxEntries, o.MaxExpandedBytes)
		if err != nil {
			return nil, err
		}
		metadata, err := json.MarshalIndent(p, "", "  ")
		if err != nil {
			return nil, err
		}
		tree, err := auto.Tree([]auto.Entry{{Name: "expanded.bin", Kind: "file", Reader: p.Data}, {Name: "metadata.json", Kind: "file", Reader: &starfile.Bytes{Data: metadata}}, {Name: "frames", Kind: "directory", View: packedFramesView(p, o)}}, o)
		if err != nil {
			return nil, err
		}
		return &auto.DescribedView{View: tree, Format: "ibmi_packed", Attributes: map[string]any{"expanded_bytes": p.ExpandedBytes, "frame_count": len(p.Frames), "relocations_applied": false}}, nil
	})
}
