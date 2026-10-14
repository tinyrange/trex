package ibmisave

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
)

func init() {
	auto.Register("ibmi_terse", 31, func(p []byte, r storage.Reader, o auto.Options) (auto.View, error) {
		if len(p) < 12 || binary.BigEndian.Uint32(p) != 0x02000080 {
			return nil, auto.ErrNoMatch
		}
		if r.Size() > 65535 {
			return nil, auto.ErrNoMatch
		}
		raw, err := starfile.ReadAll(adapter.File(r))
		if err != nil {
			return nil, err
		}
		if int64(binary.BigEndian.Uint32(p[8:])) > o.MaxExpandedBytes {
			return nil, fmt.Errorf("ibmi_terse: expanded byte limit")
		}
		expanded, info, err := DecodeTerseWithInfo(raw)
		if err != nil {
			return nil, err
		}
		if !info.TerminationVerified {
			return nil, fmt.Errorf("ibmi_terse: invalid end code or fill")
		}
		meta, err := json.Marshal(info)
		if err != nil {
			return nil, err
		}
		tree, err := auto.Tree([]auto.Entry{{Name: "expanded.bin", Kind: "file", Reader: &starfile.Bytes{Data: expanded}}, {Name: "metadata.json", Kind: "file", Reader: &starfile.Bytes{Data: meta}}}, o)
		if err != nil {
			return nil, err
		}
		return &auto.DescribedView{View: tree, Format: "ibmi_terse", Attributes: map[string]any{"codec": 2, "expanded_bytes": len(expanded), "termination_verified": info.TerminationVerified}}, nil
	})
}
