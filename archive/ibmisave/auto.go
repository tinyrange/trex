package ibmisave

import (
	"bytes"
	"fmt"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
)

func init() {
	auto.Register("ibmi_save", 30, func(p []byte, r storage.Reader, o auto.Options) (auto.View, error) {
		if len(p) <= pageSize || !bytes.Equal(p[:4], []byte{255, 255, 255, 255}) || !bytes.Equal(p[0x96:0xae], descriptor) || !bytes.HasPrefix(p[4:34], catalogName) {
			return nil, auto.ErrNoMatch
		}
		a, err := Open(adapter.File(r), o.MaxEntries)
		if err != nil {
			return nil, err
		}
		counts := map[string]int{}
		views := objectViews(a.Objects)
		for _, obj := range a.Objects {
			counts[fmt.Sprintf("save%d/%s", obj.Group, obj.Name)]++
		}
		seen := map[string]int{}
		var entries []auto.Entry
		for _, obj := range a.Objects {
			name := obj.Name
			if name == "." || name == ".." {
				name = "%4B"
				if obj.Name == ".." {
					name += "%4B"
				}
			}
			path := fmt.Sprintf("save%d/%s", obj.Group, name)
			key := fmt.Sprintf("save%d/%s", obj.Group, obj.Name)
			if counts[key] > 1 {
				seen[key]++
				path += fmt.Sprintf("/occurrence%d", seen[key])
			}
			attrs := map[string]any{"raw_name": fmt.Sprintf("%x", obj.RawName), "object_type": fmt.Sprintf("%04x", obj.Type), "offset": obj.Offset, "declared_data_blocks": obj.DeclaredDataBlocks}
			entries = append(entries, auto.Entry{Name: path, Kind: "directory", View: views[obj.Offset], Attributes: attrs})
		}
		tree, err := auto.Tree(entries, o)
		if err != nil {
			return nil, err
		}
		return &auto.DescribedView{View: tree, Format: "ibmi_save", Attributes: map[string]any{"save_groups": a.Groups, "objects": len(a.Objects), "restored": false}}, nil
	})
}
