package xcoff

import (
	"encoding/json"
	"fmt"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
)

func init() {
	auto.Register("xcoff32", 30, func(prefix []byte, source storage.Reader, o auto.Options) (auto.View, error) {
		if len(prefix) < 2 || prefix[0] != 1 || prefix[1] != 0xdf {
			return nil, auto.ErrNoMatch
		}
		f, err := Open(source, o.MaxEntries-4)
		if err != nil {
			return nil, err
		}
		metadata, err := json.MarshalIndent(f, "", "  ")
		if err != nil {
			return nil, err
		}
		entries := []auto.Entry{{Name: "metadata.json", Kind: "file", Reader: &starfile.Bytes{Data: metadata}}, {Name: "headers.bin", Kind: "file", Reader: f.RawHeader}}
		for index, s := range f.Sections {
			if s.Stored != nil {
				entries = append(entries, auto.Entry{Name: fmt.Sprintf("sections/%d.bin", index+1), Kind: "file", Reader: s.Stored, Attributes: map[string]any{"section_name": s.Name, "virtual_address": s.VirtualAddress, "flags": s.Flags}})
			}
		}
		for _, s := range f.Sections {
			if s.Flags&0xffff == 0x1000 {
				entries = append(entries, auto.Entry{Name: "loader", Kind: "directory", View: loaderView(f, o), Attributes: map[string]any{"relocations_applied": false}})
				break
			}
		}
		tree, err := auto.Tree(entries, o)
		if err != nil {
			return nil, err
		}
		return &auto.DescribedView{View: tree, Format: "xcoff32", Attributes: map[string]any{"sections": len(f.Sections), "entry_point": f.EntryPoint, "has_entry": f.HasEntry, "decoding_complete": false}}, nil
	})
}
