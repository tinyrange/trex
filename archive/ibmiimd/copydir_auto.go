package ibmiimd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
)

func init() {
	auto.Register("ibmi_copydir", 30, func(prefix []byte, source storage.Reader, o auto.Options) (auto.View, error) {
		if len(prefix) < 8 || !bytes.Equal(prefix[:8], copyMagic) {
			return nil, auto.ErrNoMatch
		}
		c, err := OpenCopyDirectory(source, min(256, o.MaxEntries), o.MaxEntries, o.StreamingMaximum())
		if err != nil {
			return nil, err
		}
		meta, err := json.MarshalIndent(c, "", "  ")
		if err != nil {
			return nil, err
		}
		if int64(len(meta)) > o.MaxExpandedBytes {
			return nil, fmt.Errorf("ibmi copydir: metadata byte budget")
		}
		entries := []auto.Entry{{Name: "header.bin", Kind: "file", Reader: c.Header}, {Name: "directory.bin", Kind: "file", Reader: c.Directory}, {Name: "metadata.json", Kind: "file", Reader: &starfile.Bytes{Data: meta}}}
		for _, s := range c.Segments {
			entries = append(entries, auto.Entry{Name: fmt.Sprintf("segments/%016x.bin", s.Address), Kind: "file", Reader: s.Data, Attributes: map[string]any{"saved_base": s.Address, "saved_start": s.CopiedAddress, "omitted_prefix_bytes": 4096, "file_offset": s.Offset, "flags": s.Flags, "logical_span": s.Span}})
		}
		for _, e := range c.LIDs {
			if e.Data != nil {
				entries = append(entries, auto.Entry{Name: fmt.Sprintf("components/%08x.bin", e.ID), Kind: "file", Reader: e.Data, Attributes: map[string]any{"saved_address": e.SavedAddress, "disk_sector": e.DiskSector, "flags": e.Flags, "execution_address_confirmed": false}})
			}
		}
		tree, err := auto.Tree(entries, o)
		if err != nil {
			return nil, err
		}
		return &auto.DescribedView{View: tree, Format: "ibmi_copydir", Attributes: map[string]any{"segments": len(c.Segments), "lids": len(c.LIDs), "copied_bytes": c.CopiedBytes, "restored_image": false}}, nil
	})
}
