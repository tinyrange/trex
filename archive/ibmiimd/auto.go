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
	auto.Register("ibmi_imd", 30, func(prefix []byte, source storage.Reader, o auto.Options) (auto.View, error) {
		if len(prefix) < 4 || !bytes.Equal(prefix[:4], magic) {
			return nil, auto.ErrNoMatch
		}
		image, err := Open(source, o.MaxEntries-4, o.MaxExpandedBytes)
		if err != nil {
			return nil, err
		}
		metadata, err := json.MarshalIndent(image, "", "  ")
		if err != nil {
			return nil, err
		}
		entries := []auto.Entry{
			{Name: "header.bin", Kind: "file", Reader: image.Header},
			{Name: "directory.bin", Kind: "file", Reader: image.Directory},
			{Name: "metadata.json", Kind: "file", Reader: &starfile.Bytes{Data: metadata}},
		}
		for _, e := range image.Entries {
			entries = append(entries, auto.Entry{Name: fmt.Sprintf("components/%08x.bin", e.ID), Kind: "file", Reader: e.Data,
				Attributes: map[string]any{"offset": e.Offset, "stored_size": e.StoredBytes, "flags": e.Flags, "declared_address": e.DeclaredAddress, "decoding_complete": false}})
		}
		tree, err := auto.Tree(entries, o)
		if err != nil {
			return nil, err
		}
		return &auto.DescribedView{View: tree, Format: "ibmi_imd", Attributes: map[string]any{"component_count": len(image.Entries), "stored_component_bytes": image.StoredBytes, "decoding_complete": false}}, nil
	})
}
