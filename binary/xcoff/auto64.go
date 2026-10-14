package xcoff

import (
	"encoding/json"
	"fmt"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
)

func init() {
	auto.Register("xcoff64", 30, func(prefix []byte, source storage.Reader, o auto.Options) (auto.View, error) {
		if len(prefix) < 2 || prefix[0] != 1 || prefix[1] != 0xf7 {
			return nil, auto.ErrNoMatch
		}
		f, err := Open64(source, o.MaxEntries-4)
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
				entries = append(entries, auto.Entry{Name: "loader", Kind: "directory", View: loaderView64(f, o), Attributes: map[string]any{"relocations_applied": false}})
				break
			}
		}
		entries = append(entries, auto.Entry{Name: "symbols", Kind: "directory", View: auto.ViewFunc(func() ([]auto.Entry, error) {
			symbols, err := f.ReadSymbols(o.MaxEntries, min(o.MaxExpandedBytes, 64<<20))
			if err != nil {
				return nil, err
			}
			raw, err := json.MarshalIndent(symbols, "", "  ")
			if err != nil {
				return nil, err
			}
			if int64(len(raw)) > o.MaxExpandedBytes {
				return nil, fmt.Errorf("xcoff64 symbols: JSON byte budget")
			}
			return []auto.Entry{{Name: "symbols.json", Kind: "file", Reader: &starfile.Bytes{Data: raw}}}, nil
		})})
		for i, s := range f.sections {
			if s.Relocations == 0 {
				continue
			}
			index := i + 1
			entries = append(entries, auto.Entry{Name: fmt.Sprintf("relocations/%d", index), Kind: "directory", View: auto.ViewFunc(func() ([]auto.Entry, error) {
				relocations, err := f.ReadRelocations(index, o.MaxEntries, min(o.MaxExpandedBytes, 64<<20))
				if err != nil {
					return nil, err
				}
				raw, err := json.MarshalIndent(relocations, "", "  ")
				if err != nil {
					return nil, err
				}
				if int64(len(raw)) > o.MaxExpandedBytes {
					return nil, fmt.Errorf("xcoff64 relocations: JSON byte budget")
				}
				return []auto.Entry{{Name: "relocations.json", Kind: "file", Reader: &starfile.Bytes{Data: raw}}}, nil
			})})
		}
		tree, err := auto.Tree(entries, o)
		if err != nil {
			return nil, err
		}
		return &auto.DescribedView{View: tree, Format: "xcoff64", Attributes: map[string]any{"sections": len(f.Sections), "entry_point": f.EntryPoint, "has_entry": f.HasEntry, "decoding_complete": false}}, nil
	})
}
