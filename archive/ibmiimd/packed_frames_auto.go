package ibmiimd

import (
	"encoding/json"
	"fmt"
	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
)

func packedFramesView(p *Packed, o auto.Options) auto.View {
	return auto.ViewFunc(func() ([]auto.Entry, error) {
		if len(p.Frames) > o.MaxEntries {
			return nil, fmt.Errorf("ibmi packed: frame view budget")
		}
		entries := make([]auto.Entry, 0, len(p.Frames))
		for i := range p.Frames {
			index := i
			entries = append(entries, auto.Entry{Name: fmt.Sprintf("%08d", index), Kind: "directory", View: auto.ViewFunc(func() ([]auto.Entry, error) {
				info, tail, err := p.InspectFrame(index)
				if err != nil {
					return nil, err
				}
				metadata, err := json.MarshalIndent(info, "", "  ")
				if err != nil {
					return nil, err
				}
				if int64(len(metadata)) > o.MaxExpandedBytes {
					return nil, fmt.Errorf("ibmi packed: frame metadata byte budget")
				}
				return []auto.Entry{{Name: "metadata.json", Kind: "file", Reader: &starfile.Bytes{Data: metadata}}, {Name: "tail.bin", Kind: "file", Reader: tail}}, nil
			})})
		}
		return entries, nil
	})
}
