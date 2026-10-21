package xcoff

import (
	"encoding/json"
	"fmt"
	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
)

func loaderView64(f *File64, o auto.Options) auto.View {
	return auto.ViewFunc(func() ([]auto.Entry, error) {
		l, err := f.ReadLoader(o.MaxEntries-4, min(o.MaxExpandedBytes, 64<<20))
		if err != nil {
			return nil, err
		}
		if l == nil {
			return nil, nil
		}
		values := []struct {
			name  string
			value any
		}{
			{"metadata.json", map[string]any{"version": l.Version, "symbols": len(l.Symbols), "imports": len(l.Imports), "relocations": len(l.Relocations), "string_bytes": l.StringBytes, "relocations_applied": false}},
			{"symbols.json", l.Symbols}, {"imports.json", l.Imports}, {"relocations.json", l.Relocations},
		}
		var entries []auto.Entry
		var total int64
		for _, v := range values {
			b, err := json.MarshalIndent(v.value, "", "  ")
			if err != nil {
				return nil, err
			}
			if int64(len(b)) > o.MaxExpandedBytes-total {
				return nil, fmt.Errorf("xcoff loader: JSON byte budget")
			}
			total += int64(len(b))
			entries = append(entries, auto.Entry{Name: v.name, Kind: "file", Reader: &starfile.Bytes{Data: b}})
		}
		return entries, nil
	})
}
