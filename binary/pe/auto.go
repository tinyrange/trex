package pe

import (
	"bytes"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
)

func init() {
	// Prefer actual installer envelopes; ordinary PEs can still expose resources
	// for recursive parsing without inventing an installer format.
	auto.Register("pe_resources", 99, func(prefix []byte, source storage.Reader, o auto.Options) (auto.View, error) {
		if !bytes.HasPrefix(prefix, []byte("MZ")) {
			return nil, auto.ErrNoMatch
		}
		maximum := o.MaxEntries
		if maximum <= 0 {
			maximum = 100000
		}
		resources, err := Resources(source, maximum)
		if err != nil || len(resources) == 0 {
			return nil, auto.ErrNoMatch
		}
		entries := make([]auto.Entry, 0, len(resources))
		for _, r := range resources {
			entries = append(entries, auto.Entry{Name: r.Path, Kind: "file", Reader: r.Data})
		}
		return auto.Tree(entries, o)
	})
}
