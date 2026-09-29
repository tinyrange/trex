package hfs

import (
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
)

func init() {
	auto.Register("hfs", 30, func(p []byte, r storage.Reader, o auto.Options) (auto.View, error) {
		if len(p) < 1026 || (string(p[1024:1026]) != "BD" && string(p[1024:1026]) != "H+" && string(p[1024:1026]) != "HX") {
			return nil, auto.ErrNoMatch
		}
		volume, err := Open(adapter.File(r), o.MaxEntries)
		if err != nil {
			return nil, err
		}
		var entries []auto.Entry
		for _, e := range volume.Entries {
			item := auto.Entry{Name: e.Path, Kind: e.Kind, Reader: e.Data, Attributes: map[string]any{"name": e.Name, "id": e.ID, "created": e.Created, "modified": e.Modified, "finder_info": e.FinderInfo}}
			if e.Resource != nil {
				forks := []auto.Entry{{Name: "resource", Kind: "file", Reader: e.Resource}}
				if e.Data != nil {
					forks = append(forks, auto.Entry{Name: "data", Kind: "file", Reader: e.Data})
				}
				item.View = auto.ViewFunc(func() ([]auto.Entry, error) { return forks, nil })
			}
			entries = append(entries, item)
		}
		return auto.Tree(entries, o)
	})
}
