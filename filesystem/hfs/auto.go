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
			item := auto.Entry{Name: e.Path, Kind: e.Kind, Reader: e.Data, Attributes: map[string]any{"name": e.Name, "id": e.ID, "created": e.Created, "modified": e.Modified, "finder_info": e.FinderInfo, "mode": e.Mode, "uid": e.UID, "gid": e.GID, "owner_flags": e.OwnerFlags, "admin_flags": e.AdminFlags, "target": e.Target}}
			if e.Kind != "directory" && (e.Resource != nil && e.Resource.Size() != 0 || len(e.Xattrs) != 0 || e.RawData != nil) {
				var forks []auto.Entry
				if e.Resource != nil {
					forks = append(forks, auto.Entry{Name: "resource", Kind: "file", Reader: e.Resource})
				}
				if e.RawData != nil {
					forks = append(forks, auto.Entry{Name: "raw_data", Kind: "file", Reader: e.RawData})
				}
				if e.RawResource != nil {
					forks = append(forks, auto.Entry{Name: "raw_resource", Kind: "file", Reader: e.RawResource})
				}
				for name, value := range e.Xattrs {
					forks = append(forks, auto.Entry{Name: "xattrs/" + plusComponent([]byte(name)), Kind: "file", Reader: value})
				}
				if e.Data != nil {
					forks = append(forks, auto.Entry{Name: "data", Kind: "file", Reader: e.Data})
				}
				forkView, err := auto.Tree(forks, o)
				if err != nil {
					return nil, err
				}
				item.View = forkView
			}
			entries = append(entries, item)
		}
		return auto.Tree(entries, o)
	})
}
