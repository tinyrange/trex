package filesystem

import (
	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
)

// AutoView exposes a snapshot of an in-memory directory through the common
// portable view, without depending on a detector or a host filesystem.
func (d *Directory) AutoView(options auto.Options) (auto.View, error) {
	snapshot := d.Snapshot()
	entries := make([]auto.Entry, 0, len(snapshot.Directories)+len(snapshot.Files))
	for _, name := range snapshot.Directories {
		entries = append(entries, auto.Entry{Name: name, Kind: "directory"})
	}
	for name, record := range snapshot.Files {
		file := record.File
		if file == nil {
			file = &starfile.Bytes{Name: name, Data: record.Data[:record.Size]}
		}
		entries = append(entries, auto.Entry{Name: name, Kind: "file", Reader: file})
	}
	return auto.Tree(entries, options)
}
