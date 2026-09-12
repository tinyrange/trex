package ufs

import (
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
	"path"
	"sync"
)

func init() {
	auto.Register("ufs", 30, func(p []byte, r storage.Reader, o auto.Options) (auto.View, error) {
		if !(len(p) >= 9568 && (binary.BigEndian.Uint32(p[9564:]) == 0x11954 || binary.LittleEndian.Uint32(p[9564:]) == 0x11954)) {
			return nil, auto.ErrNoMatch
		}
		return AutoView(r, o)
	})
}

// AutoView validates geometry immediately and reads directory contents on demand.
// Open remains the explicit full-volume validation/enumeration API.
func AutoView(source storage.Reader, o auto.Options) (auto.View, error) {
	r, root, err := openReader(adapter.File(source), o.MaxEntries, o.MaxEntries)
	if err != nil {
		return nil, err
	}
	root.Path = "/"
	var mu sync.Mutex
	remaining := o.MaxEntries - 1
	seen := map[uint32]bool{2: true}
	var directory func(Entry, uint32) auto.View
	directory = func(current Entry, parent uint32) auto.View {
		var once sync.Once
		var result []auto.Entry
		var resultErr error
		return auto.ViewFunc(func() ([]auto.Entry, error) {
			once.Do(func() {
				mu.Lock()
				defer mu.Unlock()
				children, err := directoryEntries(current, parent, r.order, remaining, r.inode)
				if err != nil {
					resultErr = err
					return
				}
				remaining -= len(children)
				for _, e := range children {
					item := auto.Entry{Name: path.Base(e.Path), Kind: e.Kind, Reader: e.Data, Attributes: map[string]any{"inode": e.Inode, "mode": e.Mode, "links": e.Links, "uid": e.UID, "gid": e.GID, "accessed": e.Accessed, "modified": e.Modified, "changed": e.Changed, "flags": e.Flags, "device": e.Device}}
					if e.Kind == "directory" {
						if seen[e.Inode] {
							resultErr = fmt.Errorf("ufs: directory cycle or hard link")
							return
						}
						seen[e.Inode] = true
						item.Reader = nil
						item.View = directory(e, current.Inode)
					}
					result = append(result, item)
				}
			})
			return append([]auto.Entry(nil), result...), resultErr
		})
	}
	return directory(root, 2), nil
}
