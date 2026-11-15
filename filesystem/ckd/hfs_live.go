package ckd

import (
	"fmt"
	"io"
	"sync"

	"github.com/tinyrange/trex/storage"
)

// pageRecorder marks the 4096-byte pages of a source that are read.
type pageRecorder struct {
	storage.Reader
	mu    sync.Mutex
	pages map[uint64]bool
}

func (r *pageRecorder) ReadAt(p []byte, off int64) (int, error) {
	n, err := r.Reader.ReadAt(p, off)
	if n > 0 {
		r.mu.Lock()
		for pg := uint64(off) / 4096; pg <= uint64(off+int64(n)-1)/4096; pg++ {
			r.pages[pg] = true
		}
		r.mu.Unlock()
	}
	return n, err
}

// HFSLivePages opens an HFS data set's pages, walks every directory and
// reads every file and symbolic link, and reports which pages the reader
// used: the IGW control and map pages, the attribute directory, and each
// object's allocation. Pages it did not use may still hold structures this
// reader does not interpret (such as space maps), so the set is evidence
// for a decision, not a free-space map.
func (ds *Dataset) HFSLivePages(maxEntries int) (live map[uint64]bool, total uint64, err error) {
	pages, err := ds.OpenPages(4096)
	if err != nil {
		return nil, 0, err
	}
	rec := &pageRecorder{Reader: pages, pages: map[uint64]bool{}}
	h, err := OpenHFS(rec, maxEntries)
	if err != nil {
		return nil, 0, err
	}
	seen := map[[6]byte]bool{}
	var walk func([6]byte, int) error
	walk = func(dir [6]byte, depth int) error {
		if depth > 256 || seen[dir] {
			return nil
		}
		seen[dir] = true
		names, err := h.Directory(dir)
		if err != nil {
			return err
		}
		for _, n := range names {
			if len(seen) > maxEntries {
				return fmt.Errorf("HFS: entry limit")
			}
			i, err := h.Inode(n.Object)
			if err != nil {
				return err
			}
			switch i.Kind {
			case "directory":
				if err := walk(n.Object, depth+1); err != nil {
					return err
				}
			case "file":
				if seen[n.Object] {
					continue // a hard link already read
				}
				seen[n.Object] = true
				f, err := h.File(n.Object)
				if err != nil {
					return err
				}
				if _, err := io.Copy(io.Discard, io.NewSectionReader(f, 0, f.Size())); err != nil {
					return err
				}
			case "symlink":
				if _, err := h.Link(n.Object); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(hfsRoot, 0); err != nil {
		return nil, 0, err
	}
	return rec.pages, pages.Count(), nil
}
