package registry

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"unicode"

	"github.com/tinyrange/trex/storage"
)

// OpenSnapshot takes an owned immutable copy before enabling lazy metadata
// indexes. Open deliberately never caches data from a possibly mutable reader.
// Capture requires the caller not to mutate the source concurrently.
func OpenSnapshot(file storage.Reader, maximum int64) (*Hive, error) {
	if file == nil || file.Size() < baseBlockSize || file.Size() > maximum || uint64(file.Size()) > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("registry snapshot: invalid or excessive file size")
	}
	data := make([]byte, int(file.Size()))
	if err := readFullAt(file, data, 0); err != nil {
		return nil, err
	}
	hive, err := Open(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	hive.snapshot = &snapshotIndex{}
	return hive, nil
}

// ReadAt and Size expose the same byte source used by this view. A snapshot is
// read-only and independent of its source; an ordinary Open view is still live.
func (h *Hive) ReadAt(p []byte, off int64) (int, error) { return h.file.ReadAt(p, off) }
func (h *Hive) Size() int64                             { return h.file.Size() }

type snapshotIndex struct {
	keys     sync.Map // cell -> Key (no mutable fields)
	children sync.Map // complete parent Key -> *snapshotChildren
}
type snapshotChildren struct {
	ordered []Key
	byName  map[string]Key
}

// Preserve strings.EqualFold semantics, including Kelvin sign and long s.
// Lowercasing alone does not produce equivalence classes for Unicode folding.
func foldedKeyName(name string) string {
	return strings.Map(func(r rune) rune {
		least := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < least {
				least = next
			}
		}
		return least
	}, name)
}
func (h *Hive) indexedChildren(parent Key) (*snapshotChildren, error) {
	if value, ok := h.snapshot.children.Load(parent); ok {
		return value.(*snapshotChildren), nil
	}
	keys, err := h.readSubkeys(parent)
	if err != nil {
		return nil, err
	}
	index := &snapshotChildren{ordered: keys, byName: make(map[string]Key, len(keys))}
	for _, key := range keys {
		folded := foldedKeyName(key.Name)
		// Match the old first-in-index behavior for duplicate folded names.
		if _, exists := index.byName[folded]; !exists {
			index.byName[folded] = key
		}
	}
	value, _ := h.snapshot.children.LoadOrStore(parent, index)
	return value.(*snapshotChildren), nil
}
