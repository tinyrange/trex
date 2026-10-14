// Package berkeleydb reads the BSD Berkeley DB version 3 B-tree format.
// It traverses the tree rooted at page 1 rather than scanning unused pages.
// Inline keys and values are supported; overflow and record-number trees fail
// explicitly. Sources use the portable Reader interface and remain borrowed.
// Format reference: OpenBSD libc/db/btree/btree.h (BSD-3-Clause).
package berkeleydb

import (
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	"github.com/tinyrange/trex/storage"
)

type Entry struct{ Key, Value storage.Reader }
type File struct {
	PageSize     uint32
	LittleEndian bool
	Entries      []Entry
}

// Open reads a bounded inline B-tree. A database can have a custom key
// comparator; records preserve traversal order without assuming byte sorting.
func Open(source storage.Reader, maximum int) (*File, error) {
	if source == nil || source.Size() < 24 || maximum <= 0 {
		return nil, fmt.Errorf("berkeley_db: invalid source or entry bound")
	}
	var h [24]byte
	if _, err := source.ReadAt(h[:], 0); err != nil {
		return nil, err
	}
	var order binary.ByteOrder = binary.LittleEndian
	little := true
	if order.Uint32(h[:]) != 0x53162 {
		order = binary.BigEndian
		little = false
	}
	if order.Uint32(h[:]) != 0x53162 || order.Uint32(h[4:]) != 3 {
		return nil, fmt.Errorf("berkeley_db: expected version 3 B-tree")
	}
	pageSize := order.Uint32(h[8:])
	if pageSize < 512 || pageSize > 65536 || pageSize%2 != 0 || source.Size()%int64(pageSize) != 0 || source.Size()/int64(pageSize) < 2 {
		return nil, fmt.Errorf("berkeley_db: invalid page geometry")
	}
	if order.Uint32(h[20:]) & ^uint32(0x20) != 0 {
		return nil, fmt.Errorf("berkeley_db: unsupported database flags")
	}
	f := &File{PageSize: pageSize, LittleEndian: little}
	seen := map[uint32]bool{}
	type links struct{ page, previous, next uint32 }
	leaves := []links{}
	var walk func(uint32, int) error
	walk = func(page uint32, depth int) error {
		if page == 0 || int64(page) >= source.Size()/int64(pageSize) || depth > 64 || seen[page] {
			return fmt.Errorf("berkeley_db: invalid, cyclic or repeated page")
		}
		if len(seen) >= 1000000 {
			return fmt.Errorf("berkeley_db: page bound exceeded")
		}
		seen[page] = true
		b := make([]byte, pageSize)
		base := int64(page) * int64(pageSize)
		if _, err := source.ReadAt(b, base); err != nil {
			return err
		}
		kind := order.Uint32(b[12:])
		if order.Uint32(b) != page || (kind != 1 && kind != 2) {
			return fmt.Errorf("berkeley_db: invalid or unsupported page type")
		}
		if kind == 2 {
			leaves = append(leaves, links{page, order.Uint32(b[4:]), order.Uint32(b[8:])})
		}
		lower, upper := int(order.Uint16(b[16:])), int(order.Uint16(b[18:]))
		if lower < 20 || lower%2 != 0 || lower > upper || upper > len(b) {
			return fmt.Errorf("berkeley_db: invalid page free-space bounds")
		}
		type span struct{ start, end int }
		spans := []span{}
		children := []uint32{}
		for i := 20; i < lower; i += 2 {
			off := int(order.Uint16(b[i:]))
			if off < upper || off > len(b)-9 {
				return fmt.Errorf("berkeley_db: invalid record offset")
			}
			keySize := uint64(order.Uint32(b[off:]))
			valueSize := uint64(0)
			if kind == 2 {
				valueSize = uint64(order.Uint32(b[off+4:]))
			}
			if b[off+8] != 0 {
				return fmt.Errorf("berkeley_db: overflow keys or values unsupported")
			}
			length := uint64(9) + keySize + valueSize
			if length > uint64(len(b)-off) {
				return fmt.Errorf("berkeley_db: record exceeds page")
			}
			end := (off + int(length) + 3) &^ 3
			if end > len(b) {
				return fmt.Errorf("berkeley_db: record padding exceeds page")
			}
			spans = append(spans, span{off, end})
			if kind == 1 {
				children = append(children, order.Uint32(b[off+4:]))
			} else {
				if len(f.Entries) == maximum {
					return fmt.Errorf("berkeley_db: entry bound exceeded")
				}
				f.Entries = append(f.Entries, Entry{io.NewSectionReader(source, base+int64(off)+9, int64(keySize)), io.NewSectionReader(source, base+int64(off)+9+int64(keySize), int64(valueSize))})
			}
		}
		sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
		for i := 1; i < len(spans); i++ {
			if spans[i].start < spans[i-1].end {
				return fmt.Errorf("berkeley_db: overlapping records")
			}
		}
		if kind == 1 && len(children) == 0 {
			return fmt.Errorf("berkeley_db: empty internal page")
		}
		for _, child := range children {
			if err := walk(child, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(1, 0); err != nil {
		return nil, err
	}
	for i, leaf := range leaves {
		var previous, next uint32
		if i > 0 {
			previous = leaves[i-1].page
		}
		if i+1 < len(leaves) {
			next = leaves[i+1].page
		}
		if leaf.previous != previous || leaf.next != next {
			return nil, fmt.Errorf("berkeley_db: inconsistent leaf sibling links")
		}
	}
	return f, nil
}
