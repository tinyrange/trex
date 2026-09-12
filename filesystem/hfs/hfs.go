// Package hfs reads classic HFS volumes without mounting. Layout facts follow
// Apple's HFS format declarations; data and resource forks remain distinct.
package hfs

import (
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/filesystem"
	starfile "github.com/tinyrange/trex/storage/star"
	"strings"
)

var be = binary.BigEndian

type extent struct{ start, count uint16 }
type forkKey struct {
	id      uint32
	kind    byte
	logical uint16
}
type Entry struct {
	Path, Kind                            string
	Name                                  []byte
	ID, Parent, Created, Modified, Backup uint32
	Flags                                 uint16
	FinderInfo                            []byte
	Data, Resource                        starfile.File
}
type Volume struct {
	Name    []byte
	Entries []Entry
}
type reader struct {
	file        starfile.File
	base, block int64
	blocks      uint32
	overflow    map[forkKey][]extent
}

func extents(b []byte) []extent {
	result := make([]extent, 3)
	for i := range result {
		result[i] = extent{be.Uint16(b[i*4:]), be.Uint16(b[i*4+2:])}
	}
	return result
}
func (r *reader) fork(id uint32, kind byte, size uint32, initial []extent) (starfile.File, error) {
	specs := []filesystem.ExtentSpec{}
	logical := int64(0)
	records := initial
	for {
		before := logical
		ended := false
		for _, e := range records {
			if e.count == 0 {
				ended = true
				continue
			}
			if ended || uint32(e.start)+uint32(e.count) > r.blocks {
				return nil, fmt.Errorf("hfs: invalid extent for %d", id)
			}
			start, length := r.base+int64(e.start)*r.block, int64(e.count)*r.block
			if start > r.file.Size() || length > r.file.Size()-start {
				return nil, fmt.Errorf("hfs: extent outside image")
			}
			offset := logical * r.block
			if offset < int64(size) {
				specs = append(specs, filesystem.ExtentSpec{Start: offset, Size: min(length, int64(size)-offset), File: r.file, Offset: start})
			}
			logical += int64(e.count)
		}
		if logical*r.block >= int64(size) {
			break
		}
		if logical == before || logical > 65535 {
			return nil, fmt.Errorf("hfs: incomplete fork extents for %d", id)
		}
		var ok bool
		records, ok = r.overflow[forkKey{id, kind, uint16(logical)}]
		if !ok {
			return nil, fmt.Errorf("hfs: missing overflow extents for file %d fork %d at block %d", id, kind, logical)
		}
	}
	return filesystem.NewGeneratedImage(fmt.Sprintf("hfs fork %d/%d", id, kind), int64(size), specs), nil
}

// leafRecords walks the linked leaf nodes, validating their offsets and count.
// This enumerates records; it does not need locale-dependent key comparisons.
func leafRecords(file starfile.File, maximum int, visit func([]byte) error) error {
	var header [120]byte
	if _, err := starfile.ReadFullAt(file, header[:], 0); err != nil {
		return err
	}
	if header[8] != 1 || header[9] != 0 || be.Uint16(header[10:]) != 3 {
		return fmt.Errorf("hfs: invalid B-tree header")
	}
	nodeSize := int64(be.Uint16(header[32:]))
	total := be.Uint32(header[36:])
	expected := be.Uint32(header[20:])
	first, last := be.Uint32(header[24:]), be.Uint32(header[28:])
	if nodeSize < 512 || nodeSize > 32768 || nodeSize&(nodeSize-1) != 0 || total == 0 || int64(total) > file.Size()/nodeSize || uint64(expected) > uint64(maximum) {
		return fmt.Errorf("hfs: invalid B-tree geometry or record limit")
	}
	seen := map[uint32]bool{}
	id, previous := first, uint32(0)
	count := uint32(0)
	node := make([]byte, nodeSize)
	for id != 0 {
		if id >= total || seen[id] {
			return fmt.Errorf("hfs: invalid or cyclic leaf link")
		}
		seen[id] = true
		if _, err := starfile.ReadFullAt(file, node, int64(id)*nodeSize); err != nil {
			return err
		}
		if node[8] != 255 || node[9] != 1 || be.Uint32(node[4:]) != previous {
			return fmt.Errorf("hfs: invalid leaf descriptor")
		}
		n := int(be.Uint16(node[10:]))
		table := int(nodeSize) - 2*(n+1)
		if n == 0 || table < 14 || uint64(count)+uint64(n) > uint64(maximum) {
			return fmt.Errorf("hfs: invalid leaf record count")
		}
		for i := 0; i < n; i++ {
			start, end := int(be.Uint16(node[int(nodeSize)-2*(i+1):])), int(be.Uint16(node[int(nodeSize)-2*(i+2):]))
			if start < 14 || end <= start || end > table {
				return fmt.Errorf("hfs: invalid leaf record offsets")
			}
			if err := visit(node[start:end]); err != nil {
				return err
			}
		}
		count += uint32(n)
		previous, id = id, be.Uint32(node)
	}
	if previous != last || count != expected {
		return fmt.Errorf("hfs: incomplete leaf chain")
	}
	return nil
}

// component is a reversible byte spelling, independent of host filenames and
// Macintosh script encodings. Raw names are also retained on every entry.
func component(name []byte) string {
	var b strings.Builder
	for _, c := range name {
		if c < 32 || c >= 127 || c == '/' || c == '%' {
			fmt.Fprintf(&b, "%%%02X", c)
		} else {
			b.WriteByte(c)
		}
	}
	s := b.String()
	if s == "." {
		return "%2E"
	}
	if s == ".." {
		return "%2E%2E"
	}
	return s
}

func Open(file starfile.File, maximumEntries int) (*Volume, error) {
	if maximumEntries <= 0 || maximumEntries > int(^uint(0)>>1)/3 {
		return nil, fmt.Errorf("hfs: invalid entry limit")
	}
	var m [162]byte
	if _, err := starfile.ReadFullAt(file, m[:], 1024); err != nil {
		return nil, err
	}
	if be.Uint16(m[:]) != 0x4244 {
		return nil, fmt.Errorf("hfs: expected classic HFS signature")
	}
	if be.Uint16(m[124:]) == 0x482b {
		return nil, fmt.Errorf("hfs: embedded HFS Plus volume requires its own decoder")
	}
	r := reader{file: file, base: int64(be.Uint16(m[28:])) * 512, block: int64(be.Uint32(m[20:])), blocks: uint32(be.Uint16(m[18:])), overflow: map[forkKey][]extent{}}
	if r.block < 512 || r.block%512 != 0 || r.blocks == 0 || r.base < 1536 || r.base > file.Size() || int64(r.blocks)*r.block > file.Size()-r.base || m[36] > 27 {
		return nil, fmt.Errorf("hfs: invalid volume geometry")
	}
	v := &Volume{Name: append([]byte(nil), m[37:37+int(m[36])]...)}
	overflow, err := r.fork(3, 0, be.Uint32(m[130:]), extents(m[134:]))
	if err != nil {
		return nil, err
	}
	if overflow.Size() != 0 {
		err = leafRecords(overflow, maximumEntries*3, func(b []byte) error {
			if len(b) < 20 || b[0] != 7 || (b[1] != 0 && b[1] != 255) {
				return fmt.Errorf("hfs: invalid overflow record")
			}
			key := forkKey{be.Uint32(b[2:]), b[1], be.Uint16(b[6:])}
			if _, ok := r.overflow[key]; ok {
				return fmt.Errorf("hfs: repeated overflow extent key")
			}
			r.overflow[key] = extents(b[8:])
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	catalog, err := r.fork(4, 0, be.Uint32(m[146:]), extents(m[150:]))
	if err != nil {
		return nil, err
	}
	ids := map[uint32]int{}
	err = leafRecords(catalog, maximumEntries*3, func(b []byte) error {
		if len(b) < 8 {
			return fmt.Errorf("hfs: short catalog record")
		}
		keySize := int(b[0])
		nameSize := int(b[6])
		dataOffset := (keySize + 2) &^ 1
		if keySize < 6 || nameSize > 31 || nameSize+6 > keySize || dataOffset >= len(b) {
			return fmt.Errorf("hfs: invalid catalog key")
		}
		data := b[dataOffset:]
		if data[0] == 3 || data[0] == 4 {
			if len(data) < 46 {
				return fmt.Errorf("hfs: truncated catalog thread")
			}
			return nil
		}
		if len(v.Entries) >= maximumEntries || nameSize == 0 {
			return fmt.Errorf("hfs: entry limit or empty catalog name")
		}
		e := Entry{Name: append([]byte(nil), b[7:7+nameSize]...), Parent: be.Uint32(b[2:])}
		switch data[0] {
		case 1:
			if len(data) < 70 {
				return fmt.Errorf("hfs: truncated directory record")
			}
			e.Kind = "directory"
			e.ID = be.Uint32(data[6:])
			e.Flags = be.Uint16(data[2:])
			e.Created = be.Uint32(data[10:])
			e.Modified = be.Uint32(data[14:])
			e.Backup = be.Uint32(data[18:])
			e.FinderInfo = append([]byte(nil), data[22:54]...)
		case 2:
			if len(data) < 102 {
				return fmt.Errorf("hfs: truncated file record")
			}
			e.Kind = "file"
			e.ID = be.Uint32(data[20:])
			e.Flags = uint16(data[2])
			e.Created = be.Uint32(data[44:])
			e.Modified = be.Uint32(data[48:])
			e.Backup = be.Uint32(data[52:])
			e.FinderInfo = append(append([]byte(nil), data[4:20]...), data[56:72]...)
			var err error
			e.Data, err = r.fork(e.ID, 0, be.Uint32(data[26:]), extents(data[74:]))
			if err != nil {
				return err
			}
			e.Resource, err = r.fork(e.ID, 255, be.Uint32(data[36:]), extents(data[86:]))
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("hfs: unknown catalog record kind %d", data[0])
		}
		if _, ok := ids[e.ID]; ok {
			return fmt.Errorf("hfs: duplicate catalog ID")
		}
		ids[e.ID] = len(v.Entries)
		v.Entries = append(v.Entries, e)
		return nil
	})
	if err != nil {
		return nil, err
	}
	root, ok := ids[2]
	if !ok || v.Entries[root].Kind != "directory" || v.Entries[root].Parent != 1 {
		return nil, fmt.Errorf("hfs: missing root directory")
	}
	v.Entries[root].Path = "/"
	paths := map[string]bool{"/": true}
	for i := range v.Entries {
		if i == root {
			continue
		}
		chain := []int{}
		seen := map[uint32]bool{}
		at := i
		for v.Entries[at].Path == "" {
			e := v.Entries[at]
			if seen[e.ID] {
				return nil, fmt.Errorf("hfs: parent cycle")
			}
			seen[e.ID] = true
			chain = append(chain, at)
			parent, ok := ids[e.Parent]
			if !ok || v.Entries[parent].Kind != "directory" {
				return nil, fmt.Errorf("hfs: missing directory parent")
			}
			at = parent
		}
		for j := len(chain) - 1; j >= 0; j-- {
			index := chain[j]
			name := strings.TrimSuffix(v.Entries[at].Path, "/") + "/" + component(v.Entries[index].Name)
			if paths[name] {
				return nil, fmt.Errorf("hfs: duplicate catalog path")
			}
			paths[name] = true
			v.Entries[index].Path = name
			at = index
		}
	}
	return v, nil
}
