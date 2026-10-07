// Package bom reads Apple BOMStore path inventories. A BOM describes files;
// it does not contain their payloads. Non-directory entries are metadata only.
package bom

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"path"
	"strings"
	"unicode/utf8"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
)

var be = binary.BigEndian

func init() { auto.Register("bom", 20, Open) }

type pointer struct{ off, length uint32 }
type record struct {
	id, parent uint32
	name       string
	entry      auto.Entry
}

func Open(prefix []byte, source storage.Reader, o auto.Options) (auto.View, error) {
	if !bytes.HasPrefix(prefix, []byte("BOMStore")) {
		return nil, auto.ErrNoMatch
	}
	entries, err := Read(source, o.MaxEntries)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var treeEntries []auto.Entry
	for i := range entries {
		e := &entries[i]
		if e.Name == "." {
			continue
		}
		if seen[e.Name] {
			e.Attributes["bom_path"] = e.Name
			e.Name = fmt.Sprintf("%%00bom-variants/%v", e.Attributes["bom_id"])
		} else {
			seen[e.Name] = true
		}
		treeEntries = append(treeEntries, *e)
	}
	return auto.Tree(treeEntries, o)
}

// Read returns every flat inventory record, including architecture variants
// sharing a path. A BOM is metadata, never a substitute for payload contents.
func Read(source storage.Reader, limit int) ([]auto.Entry, error) {
	if limit <= 0 {
		limit = 100000
	}
	read := func(off, n uint64) ([]byte, error) {
		if off > uint64(source.Size()) || n > uint64(source.Size())-off || n > 64<<20 {
			return nil, fmt.Errorf("bom: extent outside source or allocation limit")
		}
		b := make([]byte, int(n))
		_, err := io.ReadFull(io.NewSectionReader(source, int64(off), int64(n)), b)
		return b, err
	}
	h, err := read(0, 32)
	if err != nil {
		return nil, err
	}
	if string(h[:8]) != "BOMStore" || be.Uint32(h[8:]) != 1 {
		return nil, fmt.Errorf("bom: unsupported version")
	}
	index, err := read(uint64(be.Uint32(h[16:])), uint64(be.Uint32(h[20:])))
	if err != nil {
		return nil, err
	}
	if len(index) < 4 {
		return nil, fmt.Errorf("bom: truncated block table")
	}
	count := uint64(be.Uint32(index))
	if count > uint64(len(index)-4)/8 || count > uint64(limit)*8+64 {
		return nil, auto.ErrLimit
	}
	pointers := make([]pointer, int(count))
	for i := range pointers {
		b := index[4+i*8:]
		pointers[i] = pointer{be.Uint32(b), be.Uint32(b[4:])}
	}
	block := func(id uint32, minimum int) ([]byte, error) {
		if id == 0 || uint64(id) >= count || uint64(pointers[id].length) < uint64(minimum) {
			return nil, fmt.Errorf("bom: invalid block reference %d (count=%d, minimum=%d)", id, count, minimum)
		}
		p := pointers[id]
		return read(uint64(p.off), uint64(p.length))
	}
	vars, err := read(uint64(be.Uint32(h[24:])), uint64(be.Uint32(h[28:])))
	if err != nil {
		return nil, err
	}
	if len(vars) < 4 {
		return nil, fmt.Errorf("bom: truncated variables")
	}
	varCount := be.Uint32(vars)
	if varCount > uint32(limit) {
		return nil, auto.ErrLimit
	}
	vars = vars[4:]
	var paths uint32
	seenVars := map[string]bool{}
	for i := uint32(0); i < varCount; i++ {
		if len(vars) < 5 || int(vars[4]) > len(vars)-5 {
			return nil, fmt.Errorf("bom: truncated variable")
		}
		n := int(vars[4])
		name := string(vars[5 : 5+n])
		id := be.Uint32(vars)
		if seenVars[name] {
			return nil, fmt.Errorf("bom: duplicate variable")
		}
		seenVars[name] = true
		if name == "Paths" {
			paths = id
		}
		vars = vars[5+n:]
	}
	if paths == 0 {
		return nil, fmt.Errorf("bom: missing Paths tree")
	}
	tree, err := block(paths, 21)
	if err != nil {
		return nil, err
	}
	if string(tree[:4]) != "tree" || be.Uint32(tree[4:]) != 1 {
		return nil, fmt.Errorf("bom: invalid Paths tree")
	}
	expected := be.Uint32(tree[16:])
	if uint64(expected) > uint64(limit) {
		return nil, auto.ErrLimit
	}
	pending := []uint32{be.Uint32(tree[8:])}
	visited := map[uint32]bool{}
	records := map[uint32]*record{}
	var order []uint32
	var keyCount uint64
	leafLinks := map[uint32][2]uint32{}
	followingLinks := false
	for {
		if len(pending) == 0 {
			// Apple's branch index can omit the final partial leaf. The leaf
			// chain is authoritative; retain branch validation, then follow
			// its missing tails rather than dropping inventory records.
			followingLinks = true
			for _, link := range leafLinks {
				if link[0] != 0 && !visited[link[0]] {
					pending = append(pending, link[0])
				}
			}
			if len(pending) == 0 {
				break
			}
		}
		id := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if visited[id] {
			return nil, fmt.Errorf("bom: cyclic or duplicate tree node")
		}
		visited[id] = true
		if len(visited) > limit {
			return nil, auto.ErrLimit
		}
		b, err := block(id, 12)
		if err != nil {
			return nil, err
		}
		leaf, n := be.Uint16(b), int(be.Uint16(b[2:]))
		if leaf > 1 || n > (len(b)-12)/8 {
			return nil, fmt.Errorf("bom: invalid tree node")
		}
		if followingLinks && leaf != 1 {
			return nil, fmt.Errorf("bom: leaf chain points to branch")
		}
		if leaf == 1 {
			leafLinks[id] = [2]uint32{be.Uint32(b[4:]), be.Uint32(b[8:])}
		}
		keyCount += uint64(n)
		for i := 0; i < n; i++ {
			pair := b[12+i*8:]
			child, key := be.Uint32(pair), be.Uint32(pair[4:])
			if leaf == 0 {
				pending = append(pending, child)
				if len(pending) > limit {
					return nil, auto.ErrLimit
				}
				continue
			}
			info, err := block(child, 8)
			if err != nil {
				return nil, err
			}
			r := &record{id: be.Uint32(info)}
			if records[r.id] != nil || len(records) >= limit {
				return nil, fmt.Errorf("bom: duplicate path ID or entry limit")
			}
			info, err = block(be.Uint32(info[4:]), 23)
			if err != nil {
				return nil, err
			}
			name, err := block(key, 5)
			if err != nil {
				return nil, err
			}
			r.parent = be.Uint32(name)
			end := bytes.IndexByte(name[4:], 0)
			if end < 0 {
				return nil, fmt.Errorf("bom: unterminated path name")
			}
			r.name = string(name[4 : 4+end])
			if r.name == "" || r.name == ".." || strings.ContainsAny(r.name, "/\x00") || !utf8.ValidString(r.name) {
				return nil, fmt.Errorf("bom: unsafe path name")
			}
			a := map[string]any{"bom_id": r.id, "mode": be.Uint16(info[4:]), "uid": be.Uint32(info[6:]), "gid": be.Uint32(info[10:]), "mtime": be.Uint32(info[14:]), "size": be.Uint32(info[18:]), "architecture": be.Uint16(info[2:])}
			r.entry.Attributes = a
			if info[0] != 2 && len(info) < 27 || info[0] == 3 && len(info) < 31 {
				return nil, fmt.Errorf("bom: truncated path metadata")
			}
			switch info[0] {
			case 1:
				r.entry.Kind = "file"
				a["checksum"] = be.Uint32(info[23:])
				a["missing_contents"] = true
			case 2:
				r.entry.Kind = "directory"
			case 3:
				r.entry.Kind = "symlink"
				n := uint64(be.Uint32(info[27:]))
				if n > uint64(len(info)-31) {
					return nil, fmt.Errorf("bom: truncated link target")
				}
				a["target"] = strings.TrimSuffix(string(info[31:31+n]), "\x00")
			case 4:
				r.entry.Kind = "special"
				a["rdev"] = be.Uint32(info[23:])
			default:
				return nil, fmt.Errorf("bom: unsupported path type %d", info[0])
			}
			records[r.id] = r
			order = append(order, r.id)
		}
	}
	// Validate the complete doubly-linked leaf chain, including tails missing
	// from the branch index. Multiple heads and cycles are malformed.
	var head uint32
	for id, link := range leafLinks {
		if link[1] == 0 {
			if head != 0 {
				return nil, fmt.Errorf("bom: multiple leaf chain heads")
			}
			head = id
		} else if back, ok := leafLinks[link[1]]; !ok || back[0] != id {
			return nil, fmt.Errorf("bom: inconsistent leaf backlink")
		}
		if link[0] != 0 {
			if next, ok := leafLinks[link[0]]; !ok || next[1] != id {
				return nil, fmt.Errorf("bom: inconsistent leaf forward link")
			}
		}
	}
	seenLeaves := map[uint32]bool{}
	for id := head; id != 0; id = leafLinks[id][0] {
		if seenLeaves[id] {
			return nil, fmt.Errorf("bom: cyclic leaf chain")
		}
		seenLeaves[id] = true
	}
	if len(seenLeaves) != len(leafLinks) {
		return nil, fmt.Errorf("bom: disconnected leaf chain")
	}
	// Apple also counts internal separator keys in some BOM generations.
	if uint32(len(records)) != expected && keyCount != uint64(expected) {
		return nil, fmt.Errorf("bom: path count mismatch: %d != %d", len(records), expected)
	}
	resolved := map[uint32]string{}
	var resolve func(uint32, map[uint32]bool) (string, error)
	resolve = func(id uint32, seen map[uint32]bool) (string, error) {
		if name, ok := resolved[id]; ok {
			return name, nil
		}
		r := records[id]
		if r == nil || seen[id] {
			return "", fmt.Errorf("bom: missing or cyclic path parent")
		}
		if len(seen) >= 256 {
			return "", auto.ErrLimit
		}
		seen[id] = true
		var name string
		if r.parent == 0 {
			name = r.name
		} else {
			parent := records[r.parent]
			if parent == nil || parent.entry.Kind != "directory" || r.name == "." {
				return "", fmt.Errorf("bom: invalid path parent")
			}
			base, err := resolve(r.parent, seen)
			if err != nil {
				return "", err
			}
			name = path.Join(base, r.name)
		}
		resolved[id] = name
		return name, nil
	}
	var entries []auto.Entry
	for _, id := range order {
		r := records[id]
		name, err := resolve(id, map[uint32]bool{})
		if err != nil {
			return nil, err
		}
		if name == "." {
			if r.entry.Kind != "directory" {
				return nil, fmt.Errorf("bom: invalid root")
			}
		}
		r.entry.Name = name
		entries = append(entries, r.entry)
	}
	return entries, nil
}
