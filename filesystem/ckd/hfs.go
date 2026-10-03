package ckd

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
)

// HFS reads z/OS IGW HFS, not Macintosh HFS or zFS/Episode. File bytes and
// link targets retain their on-disk encoding. Names in the browser use the
// invariant EBCDIC alphabet and reversible %XX escapes for other bytes.
type HFS struct {
	igw   *IGW
	attrs map[[20]byte][]byte
	limit int
}

type HFSInode struct {
	Object        [6]byte
	Kind          string
	Size          uint64
	Number, Links uint32
	Raw           []byte
}
type HFSName struct {
	Name   []byte // Exact EBCDIC bytes, without directory padding.
	Object [6]byte
}

func igwKey(namespace uint64, object [6]byte, kind uint16) [20]byte {
	var k [20]byte
	for i := 5; i >= 0; i-- {
		k[i] = byte(namespace)
		namespace >>= 8
	}
	copy(k[6:12], object[:])
	be.PutUint16(k[14:], kind)
	return k
}

var hfsRoot = [6]byte{0, 0, 0, 0, 0, 3}

func OpenHFS(source storage.Reader, limit int) (*HFS, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("HFS: invalid entry limit")
	}
	g, err := OpenIGW(source)
	if err != nil {
		return nil, err
	}
	rows, err := g.Attributes(1000000)
	if err != nil {
		return nil, err
	}
	h := &HFS{igw: g, attrs: map[[20]byte][]byte{}, limit: limit}
	for _, c := range rows {
		// D5 and EC are observed on inode attributes. Do not discard these
		// cells as tombstones: namespace/name links establish reachability,
		// and Inode independently validates the value layout.
		if c.Flags != 0xc0 && !((c.Flags == 0xd5 || c.Flags == 0xec) && be.Uint16(c.Key[14:]) == 0x9001) {
			return nil, fmt.Errorf("HFS: unsupported attribute flags")
		}
		if _, ok := h.attrs[c.Key]; ok {
			return nil, fmt.Errorf("HFS: duplicate attribute")
		}
		h.attrs[c.Key] = c.Value
	}
	inode, err := h.Inode(hfsRoot)
	if err != nil {
		return nil, err
	}
	if inode.Kind != "directory" {
		return nil, fmt.Errorf("HFS: invalid root")
	}
	return h, nil
}
func (h *HFS) attr(object [6]byte, kind uint16) []byte { return h.attrs[igwKey(3, object, kind)] }
func (h *HFS) Inode(object [6]byte) (*HFSInode, error) {
	b := h.attr(object, 0x9001)
	if len(b) != 216 || !bytes.Equal(b[:8], []byte{0xc9, 0xc7, 0xe6, 0xd7, 0xc6, 0xc1, 0xd9, 0x40}) || be.Uint32(b[8:]) != 216 || b[12] != 1 || !bytes.Equal(b[60:64], []byte{0xc9, 0xc6, 0xe2, 0xd7}) || b[64] != 1 {
		return nil, fmt.Errorf("HFS: missing or unsupported inode %x", object)
	}
	kind := ""
	switch b[124] {
	case 1:
		kind = "directory"
	case 2:
		kind = "character-device"
	case 3:
		kind = "file"
	case 4:
		kind = "fifo"
	case 5:
		kind = "symlink"
	case 6:
		kind = "block-device"
	case 7:
		kind = "socket"
	default:
		return nil, fmt.Errorf("HFS: unsupported inode type %d", b[124])
	}
	return &HFSInode{object, kind, be.Uint64(b[20:]), be.Uint32(b[52:]), be.Uint32(b[56:]), bytes.Clone(b)}, nil
}
func (h *HFS) Directory(object [6]byte) ([]HFSName, error) {
	inode, err := h.Inode(object)
	if err != nil {
		return nil, err
	}
	if inode.Kind != "directory" {
		return nil, fmt.Errorf("HFS: not a directory")
	}
	d := h.attr(object, 0x4002)
	if len(d) != 64 || d[0] != 1 {
		return nil, fmt.Errorf("HFS: invalid name descriptor")
	}
	a, err := h.igw.objectAllocation(h.attrs, 3, object, false)
	if err != nil {
		return nil, err
	}
	cells, err := readNameDirectory(a, d, 255, 1000000)
	if err != nil {
		return nil, err
	}
	out := []HFSName{}
	seen := map[string]bool{}
	dot, dotdot := false, false
	for _, c := range cells {
		if len(c.Value) != 20 {
			return nil, fmt.Errorf("HFS: invalid name reference")
		}
		n := int(be.Uint16(c.Value[14:]))
		if n < 1 || n > 255 || !bytes.Equal(c.Name[n:], bytes.Repeat([]byte{0x40}, 255-n)) {
			return nil, fmt.Errorf("HFS: invalid name length")
		}
		name := c.Name[:n]
		if bytes.IndexByte(name, 0) >= 0 || bytes.IndexByte(name, 0x61) >= 0 || seen[string(name)] {
			return nil, fmt.Errorf("HFS: invalid or duplicate name")
		}
		seen[string(name)] = true
		var child [6]byte
		copy(child[:], c.Value[6:12])
		switch string(name) {
		case "\x4b":
			if child != object {
				return nil, fmt.Errorf("HFS: invalid self link")
			}
			dot = true
			continue
		case "\x4b\x4b":
			dotdot = true
			continue
		}
		if len(out) >= h.limit {
			return nil, fmt.Errorf("HFS: directory limit exceeded")
		}
		if _, err := h.Inode(child); err != nil {
			return nil, err
		}
		out = append(out, HFSName{bytes.Clone(name), child})
	}
	if !dot || !dotdot {
		return nil, fmt.Errorf("HFS: missing dot entries")
	}
	return out, nil
}
func (h *HFS) File(object [6]byte) (storage.Reader, error) {
	i, err := h.Inode(object)
	if err != nil {
		return nil, err
	}
	if i.Kind != "file" {
		return nil, fmt.Errorf("HFS: not a regular file")
	}
	if i.Size == 0 {
		return raw(nil), nil
	}
	a, err := h.igw.objectAllocation(h.attrs, 3, object, false)
	if err != nil {
		return nil, err
	}
	if i.Size > uint64(a.Size()) {
		return nil, fmt.Errorf("HFS: unsupported sparse file or short allocation")
	}
	return &Content{source: a, size: int64(i.Size), spans: []span{{0, int64(i.Size), 0}}}, nil
}
func (h *HFS) Link(object [6]byte) ([]byte, error) {
	i, err := h.Inode(object)
	if err != nil {
		return nil, err
	}
	if i.Kind != "symlink" {
		return nil, fmt.Errorf("HFS: not a symbolic link")
	}
	b := h.attr(object, 0x9005)
	if len(b) < 6 || b[0] != 1 || b[1] != 0 || uint64(be.Uint32(b[2:])) != i.Size || uint64(len(b)-6) != i.Size || bytes.IndexByte(b[6:], 0) >= 0 {
		return nil, fmt.Errorf("HFS: unsupported link storage")
	}
	return bytes.Clone(b[6:]), nil
}

// HFSDisplayName is lossless for arbitrary filename bytes: literal percent is
// escaped too. Unlike dataset identifiers, trailing spaces are significant.
func HFSDisplayName(b []byte) string {
	var s strings.Builder
	for _, c := range b {
		if c == 0x61 {
			s.WriteByte('/')
		} else if c == 0x40 {
			s.WriteByte(' ')
		} else {
			s.WriteString(Identifier([]byte{c}))
		}
	}
	return s.String()
}
func (h *HFS) View() auto.View { return h.directoryView(hfsRoot, nil) }
func (h *HFS) directoryView(object [6]byte, ancestors [][6]byte) auto.View {
	return auto.ViewFunc(func() ([]auto.Entry, error) {
		if len(ancestors) >= 256 {
			return nil, fmt.Errorf("HFS: depth limit exceeded")
		}
		for _, id := range ancestors {
			if id == object {
				return nil, fmt.Errorf("HFS: directory cycle")
			}
		}
		chain := append(append([][6]byte(nil), ancestors...), object)
		names, err := h.Directory(object)
		if err != nil {
			return nil, err
		}
		entries := make([]auto.Entry, 0, len(names))
		for _, n := range names {
			i, err := h.Inode(n.Object)
			if err != nil {
				return nil, err
			}
			e := auto.Entry{Name: HFSDisplayName(n.Name), Kind: i.Kind, Attributes: map[string]any{"object": hex.EncodeToString(n.Object[:]), "name_ebcdic": hex.EncodeToString(n.Name), "inode": i.Number, "links": i.Links, "size": i.Size}}
			switch i.Kind {
			case "directory":
				e.View = h.directoryView(n.Object, chain)
			case "file":
				e.Reader, err = h.File(n.Object)
			case "symlink":
				var target []byte
				target, err = h.Link(n.Object)
				e.Attributes["link"] = HFSDisplayName(target)
				e.Attributes["link_ebcdic"] = hex.EncodeToString(target)
			}
			if err != nil {
				return nil, err
			}
			entries = append(entries, e)
		}
		return entries, nil
	})
}
