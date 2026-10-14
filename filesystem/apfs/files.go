package apfs

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/tinyrange/trex/compression/decmpfs"
	"github.com/tinyrange/trex/storage"
)

type Entry struct {
	Path, Kind, Target    string
	ID, Parent, PrivateID uint64
	Mode                  uint16
	UID, GID, BSDFlags    uint32
	Size                  uint64
	Data                  storage.Reader
	RawData               storage.Reader
	CompressionType       uint32
	Xattrs                map[string]storage.Reader
	// XattrStreams identifies nonresident attribute streams. Embedded
	// attributes have no separate stream object and are absent from this map.
	XattrStreams map[string]uint64
}

type inode struct {
	entry Entry
}
type directoryEntry struct {
	parent, id uint64
	name       string
}
type extent struct{ logical, length, physical uint64 }
type attribute struct {
	id           uint64
	name         string
	data         []byte
	stream, size uint64
}

func name(b []byte) (string, error) {
	if len(b) == 0 || b[len(b)-1] != 0 || bytes.IndexByte(b[:len(b)-1], 0) >= 0 || !utf8.Valid(b[:len(b)-1]) {
		return "", fmt.Errorf("apfs: invalid terminated UTF-8 name")
	}
	return string(b[:len(b)-1]), nil
}

// Entries reconstructs the live directory tree and borrowed data streams of an
// unencrypted volume. Symbolic links remain entries and are never followed.
func (v *Volume) Entries(raw bool) ([]Entry, error) {
	if v.Flags&1 == 0 {
		return nil, fmt.Errorf("apfs: encrypted volume unsupported")
	}
	if v.Incompatible & ^uint64(0x3b) != 0 || (v.Incompatible&0x20 == 0 && (v.ExtentTree != 0 || v.Integrity != 0)) {
		return nil, fmt.Errorf("apfs: unsupported volume layout/features %x", v.Incompatible)
	}
	root, err := v.rootAddress(v.RootTree, v.RootTreeType)
	if err != nil {
		return nil, err
	}
	inodes := map[uint64]*inode{}
	directories := map[uint64][]directoryEntry{}
	extents := map[uint64][]extent{}
	attributes := []attribute{}
	resolver := func(id uint64) (uint64, error) { return v.rootAddress(id, v.RootTreeType) }
	var sealHash []byte
	var hashType uint32
	if v.Incompatible&0x20 != 0 {
		s, err := v.SealInformation()
		if err != nil {
			return nil, err
		}
		if s.Flags != 0 {
			return nil, fmt.Errorf("apfs: volume seal is broken")
		}
		sealHash, hashType = s.RootHash, s.HashType
		resolver = v.sealedResolver(s)
	}
	err = v.container.walkTreeHash(root, resolver, hashType, sealHash, func(k, b []byte) error {
		if len(k) < 8 {
			return fmt.Errorf("apfs: truncated filesystem key")
		}
		header := le.Uint64(k)
		id, kind := header&0x0fffffffffffffff, header>>60
		switch kind {
		case 3: // inode
			if len(k) != 8 || len(b) < 92 || inodes[id] != nil {
				return fmt.Errorf("apfs: invalid/duplicate inode")
			}
			e := Entry{ID: id, Parent: le.Uint64(b), PrivateID: le.Uint64(b[8:]), Mode: le.Uint16(b[80:]), UID: le.Uint32(b[72:]), GID: le.Uint32(b[76:]), BSDFlags: le.Uint32(b[68:]), Xattrs: map[string]storage.Reader{}}
			switch e.Mode & 0xf000 {
			case 0x4000:
				e.Kind = "directory"
			case 0x8000:
				e.Kind = "file"
			case 0xa000:
				e.Kind = "symlink"
			default:
				e.Kind = "special"
			}
			n := &inode{entry: e}
			if len(b) > 92 {
				x := b[92:]
				if len(x) < 4 {
					return fmt.Errorf("apfs: truncated inode fields")
				}
				count := int(le.Uint16(x))
				if count > (len(x)-4)/4 {
					return fmt.Errorf("apfs: invalid inode field table")
				}
				pos := 4 + count*4
				seen := map[byte]bool{}
				for i := 0; i < count; i++ {
					field := x[4+i*4:]
					size := int(le.Uint16(field[2:]))
					if seen[field[0]] || pos > len(x)-size {
						return fmt.Errorf("apfs: invalid inode extended field")
					}
					seen[field[0]] = true
					if field[0] == 8 {
						if size != 40 {
							return fmt.Errorf("apfs: invalid inode data stream")
						}
						n.entry.Size = le.Uint64(x[pos:])
					}
					pos += (size + 7) &^ 7
				}
			}
			inodes[id] = n
		case 9: // directory record
			if len(k) < 10 || len(b) < 18 {
				return fmt.Errorf("apfs: truncated directory record")
			}
			start, length := 10, int(le.Uint16(k[8:]))
			if v.Incompatible&9 != 0 {
				if len(k) < 12 {
					return fmt.Errorf("apfs: truncated hashed directory key")
				}
				start, length = 12, int(le.Uint32(k[8:])&1023)
			}
			if length != len(k)-start {
				return fmt.Errorf("apfs: invalid directory name extent")
			}
			text, err := name(k[start:])
			if err != nil {
				return err
			}
			if text == "" || text == "." || text == ".." || strings.Contains(text, "/") {
				return fmt.Errorf("apfs: invalid directory component")
			}
			directories[id] = append(directories[id], directoryEntry{id, le.Uint64(b), text})
		case 8: // file extent
			if len(k) != 16 || len(b) != 24 {
				return fmt.Errorf("apfs: invalid file extent")
			}
			packed := le.Uint64(b)
			if packed>>56 != 0 {
				return fmt.Errorf("apfs: unsupported extent flags")
			}
			e := extent{le.Uint64(k[8:]), packed & 0x00ffffffffffffff, le.Uint64(b[8:])}
			if e.length == 0 || e.logical > math.MaxInt64-e.length {
				return fmt.Errorf("apfs: invalid logical extent")
			}
			extents[id] = append(extents[id], e)
		case 4: // extended attribute
			if len(k) < 10 || int(le.Uint16(k[8:])) != len(k)-10 || len(b) < 4 {
				return fmt.Errorf("apfs: invalid xattr record")
			}
			text, err := name(k[10:])
			if err != nil {
				return err
			}
			a := attribute{id: id, name: text}
			switch le.Uint16(b) & 3 {
			case 2:
				if int(le.Uint16(b[2:])) != len(b)-4 {
					return fmt.Errorf("apfs: invalid embedded xattr")
				}
				a.data = append([]byte(nil), b[4:]...)
			case 1:
				if len(b) != 52 {
					return fmt.Errorf("apfs: invalid xattr stream")
				}
				a.stream, a.size = le.Uint64(b[4:]), le.Uint64(b[12:])
			default:
				return fmt.Errorf("apfs: unsupported xattr storage")
			}
			attributes = append(attributes, a)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if v.ExtentTree != 0 {
		address, err := v.rootAddress(v.ExtentTree, v.ExtentTreeType)
		if err != nil {
			return nil, err
		}
		err = v.container.walkTree(address, func(id uint64) (uint64, error) { return v.rootAddress(id, v.ExtentTreeType) }, func(k, b []byte) error {
			if len(k) != 16 || len(b) != 16 || le.Uint64(b)>>56 != 0 {
				return fmt.Errorf("apfs: invalid sealed file extent")
			}
			id := le.Uint64(k)
			extents[id] = append(extents[id], extent{le.Uint64(k[8:]), le.Uint64(b), le.Uint64(b[8:])})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	for id, items := range extents {
		sort.Slice(items, func(i, j int) bool { return items[i].logical < items[j].logical })
		var end uint64
		for _, e := range items {
			if e.logical < end || e.length > math.MaxInt64 || e.logical > math.MaxInt64-e.length {
				return nil, fmt.Errorf("apfs: overlapping/wrapping extents for %d", id)
			}
			end = e.logical + e.length
			if e.physical != 0 && (e.physical >= v.container.Blocks || (e.length+uint64(v.container.BlockSize)-1)/uint64(v.container.BlockSize) > v.container.Blocks-e.physical) {
				return nil, fmt.Errorf("apfs: data extent exceeds container")
			}
		}
	}
	for _, a := range attributes {
		n := inodes[a.id]
		if n == nil {
			return nil, fmt.Errorf("apfs: xattr without inode")
		}
		if _, ok := n.entry.Xattrs[a.name]; ok {
			return nil, fmt.Errorf("apfs: duplicate xattr")
		}
		var data storage.Reader = bytes.NewReader(a.data)
		if a.stream != 0 {
			if a.size > math.MaxInt64 {
				return nil, fmt.Errorf("apfs: oversized xattr")
			}
			data = &stream{v.container, int64(a.size), extents[a.stream]}
			if n.entry.XattrStreams == nil {
				n.entry.XattrStreams = map[string]uint64{}
			}
			n.entry.XattrStreams[a.name] = a.stream
		}
		n.entry.Xattrs[a.name] = data
	}
	for _, n := range inodes {
		e := &n.entry
		if e.Size > math.MaxInt64 {
			return nil, fmt.Errorf("apfs: oversized file")
		}
		if e.Kind == "file" {
			e.Data = &stream{v.container, int64(e.Size), extents[e.PrivateID]}
		}
		if e.Kind == "symlink" {
			a := e.Xattrs["com.apple.fs.symlink"]
			if a == nil || a.Size() > 65536 {
				return nil, fmt.Errorf("apfs: invalid symlink target")
			}
			b, err := io.ReadAll(io.NewSectionReader(a, 0, a.Size()))
			if err != nil {
				return nil, err
			}
			e.Target = strings.TrimRight(string(b), "\x00")
		}
		if e.BSDFlags&0x20 != 0 {
			a := e.Xattrs["com.apple.decmpfs"]
			if a == nil || a.Size() < 16 {
				return nil, fmt.Errorf("apfs: compressed inode lacks decmpfs header")
			}
			var h [16]byte
			if _, err := a.ReadAt(h[:], 0); err != nil {
				return nil, err
			}
			if string(h[:4]) != "fpmc" {
				return nil, fmt.Errorf("apfs: invalid decmpfs signature")
			}
			e.CompressionType = le.Uint32(h[4:])
			e.Size = le.Uint64(h[8:])
			e.RawData = e.Data
			e.Data = nil
			if !raw {
				decoded, kind, err := decmpfs.Open(a, e.Xattrs["com.apple.ResourceFork"])
				if err != nil {
					return nil, fmt.Errorf("apfs: inode %d: %w", e.ID, err)
				}
				e.Data, e.CompressionType, e.Size = decoded, kind, uint64(decoded.Size())
			}
		}
	}
	if inodes[2] == nil || inodes[2].entry.Kind != "directory" {
		return nil, fmt.Errorf("apfs: root inode missing")
	}
	result := []Entry{}
	seen := map[uint64]bool{}
	var walk func(uint64, string, int) error
	walk = func(id uint64, path string, depth int) error {
		if depth > 64 || len(result) >= 1000000 {
			return fmt.Errorf("apfs: directory depth/entry limit")
		}
		n := inodes[id]
		if n == nil {
			return fmt.Errorf("apfs: directory references missing inode %d", id)
		}
		e := n.entry
		e.Path = path
		result = append(result, e)
		if e.Kind != "directory" {
			return nil
		}
		if seen[id] {
			return fmt.Errorf("apfs: repeated directory inode")
		}
		seen[id] = true
		children := directories[id]
		sort.Slice(children, func(i, j int) bool { return children[i].name < children[j].name })
		previous := ""
		for _, child := range children {
			if child.name == previous {
				return fmt.Errorf("apfs: duplicate directory name")
			}
			previous = child.name
			if err := walk(child.id, strings.TrimSuffix(path, "/")+"/"+child.name, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(2, "/", 0); err != nil {
		return nil, err
	}
	return result, nil
}

type stream struct {
	container *Container
	size      int64
	extents   []extent
}

func (f *stream) Size() int64 { return f.size }
func (f *stream) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("apfs: negative stream offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= f.size {
		return 0, io.EOF
	}
	wanted := len(p)
	done := 0
	for len(p) > 0 && off < f.size {
		i := sort.Search(len(f.extents), func(i int) bool { return f.extents[i].logical+f.extents[i].length > uint64(off) })
		count := min(int64(len(p)), f.size-off)
		physical := uint64(0)
		if i < len(f.extents) {
			e := f.extents[i]
			if uint64(off) < e.logical {
				count = min(count, int64(e.logical)-off)
			} else {
				count = min(count, int64(e.logical+e.length)-off)
				if e.physical != 0 {
					physical = e.physical*uint64(f.container.BlockSize) + uint64(off) - e.logical
				}
			}
		}
		if physical == 0 {
			clear(p[:count])
		} else {
			n, err := f.container.Source.ReadAt(p[:count], int64(physical))
			done += n
			if err != nil {
				return done, err
			}
			if n != int(count) {
				return done, io.ErrUnexpectedEOF
			}
			p = p[count:]
			off += count
			continue
		}
		done += int(count)
		p = p[count:]
		off += count
	}
	if done < wanted {
		return done, io.EOF
	}
	return done, nil
}
