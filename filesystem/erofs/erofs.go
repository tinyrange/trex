// Package erofs reads EROFS through portable byte sources. On-disk facts follow
// Linux fs/erofs/erofs_fs.h; no mount, extraction or host tools are involved.
package erofs

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"sort"
	"strings"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
	bytecache "github.com/tinyrange/trex/storage/cache"
)

var le = binary.LittleEndian

func init() { auto.Register("erofs", 30, Open) }

type image struct {
	source                        storage.Reader
	used, meta, inodes, buildTime uint64
	block                         uint64
	bits                          uint8
	compat, incompat              uint32
	algorithms                    uint16
	buildNsec                     uint32
	root                          uint64
	uuid, label                   string
	raw, decoded                  *bytecache.Cache
	options                       auto.Options
}
type inode struct {
	fs                              *image
	nid, pos, size, tail, mtime     uint64
	mode                            uint16
	uid, gid, links, nsec, rawBlock uint32
	layout                          uint8
	xattrs                          uint16
}
type directory struct {
	node    *inode
	parents []uint64
}

// Open supports compact/extended inodes, flat and inline data, and full/compact
// LZ4 compression indexes including 2-byte packs and big physical clusters.
// Unsupported incompatible filesystem features are rejected explicitly.
func Open(prefix []byte, source storage.Reader, options auto.Options) (auto.View, error) {
	if len(prefix) < 1028 || le.Uint32(prefix[1024:]) != 0xe0f5e1e2 {
		return nil, auto.ErrNoMatch
	}
	if source == nil || source.Size() < 1152 {
		return nil, fmt.Errorf("erofs: truncated superblock")
	}
	h := make([]byte, 128)
	if _, err := io.ReadFull(io.NewSectionReader(source, 1024, 128), h); err != nil {
		return nil, err
	}
	s := &image{source: source, bits: h[12], compat: le.Uint32(h[8:]), incompat: le.Uint32(h[80:]), root: uint64(le.Uint16(h[14:])), inodes: le.Uint64(h[16:]), buildTime: le.Uint64(h[24:]), uuid: hex.EncodeToString(h[48:64]), label: strings.TrimRight(string(h[64:80]), "\x00"), raw: bytecache.New(32 << 20), decoded: bytecache.New(32 << 20), options: options}
	s.buildNsec = le.Uint32(h[32:])
	if s.options.MaxEntries <= 0 {
		s.options.MaxEntries = 100000
	}
	if s.options.MaxDepth <= 0 {
		s.options.MaxDepth = 32
	}
	if s.bits < 9 || s.bits > 16 || s.inodes == 0 || s.inodes > math.MaxInt64 || s.buildNsec >= 1000000000 {
		return nil, fmt.Errorf("erofs: invalid superblock geometry")
	}
	s.block = uint64(1) << s.bits
	s.used = uint64(le.Uint32(h[36:])) * s.block
	s.meta = uint64(le.Uint32(h[40:])) * s.block
	if s.used < 1152 || s.used > uint64(source.Size()) || s.meta >= s.used || uint64(128)+uint64(h[13])*16 > s.used-1024 {
		return nil, fmt.Errorf("erofs: invalid filesystem size or metadata address")
	}
	if s.incompat & ^uint32(3) != 0 || le.Uint16(h[86:]) != 0 || h[90] != 0 {
		return nil, fmt.Errorf("erofs: unsupported incompatible features %#x, device table or directory block size", s.incompat)
	}
	s.algorithms = 1
	if s.incompat&2 != 0 {
		s.algorithms = le.Uint16(h[84:])
		if s.algorithms & ^uint16(1) != 0 {
			return nil, fmt.Errorf("erofs: unsupported compression algorithms %#x", s.algorithms)
		}
		pos := uint64(1152) + uint64(h[13])*16
		if s.algorithms&1 != 0 {
			cfg, err := s.read(pos, 2)
			if err != nil {
				return nil, err
			}
			n := uint64(le.Uint16(cfg))
			if n == 0 {
				n = 65536
			}
			if n < 14 {
				return nil, fmt.Errorf("erofs: truncated LZ4 configuration")
			}
			cfg, err = s.read(pos+2, n)
			if err != nil {
				return nil, err
			}
			maxBlocks := le.Uint16(cfg[2:])
			if maxBlocks == 0 || uint64(maxBlocks)*s.block > 1<<20 {
				return nil, fmt.Errorf("erofs: invalid LZ4 physical cluster limit")
			}
		}
	}
	if s.compat&1 != 0 {
		n := s.block
		if n > 1024 {
			n -= 1024
		}
		b, err := s.read(1024, n)
		if err != nil {
			return nil, err
		}
		want := le.Uint32(b[4:])
		clear(b[4:8])
		if ^crc32.Checksum(b, crc32.MakeTable(crc32.Castagnoli)) != want {
			return nil, fmt.Errorf("erofs: superblock checksum mismatch")
		}
	}
	root, err := s.inode(s.root)
	if err != nil {
		return nil, err
	}
	if root.mode&0170000 != 0040000 {
		return nil, fmt.Errorf("erofs: root is not a directory")
	}
	return &directory{node: root}, nil
}

func (s *image) read(off, n uint64) ([]byte, error) {
	if off > s.used || n > s.used-off || n > 12<<20 {
		return nil, fmt.Errorf("erofs: byte range outside filesystem")
	}
	b := make([]byte, int(n))
	for done := 0; done < len(b); {
		at := off + uint64(done)
		start := at / s.block * s.block
		page, err := s.raw.Get(bytecache.Key{Offset: int64(start)}, func() ([]byte, error) {
			p := make([]byte, int(min(s.block, s.used-start)))
			_, err := io.ReadFull(io.NewSectionReader(s.source, int64(start), int64(len(p))), p)
			return p, err
		})
		if err != nil {
			return nil, err
		}
		done += copy(b[done:], page[at-start:])
	}
	return b, nil
}

func (s *image) inode(nid uint64) (*inode, error) {
	if nid > (s.used-s.meta)/32 || s.used-s.meta-nid*32 < 32 {
		return nil, fmt.Errorf("erofs: inode address outside filesystem")
	}
	pos := s.meta + nid*32
	h, err := s.read(pos, 32)
	if err != nil {
		return nil, err
	}
	format := le.Uint16(h)
	layout := uint8(format >> 1 & 7)
	if format & ^uint16(31) != 0 || layout > 3 {
		return nil, fmt.Errorf("erofs: unsupported inode format %#x at nid %d", format, nid)
	}
	n := &inode{fs: s, nid: nid, pos: pos, mode: le.Uint16(h[4:]), layout: layout, xattrs: le.Uint16(h[2:]), rawBlock: le.Uint32(h[16:])}
	isize := uint64(32)
	if format&1 != 0 {
		h, err = s.read(pos, 64)
		if err != nil {
			return nil, err
		}
		isize = 64
		n.size = le.Uint64(h[8:])
		n.uid = le.Uint32(h[24:])
		n.gid = le.Uint32(h[28:])
		n.mtime = le.Uint64(h[32:])
		n.nsec = le.Uint32(h[40:])
		n.links = le.Uint32(h[44:])
	} else {
		n.size = uint64(le.Uint32(h[8:]))
		n.uid = uint32(le.Uint16(h[24:]))
		n.gid = uint32(le.Uint16(h[26:]))
		n.links = uint32(le.Uint16(h[6:]))
		n.mtime = s.buildTime
		n.nsec = s.buildNsec
	}
	if format&1 == 0 && format&16 != 0 && n.mode&0170000 != 0040000 {
		n.links = 1
	}
	if format&1 == 0 && s.compat&2 != 0 {
		n.mtime += uint64(le.Uint32(h[12:]))
	}
	if n.size > math.MaxInt64 || n.nsec >= 1000000000 {
		return nil, fmt.Errorf("erofs: invalid inode size or time")
	}
	xsize := uint64(0)
	if n.xattrs != 0 {
		xsize = 12 + uint64(n.xattrs-1)*4
	}
	n.tail = pos + isize + xsize
	if n.tail > s.used {
		return nil, fmt.Errorf("erofs: xattrs exceed filesystem")
	}
	if layout == 0 || layout == 2 {
		length := n.size
		if layout == 2 && n.size > 0 {
			tail := n.size % s.block
			if tail == 0 {
				tail = s.block
			}
			length -= tail
			if n.tail%s.block+tail > s.block {
				return nil, fmt.Errorf("erofs: inline data crosses metadata block")
			}
		}
		if length > 0 && (uint64(n.rawBlock)*s.block > s.used || length > s.used-uint64(n.rawBlock)*s.block) {
			return nil, fmt.Errorf("erofs: flat extent exceeds filesystem")
		}
	}
	return n, nil
}

func (d *directory) Description() (string, map[string]any) {
	s := d.node.fs
	return "erofs", map[string]any{"block_size": s.block, "filesystem_bytes": s.used, "inode_count": s.inodes, "root_nid": s.root, "uuid": s.uuid, "volume_name": s.label, "feature_compat": s.compat, "feature_incompat": s.incompat, "compression_algorithms": s.algorithms}
}
func (n *inode) attributes() map[string]any {
	return map[string]any{"nid": n.nid, "inode_offset": n.pos, "mode": n.mode, "uid": n.uid, "gid": n.gid, "links": n.links, "mtime": n.mtime, "mtime_nsec": n.nsec, "data_layout": n.layout, "xattr_icount": n.xattrs}
}
func (d *directory) Entries() ([]auto.Entry, error) {
	n, s := d.node, d.node.fs
	if len(d.parents) >= s.options.MaxDepth {
		return nil, auto.ErrLimit
	}
	for _, p := range d.parents {
		if p == n.nid {
			return nil, fmt.Errorf("erofs: directory cycle")
		}
	}
	if n.size > uint64(s.options.MaxEntries)*267 {
		return nil, auto.ErrLimit
	}
	parents := append(append([]uint64(nil), d.parents...), n.nid)
	type record struct {
		name string
		id   uint64
		kind byte
	}
	var records []record
	seen := map[string]bool{}
	for off := uint64(0); off < n.size; off += s.block {
		b := make([]byte, int(min(s.block, n.size-off)))
		if _, err := n.ReadAt(b, int64(off)); err != nil {
			return nil, err
		}
		if len(b) < 12 {
			return nil, fmt.Errorf("erofs: truncated directory block")
		}
		first := int(le.Uint16(b[8:]))
		if first < 12 || first%12 != 0 || first > len(b) {
			return nil, fmt.Errorf("erofs: invalid directory name area")
		}
		for pos := 0; pos < first; pos += 12 {
			row := b[pos : pos+12]
			start := int(le.Uint16(row[8:]))
			end := len(b)
			if pos+12 < first {
				end = int(le.Uint16(b[pos+20:]))
			}
			if start < first || end <= start || end > len(b) || row[11] != 0 {
				return nil, fmt.Errorf("erofs: invalid directory name bounds")
			}
			name := string(b[start:end])
			if pos+12 == first {
				name = strings.TrimRight(name, "\x00")
			}
			if name == "" || len(name) > 255 || strings.ContainsAny(name, "/\x00") || seen[name] {
				return nil, fmt.Errorf("erofs: invalid or duplicate directory name")
			}
			seen[name] = true
			id := le.Uint64(row)
			if name == "." {
				if id != n.nid {
					return nil, fmt.Errorf("erofs: invalid dot entry")
				}
				continue
			}
			if name == ".." {
				parent := n.nid
				if len(d.parents) > 0 {
					parent = d.parents[len(d.parents)-1]
				}
				if id != parent {
					return nil, fmt.Errorf("erofs: invalid dotdot entry")
				}
				continue
			}
			records = append(records, record{name, id, row[10]})
			if len(records) > s.options.MaxEntries {
				return nil, auto.ErrLimit
			}
		}
	}
	// Inodes need not be near the directory or appear in name order. Load them
	// in physical order, preserving directory order in the returned entries.
	// This also avoids repeated decompression on streaming archive sources.
	ids := make([]uint64, 0, len(records))
	for _, r := range records {
		ids = append(ids, r.id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	inodes := make(map[uint64]*inode, len(ids))
	for _, id := range ids {
		if inodes[id] != nil {
			continue
		}
		child, err := s.inode(id)
		if err != nil {
			return nil, err
		}
		inodes[id] = child
	}
	out := make([]auto.Entry, 0, len(records))
	for _, r := range records {
		child := inodes[r.id]
		e := auto.Entry{Name: r.name, Attributes: child.attributes()}
		typeCode := byte(0)
		switch child.mode & 0170000 {
		case 0040000:
			e.Kind = "directory"
			e.View = &directory{child, parents}
			typeCode = 2
		case 0100000:
			e.Kind = "file"
			e.Reader = child
			typeCode = 1
		case 0120000:
			e.Kind = "symlink"
			typeCode = 7
			if child.size > 4096 {
				return nil, fmt.Errorf("erofs: oversized symlink")
			}
			b := make([]byte, int(child.size))
			if _, err := child.ReadAt(b, 0); err != nil {
				return nil, err
			}
			e.Attributes["target"] = string(b)
		case 0020000:
			e.Kind = "device"
			typeCode = 3
			e.Attributes["device"] = child.rawBlock
		case 0060000:
			e.Kind = "device"
			typeCode = 4
			e.Attributes["device"] = child.rawBlock
		case 0010000:
			e.Kind = "fifo"
			typeCode = 5
		case 0140000:
			e.Kind = "socket"
			typeCode = 6
		default:
			return nil, fmt.Errorf("erofs: invalid inode mode")
		}
		if r.kind != 0 && r.kind != typeCode {
			return nil, fmt.Errorf("erofs: directory/inode type mismatch")
		}
		out = append(out, e)
	}
	return out, nil
}

func (n *inode) Size() int64 { return int64(n.size) }
func (n *inode) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("erofs: negative offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if uint64(off) >= n.size {
		return 0, io.EOF
	}
	want := len(p)
	p = p[:min(uint64(len(p)), n.size-uint64(off))]
	done := 0
	for len(p) > 0 {
		at := uint64(off) + uint64(done)
		var b []byte
		var err error
		if n.layout == 0 || n.layout == 2 {
			end := n.size
			pa := uint64(n.rawBlock)*n.fs.block + at
			if n.layout == 2 {
				base := uint64(0)
				if n.size > 0 {
					base = (n.size - 1) / n.fs.block * n.fs.block
				}
				if at >= base {
					pa = n.tail + at - base
				} else {
					end = base
				}
			}
			b, err = n.fs.read(pa, min(uint64(len(p)), min(end-at, 1<<20)))
		} else {
			b, err = n.compressed(at)
		}
		if err != nil {
			return done, fmt.Errorf("erofs: nid %d at %d: %w", n.nid, at, err)
		}
		if len(b) == 0 {
			return done, io.ErrNoProgress
		}
		count := copy(p, b)
		done += count
		p = p[count:]
	}
	if done < want {
		return done, io.EOF
	}
	return done, nil
}
