// Package squashfs reads version 4 filesystems through portable byte sources.
// Payloads are lazy, with a bounded shared cache of decoded blocks.
package squashfs

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/tinyrange/trex/archive/xz"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
	bytecache "github.com/tinyrange/trex/storage/cache"
	starfile "github.com/tinyrange/trex/storage/star"
)

var le = binary.LittleEndian

func init() { auto.Register("squashfs", 30, Open) }

type image struct {
	source                                                 storage.Reader
	used, inodesTable, dirsTable, idsTable, fragmentsTable uint64
	blockSize, fragmentCount, inodeCount                   uint32
	codec, idCount                                         uint16
	cache                                                  *bytecache.Cache
	options                                                auto.Options
}

// Open supports SquashFS 4.0 with zlib, XZ and Zstandard compression.
// Symlinks/devices remain metadata; xattr identifiers are retained, not decoded.
func Open(prefix []byte, source storage.Reader, o auto.Options) (auto.View, error) {
	if !bytes.HasPrefix(prefix, []byte("hsqs")) {
		return nil, auto.ErrNoMatch
	}
	h := make([]byte, 96)
	if _, err := io.ReadFull(io.NewSectionReader(source, 0, 96), h); err != nil {
		return nil, err
	}
	if le.Uint16(h[28:]) != 4 || le.Uint16(h[30:]) != 0 {
		return nil, fmt.Errorf("squashfs: unsupported version")
	}
	s := &image{source: source, used: le.Uint64(h[40:]), inodeCount: le.Uint32(h[4:]), blockSize: le.Uint32(h[12:]), fragmentCount: le.Uint32(h[16:]), codec: le.Uint16(h[20:]), idCount: le.Uint16(h[26:]), idsTable: le.Uint64(h[48:]), inodesTable: le.Uint64(h[64:]), dirsTable: le.Uint64(h[72:]), fragmentsTable: le.Uint64(h[80:]), cache: bytecache.New(64 << 20), options: o}
	if s.options.MaxEntries <= 0 {
		s.options.MaxEntries = 100000
	}
	if s.options.MaxDepth <= 0 {
		s.options.MaxDepth = 32
	}
	log := le.Uint16(h[22:])
	if s.used < 96 || s.used > uint64(source.Size()) || s.blockSize < 4096 || s.blockSize > 1<<20 || log > 20 || uint32(1)<<log != s.blockSize || s.inodeCount == 0 || s.idCount == 0 {
		return nil, fmt.Errorf("squashfs: invalid superblock geometry")
	}
	if s.codec != 1 && s.codec != 4 && s.codec != 6 {
		return nil, fmt.Errorf("squashfs: unsupported compression %d", s.codec)
	}
	for _, off := range []uint64{s.inodesTable, s.dirsTable, s.idsTable} {
		if off < 96 || off >= s.used {
			return nil, fmt.Errorf("squashfs: invalid table offset")
		}
	}
	if s.fragmentCount > 0 && (s.fragmentsTable < 96 || s.fragmentsTable >= s.used) {
		return nil, fmt.Errorf("squashfs: invalid fragment table")
	}
	root, _, err := s.inode(le.Uint64(h[32:]), nil)
	if err != nil {
		return nil, err
	}
	if root.Kind != "directory" {
		return nil, fmt.Errorf("squashfs: root is not a directory")
	}
	return root.View, nil
}
func (s *image) read(off, n uint64) ([]byte, error) {
	if off > s.used || n > s.used-off || n > 1<<24 {
		return nil, fmt.Errorf("squashfs: extent outside filesystem")
	}
	b := make([]byte, int(n))
	_, err := io.ReadFull(io.NewSectionReader(s.source, int64(off), int64(n)), b)
	return b, err
}
func (s *image) decode(b []byte, stored bool, maximum int) ([]byte, error) {
	if stored {
		if len(b) > maximum {
			return nil, fmt.Errorf("squashfs: oversized stored block")
		}
		return b, nil
	}
	var r io.Reader
	var close func()
	switch s.codec {
	case 1:
		z, err := zlib.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		r = z
		close = func() { z.Close() }
	case 4:
		z, err := xz.Open(&starfile.Bytes{Data: b}, 64<<20)
		if err != nil {
			return nil, err
		}
		if z.Size() > int64(maximum) {
			return nil, auto.ErrLimit
		}
		r = io.NewSectionReader(z, 0, z.Size())
	case 6:
		z, err := zstd.NewReader(bytes.NewReader(b), zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(64<<20))
		if err != nil {
			return nil, err
		}
		r = z
		close = z.Close
	}
	if close != nil {
		defer close()
	}
	out, err := io.ReadAll(io.LimitReader(r, int64(maximum)+1))
	if err != nil {
		return nil, err
	}
	if len(out) > maximum {
		return nil, auto.ErrLimit
	}
	return out, nil
}
func (s *image) metadata(off uint64) ([]byte, uint64, error) {
	h, err := s.read(off, 2)
	if err != nil {
		return nil, 0, err
	}
	word := le.Uint16(h)
	n := uint64(word & 0x7fff)
	if n == 0 || n > 8192 {
		return nil, 0, fmt.Errorf("squashfs: invalid metadata block size")
	}
	data, err := s.cache.Get(bytecache.Key{Kind: 1, Offset: int64(off)}, func() ([]byte, error) {
		b, e := s.read(off+2, n)
		if e != nil {
			return nil, e
		}
		out, e := s.decode(b, word&0x8000 != 0, 8192)
		if e == nil && len(out) == 0 {
			return nil, fmt.Errorf("squashfs: empty metadata block")
		}
		return out, e
	})
	return data, off + 2 + n, err
}

type cursor struct {
	s   *image
	off uint64
	at  int
}

func (c *cursor) take(n int) ([]byte, error) {
	if n < 0 || n > 8<<20 || c.at < 0 || c.at >= 8192 {
		return nil, auto.ErrLimit
	}
	out := make([]byte, 0, n)
	for len(out) < n {
		b, next, err := c.s.metadata(c.off)
		if err != nil {
			return nil, err
		}
		if c.at > len(b) {
			return nil, fmt.Errorf("squashfs: invalid metadata offset")
		}
		count := min(n-len(out), len(b)-c.at)
		out = append(out, b[c.at:c.at+count]...)
		c.at += count
		if c.at == len(b) {
			c.off = next
			c.at = 0
		}
	}
	return out, nil
}
func (s *image) table(start uint64, index, size uint32) ([]byte, error) {
	byteOffset := uint64(index) * uint64(size)
	if start > s.used || byteOffset/8192*8 > s.used-start {
		return nil, fmt.Errorf("squashfs: invalid table index")
	}
	ptr, err := s.read(start+byteOffset/8192*8, 8)
	if err != nil {
		return nil, err
	}
	c := cursor{s: s, off: le.Uint64(ptr), at: int(byteOffset % 8192)}
	return c.take(int(size))
}
func (s *image) inode(ref uint64, parents []uint64) (auto.Entry, uint16, error) {
	var e auto.Entry
	if ref>>16 > s.used-s.inodesTable {
		return e, 0, fmt.Errorf("squashfs: inode reference out of bounds")
	}
	c := cursor{s: s, off: s.inodesTable + (ref >> 16), at: int(ref & 0xffff)}
	h, err := c.take(16)
	if err != nil {
		return e, 0, err
	}
	kind := le.Uint16(h)
	number := le.Uint32(h[12:])
	if kind < 1 || kind > 14 || number == 0 || number > s.inodeCount {
		return e, 0, fmt.Errorf("squashfs: invalid inode")
	}
	ids := [2]uint32{}
	for i := range ids {
		index := le.Uint16(h[4+2*i:])
		if index >= s.idCount {
			return e, 0, fmt.Errorf("squashfs: invalid ID index")
		}
		b, err := s.table(s.idsTable, uint32(index), 4)
		if err != nil {
			return e, 0, err
		}
		ids[i] = le.Uint32(b)
	}
	e.Attributes = map[string]any{"mode": le.Uint16(h[2:]), "uid": ids[0], "gid": ids[1], "mtime": le.Uint32(h[8:]), "inode": number}
	baseKind := (kind-1)%7 + 1
	switch baseKind {
	case 1:
		for _, ancestor := range parents {
			if ancestor == ref {
				return e, 0, fmt.Errorf("squashfs: directory cycle")
			}
		}
		if len(parents) >= s.options.MaxDepth {
			return e, 0, auto.ErrLimit
		}
		n := 16
		if kind == 8 {
			n = 24
		}
		b, err := c.take(n)
		if err != nil {
			return e, 0, err
		}
		var start, length uint32
		var offset uint16
		if kind == 1 {
			start = le.Uint32(b)
			length = uint32(le.Uint16(b[8:]))
			offset = le.Uint16(b[10:])
			e.Attributes["nlink"] = le.Uint32(b[4:])
		} else {
			length = le.Uint32(b[4:])
			start = le.Uint32(b[8:])
			offset = le.Uint16(b[18:])
			e.Attributes["nlink"] = le.Uint32(b)
			e.Attributes["xattr_id"] = le.Uint32(b[20:])
		}
		if length < 3 || uint64(start) > s.used-s.dirsTable {
			return e, 0, fmt.Errorf("squashfs: invalid directory extent")
		}
		e.Kind = "directory"
		e.View = &directory{s: s, off: s.dirsTable + uint64(start), at: int(offset), length: int64(length) - 3, parents: append(append([]uint64{}, parents...), ref)}
	case 2:
		n := 16
		if kind == 9 {
			n = 40
		}
		b, err := c.take(n)
		if err != nil {
			return e, 0, err
		}
		f := &file{s: s}
		var start uint64
		if kind == 2 {
			start = uint64(le.Uint32(b))
			f.fragment = le.Uint32(b[4:])
			f.fragmentOffset = le.Uint32(b[8:])
			f.size = int64(le.Uint32(b[12:]))
		} else {
			start = le.Uint64(b)
			size := le.Uint64(b[8:])
			if size > 1<<40 {
				return e, 0, auto.ErrLimit
			}
			f.size = int64(size)
			f.fragment = le.Uint32(b[28:])
			f.fragmentOffset = le.Uint32(b[32:])
			e.Attributes["sparse_bytes"] = le.Uint64(b[16:])
			e.Attributes["nlink"] = le.Uint32(b[24:])
			e.Attributes["xattr_id"] = le.Uint32(b[36:])
		}
		count := f.size / int64(s.blockSize)
		if f.fragment == 0xffffffff {
			if f.size%int64(s.blockSize) != 0 {
				count++
			}
		} else if f.fragment >= s.fragmentCount {
			return e, 0, fmt.Errorf("squashfs: invalid fragment index")
		}
		if count > 1<<20 {
			return e, 0, auto.ErrLimit
		}
		sizes, err := c.take(int(count) * 4)
		if err != nil {
			return e, 0, err
		}
		for i := int64(0); i < count; i++ {
			word := le.Uint32(sizes[i*4:])
			n := uint64(word & 0xffffff)
			if word>>25 != 0 || n > uint64(s.blockSize) || start > s.used || n > s.used-start || word == 1<<24 {
				return e, 0, fmt.Errorf("squashfs: invalid data extent")
			}
			f.blocks = append(f.blocks, dataBlock{off: start, word: word})
			start += n
		}
		e.Kind = "file"
		e.Reader = f
	case 3:
		b, err := c.take(8)
		if err != nil {
			return e, 0, err
		}
		n := le.Uint32(b[4:])
		if n > 65536 {
			return e, 0, auto.ErrLimit
		}
		target, err := c.take(int(n))
		if err != nil {
			return e, 0, err
		}
		e.Kind = "symlink"
		e.Attributes["target"] = string(target)
		e.Attributes["nlink"] = le.Uint32(b)
		if kind == 10 {
			b, err = c.take(4)
			if err != nil {
				return e, 0, err
			}
			e.Attributes["xattr_id"] = le.Uint32(b)
		}
	default:
		n := 4
		if baseKind == 4 || baseKind == 5 {
			n += 4
		}
		if kind > 7 {
			n += 4
		}
		b, err := c.take(n)
		if err != nil {
			return e, 0, err
		}
		e.Kind = "special"
		e.Attributes["inode_type"] = baseKind
		e.Attributes["nlink"] = le.Uint32(b)
		if baseKind == 4 || baseKind == 5 {
			e.Attributes["rdev"] = le.Uint32(b[4:])
		}
		if kind > 7 {
			e.Attributes["xattr_id"] = le.Uint32(b[len(b)-4:])
		}
	}
	return e, baseKind, nil
}

type directory struct {
	s       *image
	off     uint64
	at      int
	length  int64
	parents []uint64
}

func (d *directory) Entries() ([]auto.Entry, error) {
	c := cursor{s: d.s, off: d.off, at: d.at}
	remaining := d.length
	var entries []auto.Entry
	seen := map[string]bool{}
	take := func(n int) ([]byte, error) {
		if int64(n) > remaining {
			return nil, fmt.Errorf("squashfs: truncated directory")
		}
		remaining -= int64(n)
		return c.take(n)
	}
	for remaining > 0 {
		h, err := take(12)
		if err != nil {
			return nil, err
		}
		count := uint64(le.Uint32(h)) + 1
		start, base := le.Uint32(h[4:]), le.Uint32(h[8:])
		if count > 256 || count > uint64(d.s.options.MaxEntries-len(entries)) {
			return nil, auto.ErrLimit
		}
		for i := uint64(0); i < count; i++ {
			b, err := take(8)
			if err != nil {
				return nil, err
			}
			n := int(le.Uint16(b[6:])) + 1
			if n > 256 {
				return nil, fmt.Errorf("squashfs: oversized name")
			}
			text, err := take(n)
			if err != nil {
				return nil, err
			}
			name := string(text)
			if name == "." || name == ".." || strings.ContainsAny(name, "/\x00") || seen[name] {
				return nil, fmt.Errorf("squashfs: invalid or duplicate name")
			}
			seen[name] = true
			ref := uint64(start)<<16 | uint64(le.Uint16(b))
			entry, kind, err := d.s.inode(ref, d.parents)
			if err != nil {
				return nil, err
			}
			number := int64(base) + int64(int16(le.Uint16(b[2:])))
			if number != int64(entry.Attributes["inode"].(uint32)) || kind != le.Uint16(b[4:]) {
				return nil, fmt.Errorf("squashfs: directory and inode disagree")
			}
			entry.Name = name
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

type dataBlock struct {
	off  uint64
	word uint32
}
type file struct {
	s                        *image
	size                     int64
	blocks                   []dataBlock
	fragment, fragmentOffset uint32
}

func (f *file) Size() int64 { return f.size }
func (s *image) data(b dataBlock) ([]byte, error) {
	n := uint64(b.word & 0xffffff)
	if b.word>>25 != 0 || n == 0 || n > uint64(s.blockSize) {
		return nil, fmt.Errorf("squashfs: invalid block length")
	}
	return s.cache.Get(bytecache.Key{Kind: 2, Offset: int64(b.off), Size: int64(b.word)}, func() ([]byte, error) {
		data, err := s.read(b.off, n)
		if err != nil {
			return nil, err
		}
		return s.decode(data, b.word&(1<<24) != 0, int(s.blockSize))
	})
}
func (f *file) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("squashfs: negative offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= f.size {
		return 0, io.EOF
	}
	wanted := len(p)
	if int64(len(p)) > f.size-off {
		p = p[:f.size-off]
	}
	total := 0
	blockSize := int64(f.s.blockSize)
	for len(p) > 0 {
		index, within := off/blockSize, off%blockSize
		expected := min(blockSize, f.size-index*blockSize)
		n := min(int64(len(p)), expected-within)
		if index < int64(len(f.blocks)) && f.blocks[index].word == 0 {
			clear(p[:n])
		} else {
			var b []byte
			var err error
			if index < int64(len(f.blocks)) {
				b, err = f.s.data(f.blocks[index])
				if err == nil && int64(len(b)) != expected {
					err = fmt.Errorf("squashfs: decoded data length mismatch")
				}
			} else {
				if f.fragment == 0xffffffff {
					return total, fmt.Errorf("squashfs: missing file block")
				}
				h, e := f.s.table(f.s.fragmentsTable, f.fragment, 16)
				if e != nil {
					return total, e
				}
				b, err = f.s.data(dataBlock{off: le.Uint64(h), word: le.Uint32(h[8:])})
				if err == nil {
					if uint64(f.fragmentOffset)+uint64(expected) > uint64(len(b)) {
						err = fmt.Errorf("squashfs: fragment extent out of bounds")
					} else {
						b = b[f.fragmentOffset : uint64(f.fragmentOffset)+uint64(expected)]
					}
				}
			}
			if err != nil {
				return total, err
			}
			copy(p[:n], b[within:within+n])
		}
		total += int(n)
		off += n
		p = p[n:]
	}
	if total < wanted {
		return total, io.EOF
	}
	return total, nil
}
