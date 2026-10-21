package ext4

import (
	"bytes"
	"fmt"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/filesystem/unixfs"
	"github.com/tinyrange/trex/storage"
	"hash/crc32"
	"io"
	"math"
	"sort"
	"strings"
	"sync"
)

func init() { auto.Register("ext4", 45, Open) }

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// crc16 is the reflected CRC-16 used by the legacy GDT_CSUM feature.
func crc16(seed uint16, data []byte) uint16 {
	for _, b := range data {
		seed ^= uint16(b)
		for i := 0; i < 8; i++ {
			if seed&1 != 0 {
				seed = (seed >> 1) ^ 0xa001
			} else {
				seed >>= 1
			}
		}
	}
	return seed
}

func rawCRC(seed uint32, data []byte) uint32 { return ^crc32.Update(^seed, castagnoli, data) }

type Volume struct {
	source                  storage.Reader
	block                   uint64
	blocks                  uint64
	first, bpg, ipg, inodes uint32
	inodeSize, descSize     uint16
	groups                  uint64
	incompat, ro            uint32
	seed                    uint32
	uuid                    [16]byte
	label                   string
	options                 auto.Options
}
type inode struct {
	id                     uint32
	mode                   uint32
	uid, gid, mtime, nlink uint32
	size                   int64
	flags                  uint32
	raw                    []byte
	seed                   uint32
}

func Open(prefix []byte, source storage.Reader, options auto.Options) (auto.View, error) {
	if len(prefix) < 1082 || u16(prefix, 1080) != 0xef53 {
		return nil, auto.ErrNoMatch
	}
	v, err := Read(source, options)
	if err != nil {
		return nil, err
	}
	return &dirView{volume: v, id: 2, depth: 0, ancestors: map[uint32]bool{2: true}}, nil
}

// Read opens a clean ext2/3/4 volume. Unsupported layout-changing features are
// rejected explicitly rather than misinterpreted. Journal replay is not implicit.
func Read(source storage.Reader, options auto.Options) (*Volume, error) {
	if source == nil || source.Size() < 2048 {
		return nil, fmt.Errorf("ext4: truncated superblock")
	}
	sb := make([]byte, 1024)
	if _, err := io.ReadFull(io.NewSectionReader(source, 1024, 1024), sb); err != nil {
		return nil, err
	}
	if u16(sb, 56) != 0xef53 {
		return nil, auto.ErrNoMatch
	}
	if u32(sb, 72) != 0 {
		return nil, fmt.Errorf("ext4: unsupported non-Linux inode OS layout")
	}
	log := u32(sb, 24)
	if log > 6 {
		return nil, fmt.Errorf("ext4: invalid block size")
	}
	v := &Volume{source: source, block: uint64(1024) << log, blocks: uint64(u32(sb, 4)), first: u32(sb, 20), bpg: u32(sb, 32), ipg: u32(sb, 40), inodes: u32(sb, 0), inodeSize: u16(sb, 88), descSize: 32, incompat: u32(sb, 96), ro: u32(sb, 100), options: options, label: strings.TrimRight(string(sb[120:136]), "\x00")}
	copy(v.uuid[:], sb[104:120])
	if u32(sb, 76) == 0 {
		v.inodeSize = 128
		v.incompat = 0
		v.ro = 0
	}
	// FILETYPE, EXTENTS, 64BIT, FLEX_BG and CSUM_SEED do not require external state.
	if v.incompat & ^uint32(0x2|0x40|0x80|0x200|0x2000) != 0 {
		return nil, fmt.Errorf("ext4: unsupported incompatible features %#x (including journal recovery)", v.incompat)
	}
	if v.ro & ^uint32(0x1|0x2|0x8|0x10|0x20|0x40|0x400|0x1000) != 0 {
		return nil, fmt.Errorf("ext4: unsupported read-only features %#x", v.ro)
	}
	if v.incompat&0x80 != 0 {
		v.blocks |= uint64(u32(sb, 336)) << 32
		v.descSize = u16(sb, 254)
		if v.descSize < 64 || uint64(v.descSize) > v.block || v.descSize%8 != 0 {
			return nil, fmt.Errorf("ext4: invalid 64-bit group descriptor")
		}
	}
	if v.blocks == 0 || v.blocks > uint64(source.Size())/v.block || uint64(v.first) >= v.blocks || v.bpg == 0 || uint64(v.bpg) > v.block*8 || v.ipg == 0 || uint64(v.ipg) > v.block*8 || v.inodes < 2 || v.inodeSize < 128 || uint64(v.inodeSize) > v.block || v.inodeSize&(v.inodeSize-1) != 0 {
		return nil, fmt.Errorf("ext4: invalid filesystem geometry")
	}
	v.groups = (v.blocks - uint64(v.first) + uint64(v.bpg) - 1) / uint64(v.bpg)
	if uint64(v.inodes) > v.groups*uint64(v.ipg) || (v.block == 1024 && v.first != 1) || (v.block != 1024 && v.first != 0) {
		return nil, fmt.Errorf("ext4: invalid group geometry")
	}
	if v.options.MaxEntries <= 0 {
		v.options.MaxEntries = 100000
	}
	if v.options.MaxDepth <= 0 {
		v.options.MaxDepth = 32
	}
	v.seed = rawCRC(math.MaxUint32, v.uuid[:])
	if v.incompat&0x2000 != 0 {
		if v.ro&0x400 == 0 {
			return nil, fmt.Errorf("ext4: checksum seed without metadata checksums")
		}
		v.seed = u32(sb, 624)
	}
	if v.ro&0x400 != 0 {
		if sb[373] != 1 || rawCRC(math.MaxUint32, sb[:1020]) != u32(sb, 1020) {
			return nil, fmt.Errorf("ext4: superblock checksum mismatch")
		}
	}
	return v, nil
}
func (v *Volume) readBlock(id uint64) ([]byte, error) {
	if id == 0 || id >= v.blocks {
		return nil, fmt.Errorf("ext4: block %d outside volume", id)
	}
	b := make([]byte, v.block)
	_, err := io.ReadFull(io.NewSectionReader(v.source, int64(id*v.block), int64(v.block)), b)
	return b, err
}
func (v *Volume) readInode(id uint32) (*inode, error) {
	if id == 0 || id > v.inodes {
		return nil, fmt.Errorf("ext4: invalid inode %d", id)
	}
	group := uint64((id - 1) / v.ipg)
	at := (uint64(v.first)+1)*v.block + group*uint64(v.descSize)
	desc := make([]byte, v.descSize)
	if at > uint64(v.source.Size()) || uint64(len(desc)) > uint64(v.source.Size())-at {
		return nil, fmt.Errorf("ext4: truncated group descriptor")
	}
	if _, err := io.ReadFull(io.NewSectionReader(v.source, int64(at), int64(len(desc))), desc); err != nil {
		return nil, err
	}
	if v.ro&0x400 != 0 {
		want := u16(desc, 30)
		copyDesc := append([]byte(nil), desc...)
		put16(copyDesc, 30, 0)
		var groupBytes [4]byte
		put32(groupBytes[:], 0, uint32(group))
		got := rawCRC(rawCRC(v.seed, groupBytes[:]), copyDesc)
		if uint16(got) != want {
			return nil, fmt.Errorf("ext4: group descriptor checksum mismatch")
		}
	} else if v.ro&0x10 != 0 {
		var groupBytes [4]byte
		put32(groupBytes[:], 0, uint32(group))
		got := crc16(crc16(crc16(0xffff, v.uuid[:]), groupBytes[:]), desc[:30])
		got = crc16(got, desc[32:])
		if got != u16(desc, 30) {
			return nil, fmt.Errorf("ext4: group descriptor checksum mismatch")
		}
	}
	table := uint64(u32(desc, 8))
	if v.incompat&0x80 != 0 {
		table |= uint64(u32(desc, 40)) << 32
	}
	if table == 0 || table >= v.blocks || uint64(v.ipg)*uint64(v.inodeSize) > (v.blocks-table)*v.block {
		return nil, fmt.Errorf("ext4: invalid inode table")
	}
	off := table*v.block + uint64((id-1)%v.ipg)*uint64(v.inodeSize)
	raw := make([]byte, v.inodeSize)
	if _, err := io.ReadFull(io.NewSectionReader(v.source, int64(off), int64(len(raw))), raw); err != nil {
		return nil, err
	}
	n := &inode{id: id, mode: uint32(u16(raw, 0)), uid: uint32(u16(raw, 2)) | uint32(u16(raw, 120))<<16, gid: uint32(u16(raw, 24)) | uint32(u16(raw, 122))<<16, mtime: u32(raw, 16), nlink: uint32(u16(raw, 26)), flags: u32(raw, 32), raw: raw}
	size := uint64(u32(raw, 4))
	if n.mode&0170000 == unixfs.Regular || n.mode&0170000 == unixfs.Directory {
		size |= uint64(u32(raw, 108)) << 32
	}
	if size > math.MaxInt64 || size > uint64(math.MaxUint32+1)*v.block {
		return nil, fmt.Errorf("ext4: invalid inode size")
	}
	n.size = int64(size)
	if n.flags&(0x800|0x10000000|0x4) != 0 {
		return nil, fmt.Errorf("ext4: encrypted, inline or compressed inode unsupported")
	}
	var seedData [8]byte
	put32(seedData[:], 0, id)
	put32(seedData[:], 4, u32(raw, 100))
	n.seed = rawCRC(v.seed, seedData[:])
	if v.ro&0x400 != 0 {
		want := uint32(u16(raw, 124))
		check := append([]byte(nil), raw...)
		put16(check, 124, 0)
		high := len(raw) > 131 && u16(raw, 128) >= 4
		if high {
			want |= uint32(u16(raw, 130)) << 16
			put16(check, 130, 0)
		}
		got := rawCRC(n.seed, check)
		if !high {
			got &= 65535
		}
		if got != want {
			return nil, fmt.Errorf("ext4: inode checksum mismatch")
		}
	}
	return n, nil
}

// extents validates every node, its depth, ordering, bounds and checksum. Sparse
// and unwritten ranges remain zeroes rather than exposing underlying disk data.
func (v *Volume) extents(n *inode) ([]extent, error) {
	if n.flags&0x80000 == 0 {
		return v.indirect(n)
	}
	var out []extent
	seen := map[uint64]bool{}
	nodes := 0
	var walk func([]byte, int, bool) error
	walk = func(data []byte, depth int, external bool) error {
		nodes++
		if nodes > v.options.MaxEntries {
			return auto.ErrLimit
		}
		if len(data) < 12 || u16(data, 0) != 0xf30a || int(u16(data, 6)) != depth || depth > 5 {
			return fmt.Errorf("ext4: invalid extent header")
		}
		count, max := int(u16(data, 2)), int(u16(data, 4))
		if max == 0 || count > max || max > (len(data)-12)/12 {
			return fmt.Errorf("ext4: invalid extent count")
		}
		if external && v.ro&0x400 != 0 {
			tail := 12 + max*12
			if tail+4 > len(data) || rawCRC(n.seed, data[:tail]) != u32(data, tail) {
				return fmt.Errorf("ext4: extent checksum mismatch")
			}
		}
		var previous uint32
		for i := 0; i < count; i++ {
			off := 12 + i*12
			logical := u32(data, off)
			if i > 0 && logical <= previous {
				return fmt.Errorf("ext4: unsorted extent node")
			}
			previous = logical
			if depth > 0 {
				block := uint64(u32(data, off+4)) | uint64(u16(data, off+8))<<32
				if seen[block] {
					return fmt.Errorf("ext4: repeated extent node")
				}
				seen[block] = true
				child, err := v.readBlock(block)
				if err != nil {
					return err
				}
				before := len(out)
				if err := walk(child, depth-1, true); err != nil {
					return err
				}
				if len(out) == before || out[before].logical != logical {
					return fmt.Errorf("ext4: extent index mismatch")
				}
			} else {
				length := uint32(u16(data, off+4))
				unwritten := length > 32768
				if unwritten {
					length -= 32768
				}
				physical := uint64(u32(data, off+8)) | uint64(u16(data, off+6))<<32
				if length == 0 || uint64(logical)+uint64(length) > math.MaxUint32+1 || physical == 0 || physical >= v.blocks || uint64(length) > v.blocks-physical {
					return fmt.Errorf("ext4: invalid extent bounds")
				}
				if len(out) > 0 {
					last := out[len(out)-1]
					if uint64(logical) < uint64(last.logical)+uint64(last.count) {
						return fmt.Errorf("ext4: overlapping extents")
					}
				}
				out = append(out, extent{logical: logical, physical: physical, count: length, unwritten: unwritten})
				if len(out) > v.options.MaxEntries {
					return auto.ErrLimit
				}
			}
		}
		return nil
	}
	if err := walk(n.raw[40:100], int(u16(n.raw, 46)), false); err != nil {
		return nil, err
	}
	return out, nil
}
func (v *Volume) indirect(n *inode) ([]extent, error) {
	needed := (uint64(n.size) + v.block - 1) / v.block
	var out []extent
	var logical uint64
	seen := map[uint64]bool{}
	visited := 0
	add := func(block uint64) error {
		if logical >= needed {
			return nil
		}
		if block >= v.blocks {
			return fmt.Errorf("ext4: invalid indirect data block")
		}
		if block != 0 {
			out = append(out, extent{logical: uint32(logical), physical: block, count: 1})
			if len(out) > v.options.MaxEntries {
				return auto.ErrLimit
			}
		}
		logical++
		return nil
	}
	for i := 0; i < 12 && logical < needed; i++ {
		if err := add(uint64(u32(n.raw, 40+i*4))); err != nil {
			return nil, err
		}
	}
	var walk func(uint64, int) error
	walk = func(block uint64, depth int) error {
		if logical >= needed {
			return nil
		}
		capacity := uint64(1)
		for i := 0; i < depth; i++ {
			capacity *= v.block / 4
		}
		if block == 0 {
			logical += min(capacity, needed-logical)
			return nil
		}
		if seen[block] {
			return fmt.Errorf("ext4: repeated indirect block")
		}
		seen[block] = true
		visited++
		if visited > v.options.MaxEntries {
			return auto.ErrLimit
		}
		data, err := v.readBlock(block)
		if err != nil {
			return err
		}
		for off := 0; off < len(data) && logical < needed; off += 4 {
			id := uint64(u32(data, off))
			if depth == 1 {
				err = add(id)
			} else {
				err = walk(id, depth-1)
			}
			if err != nil {
				return err
			}
		}
		return nil
	}
	for depth := 1; depth <= 3 && logical < needed; depth++ {
		if err := walk(uint64(u32(n.raw, 88+(depth-1)*4)), depth); err != nil {
			return nil, err
		}
	}
	if logical < needed {
		return nil, fmt.Errorf("ext4: file exceeds indirect addressing")
	}
	return out, nil
}

type fileReader struct {
	volume *Volume
	node   *inode
	once   sync.Once
	ranges []extent
	err    error
}

func (r *fileReader) Size() int64 { return r.node.size }
func (r *fileReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("ext4: negative file offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= r.Size() {
		return 0, io.EOF
	}
	r.once.Do(func() { r.ranges, r.err = r.volume.extents(r.node) })
	if r.err != nil {
		return 0, r.err
	}
	wanted := len(p)
	count := int(min(int64(wanted), r.Size()-off))
	p = p[:count]
	done := 0
	block := int64(r.volume.block)
	for done < count {
		logical := uint64(off / block)
		index := sort.Search(len(r.ranges), func(i int) bool { return uint64(r.ranges[i].logical)+uint64(r.ranges[i].count) > logical })
		n := count - done
		zero := true
		var physical int64
		if index < len(r.ranges) {
			x := r.ranges[index]
			if logical >= uint64(x.logical) {
				n = int(min(int64(n), (int64(x.logical)+int64(x.count))*block-off))
				zero = x.unwritten
				physical = int64(x.physical)*block + off - int64(x.logical)*block
			} else {
				n = int(min(int64(n), int64(x.logical)*block-off))
			}
		}
		if zero {
			clear(p[done : done+n])
		} else {
			got, err := r.volume.source.ReadAt(p[done:done+n], physical)
			if err != nil && !(err == io.EOF && got == n) {
				return done + got, err
			}
			if got != n {
				return done + got, io.ErrUnexpectedEOF
			}
		}
		done += n
		off += int64(n)
	}
	if count < wanted {
		return count, io.EOF
	}
	return count, nil
}
func (v *Volume) entry(n *inode, name string) (auto.Entry, error) {
	e := auto.Entry{Name: name, Attributes: map[string]any{"inode": n.id, "mode": n.mode, "uid": n.uid, "gid": n.gid, "mtime": n.mtime, "nlink": n.nlink}}
	switch n.mode & 0170000 {
	case unixfs.Regular:
		e.Kind = "file"
		e.Reader = &fileReader{volume: v, node: n}
	case unixfs.Directory:
		e.Kind = "directory"
	case unixfs.Symlink:
		e.Kind = "symlink"
		if n.size > 65536 {
			return e, auto.ErrLimit
		}
		var data []byte
		// Fast symlinks have no data blocks (extended attributes may consume blocks).
		sectors := uint64(u32(n.raw, 28))
		acl := uint64(u32(n.raw, 104))
		if v.incompat&0x80 != 0 {
			acl |= uint64(u16(n.raw, 118)) << 32
		}
		if acl != 0 {
			if sectors < v.block/512 {
				return e, fmt.Errorf("ext4: invalid symlink blocks")
			}
			sectors -= v.block / 512
		}
		if sectors == 0 {
			if n.size > 60 {
				return e, fmt.Errorf("ext4: invalid fast symlink")
			}
			data = n.raw[40 : 40+n.size]
		} else {
			r := &fileReader{volume: v, node: n}
			data = make([]byte, n.size)
			if _, err := io.ReadFull(io.NewSectionReader(r, 0, n.size), data); err != nil {
				return e, err
			}
		}
		if len(data) == 0 || bytes.IndexByte(data, 0) >= 0 {
			return e, fmt.Errorf("ext4: invalid symlink target")
		}
		e.Attributes["target"] = string(data)
	case unixfs.Character, unixfs.Block:
		if n.mode&0170000 == unixfs.Character {
			e.Kind = "character_device"
		} else {
			e.Kind = "block_device"
		}
		dev := u32(n.raw, 40)
		var major, minor uint32
		if dev != 0 {
			major = (dev >> 8) & 255
			minor = dev & 255
		} else {
			dev = u32(n.raw, 44)
			major = (dev >> 8) & 4095
			minor = (dev & 255) | ((dev >> 12) & 0xfff00)
		}
		e.Attributes["major"] = major
		e.Attributes["minor"] = minor
	case unixfs.FIFO:
		e.Kind = "fifo"
	case unixfs.Socket:
		e.Kind = "socket"
	default:
		return e, fmt.Errorf("ext4: invalid inode type %#o", n.mode)
	}
	return e, nil
}

type dirView struct {
	volume    *Volume
	id        uint32
	depth     int
	ancestors map[uint32]bool
	once      sync.Once
	entries   []auto.Entry
	err       error
}

func (d *dirView) Description() (string, map[string]any) {
	return "ext4", map[string]any{"label": d.volume.label, "block_size": d.volume.block, "blocks": d.volume.blocks}
}
func (d *dirView) Entries() ([]auto.Entry, error) {
	d.once.Do(func() { d.entries, d.err = d.load() })
	return append([]auto.Entry(nil), d.entries...), d.err
}
func (d *dirView) load() ([]auto.Entry, error) {
	v := d.volume
	if d.depth >= v.options.MaxDepth {
		return nil, auto.ErrLimit
	}
	node, err := v.readInode(d.id)
	if err != nil {
		return nil, err
	}
	if node.mode&0170000 != unixfs.Directory || node.size < 0 || uint64(node.size)%v.block != 0 {
		return nil, fmt.Errorf("ext4: invalid directory inode")
	}
	r := &fileReader{volume: v, node: node}
	block := make([]byte, v.block)
	var out []auto.Entry
	names := map[string]bool{}
	for off := int64(0); off < node.size; off += int64(v.block) {
		if off/int64(v.block) > int64(v.options.MaxEntries) {
			return nil, auto.ErrLimit
		}
		if _, err := io.ReadFull(io.NewSectionReader(r, off, int64(v.block)), block); err != nil {
			return nil, err
		}
		if v.ro&0x400 != 0 {
			if err := v.directoryChecksum(node, block, off == 0); err != nil {
				return nil, err
			}
		}
		for at := 0; at < len(block); {
			if len(block)-at < 8 {
				return nil, fmt.Errorf("ext4: truncated directory record")
			}
			id := u32(block, at)
			length := int(u16(block, at+4))
			if v.block == 65536 {
				if length == 65535 {
					length = 0
				} else {
					length = (length & 65532) | ((length & 3) << 16)
				}
				if length == 0 {
					length = 65536
				}
			}
			nameLen := int(u16(block, at+6))
			if v.incompat&2 != 0 {
				nameLen = int(block[at+6])
			}
			if length < 8 || length%4 != 0 || length > len(block)-at || nameLen > 255 || nameLen > length-8 {
				return nil, fmt.Errorf("ext4: invalid directory record")
			}
			if id != 0 {
				name := string(block[at+8 : at+8+nameLen])
				if name == "" || strings.ContainsAny(name, "/\x00") {
					return nil, fmt.Errorf("ext4: invalid directory name")
				}
				if name != "." && name != ".." {
					if names[name] {
						return nil, fmt.Errorf("ext4: duplicate directory name")
					}
					names[name] = true
					if len(out) >= v.options.MaxEntries {
						return nil, auto.ErrLimit
					}
					child, err := v.readInode(id)
					if err != nil {
						return nil, err
					}
					entry, err := v.entry(child, name)
					if err != nil {
						return nil, err
					}
					if entry.Kind == "directory" {
						if d.ancestors[id] {
							return nil, fmt.Errorf("ext4: directory cycle")
						}
						ancestors := map[uint32]bool{}
						for k, val := range d.ancestors {
							ancestors[k] = val
						}
						ancestors[id] = true
						entry.View = &dirView{volume: v, id: id, depth: d.depth + 1, ancestors: ancestors}
					}
					out = append(out, entry)
				}
			}
			at += length
		}
	}
	return out, nil
}
func (v *Volume) directoryChecksum(n *inode, b []byte, first bool) error {
	// Linear/htree leaf blocks end with ext4_dir_entry_tail.
	tail := len(b) - 12
	if u32(b, tail) == 0 && u16(b, tail+4) == 12 && b[tail+6] == 0 && b[tail+7] == 0xde {
		if rawCRC(n.seed, b[:tail]) != u32(b, tail+8) {
			return fmt.Errorf("ext4: directory checksum mismatch")
		}
		return nil
	}
	// Htree root and interior nodes carry a dx_tail after their entry capacity.
	if n.flags&0x1000 == 0 {
		return fmt.Errorf("ext4: missing directory checksum tail")
	}
	countOff := 8
	if first {
		if len(b) < 40 || b[29] != 8 {
			return fmt.Errorf("ext4: invalid htree root")
		}
		countOff = 32
	}
	limit, count := int(u16(b, countOff)), int(u16(b, countOff+2))
	tail = countOff + limit*8
	if limit == 0 || count == 0 || count > limit || tail+8 > len(b) {
		return fmt.Errorf("ext4: invalid htree count")
	}
	seed := rawCRC(n.seed, b[:countOff+count*8])
	seed = rawCRC(seed, b[tail:tail+4])
	seed = rawCRC(seed, []byte{0, 0, 0, 0})
	if seed != u32(b, tail+4) {
		return fmt.Errorf("ext4: htree checksum mismatch")
	}
	return nil
}
