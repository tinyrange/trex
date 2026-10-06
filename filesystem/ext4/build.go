// Package ext4 implements portable ext filesystem views and native image
// construction. The writer creates ext4 with extents and linear directories,
// without a journal; it never invokes mkfs, mounts, or copies file payloads.
package ext4

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/filesystem/unixfs"
	"github.com/tinyrange/trex/storage"
	"io"
	"math"
	"path"
	"sort"
	"strings"
)

const blockSize uint32 = 4096
const blocksPerGroup uint32 = 32768

var le = binary.LittleEndian

func put16(b []byte, o int, v uint16) { le.PutUint16(b[o:], v) }
func put32(b []byte, o int, v uint32) { le.PutUint32(b[o:], v) }
func u16(b []byte, o int) uint16      { return le.Uint16(b[o:]) }
func u32(b []byte, o int) uint32      { return le.Uint32(b[o:]) }

type BuildOptions struct {
	Size  int64
	UUID  [16]byte
	Label string
}
type fragment struct {
	offset int64
	source storage.Reader
}
type buildGroup struct {
	start, count, next     uint32
	bitmap, ibitmap, table []byte
	usedInodes, dirs       uint32
}
type imageBuilder struct {
	groups         []buildGroup
	ipg, gdtBlocks uint32
	fragments      []fragment
	cursor         int
}
type extent struct {
	logical   uint32
	physical  uint64
	count     uint32
	unwritten bool
}
type buildNode struct {
	entry    unixfs.Entry
	ino      uint32
	links    uint32
	children []*buildNode
}

// Build returns a sparse, immutable image reader. File data is borrowed and must
// remain stable/open for the image's lifetime. Size is a multiple of 4096.
func Build(input []unixfs.Entry, options BuildOptions) (storage.Reader, error) {
	if options.Size < 8<<20 || options.Size%int64(blockSize) != 0 || options.Size/int64(blockSize) > math.MaxUint32 {
		return nil, fmt.Errorf("ext4: size must be 8 MiB..16 TiB, aligned to 4096 bytes")
	}
	if len(options.Label) > 16 || strings.ContainsRune(options.Label, 0) {
		return nil, fmt.Errorf("ext4: invalid volume label")
	}
	entries, err := unixfs.Normalize(input)
	if err != nil {
		return nil, err
	}
	total := uint32(options.Size / int64(blockSize))
	ng := (uint64(total) + uint64(blocksPerGroup) - 1) / uint64(blocksPerGroup)
	// Bound retained metadata independently of sparse disk capacity.
	ipg := uint32((uint64(len(entries)) + 10 + ng - 1) / ng)
	ipg = max(128, (ipg+31)&^31)
	if ipg > 32768 || ng*(uint64(ipg)*256+8192) > 256<<20 {
		return nil, fmt.Errorf("ext4: metadata capacity exceeded")
	}
	b := &imageBuilder{ipg: ipg, gdtBlocks: uint32((ng*32 + 4095) / 4096)}
	tableBlocks := ipg * 256 / blockSize
	metadata := 1 + b.gdtBlocks + 2 + tableBlocks
	for g := uint32(0); uint64(g) < ng; g++ {
		start := g * blocksPerGroup
		count := min(blocksPerGroup, total-start)
		if count <= metadata {
			return nil, fmt.Errorf("ext4: final block group has no data space; choose a larger size")
		}
		group := buildGroup{start: start, count: count, next: metadata, bitmap: make([]byte, 4096), ibitmap: make([]byte, 4096), table: make([]byte, ipg*256)}
		for i := uint32(0); i < metadata; i++ {
			bitSet(group.bitmap, i)
		}
		for i := count; i < blocksPerGroup; i++ {
			bitSet(group.bitmap, i)
		}
		for i := ipg; i < 32768; i++ {
			bitSet(group.ibitmap, i)
		}
		b.groups = append(b.groups, group)
	}
	// Reserve traditional inodes 1..10. Inode 2 is the root directory.
	for i := uint32(0); i < 10; i++ {
		bitSet(b.groups[0].ibitmap, i)
	}
	b.groups[0].usedInodes = 10
	nodes := map[string]*buildNode{}
	var unique []*buildNode
	next := uint32(11)
	for _, e := range entries {
		if e.Hardlink {
			continue
		}
		ino := next
		if e.Path == "." {
			ino = 2
		} else {
			next++
		}
		if uint64(ino) > ng*uint64(ipg) {
			return nil, fmt.Errorf("ext4: inode capacity exceeded")
		}
		n := &buildNode{entry: e, ino: ino, links: 1}
		nodes[e.Path] = n
		unique = append(unique, n)
		group := (ino - 1) / ipg
		if ino != 2 {
			bitSet(b.groups[group].ibitmap, (ino-1)%ipg)
			b.groups[group].usedInodes++
		}
		if e.Mode&0170000 == unixfs.Directory {
			n.links = 2
			b.groups[group].dirs++
		}
	}
	for _, e := range entries {
		if e.Hardlink {
			n := nodes[e.Target]
			if n == nil {
				return nil, fmt.Errorf("ext4: missing hardlink")
			}
			n.links++
			nodes[e.Path] = n
		}
	}
	// Keep distinct directory-entry names even when the inode is shared.
	for _, e := range entries {
		if e.Path == "." {
			continue
		}
		parent := nodes[path.Dir(e.Path)]
		child := nodes[e.Path]
		alias := *child
		alias.entry = e
		parent.children = append(parent.children, &alias)
		if e.Mode&0170000 == unixfs.Directory {
			parent.links++
		}
	}
	for _, n := range unique {
		if n.links > 65535 {
			return nil, fmt.Errorf("ext4: too many links for %q", n.entry.Path)
		}
		inode := b.groups[(n.ino-1)/ipg].table[((n.ino-1)%ipg)*256:][:256]
		e := n.entry
		put16(inode, 0, uint16(e.Mode))
		put16(inode, 2, uint16(e.UID))
		put16(inode, 24, uint16(e.GID))
		put16(inode, 26, uint16(n.links))
		put16(inode, 120, uint16(e.UID>>16))
		put16(inode, 122, uint16(e.GID>>16))
		put16(inode, 128, 32)
		for _, off := range []int{8, 12, 16, 144} {
			put32(inode, off, e.Mtime)
		}
		var data storage.Reader
		switch e.Mode & 0170000 {
		case unixfs.Directory:
			parent := n.ino
			if e.Path != "." {
				parent = nodes[path.Dir(e.Path)].ino
			}
			contents, err := directoryData(n, parent)
			if err != nil {
				return nil, err
			}
			data = bytes.NewReader(contents)
		case unixfs.Regular:
			data = e.Data
		case unixfs.Symlink:
			data = bytes.NewReader([]byte(e.Target))
			if len(e.Target) <= 60 {
				copy(inode[40:100], e.Target)
				put32(inode, 4, uint32(len(e.Target)))
				continue
			}
		case unixfs.Character, unixfs.Block:
			if e.Major > 4095 || e.Minor > 1048575 {
				return nil, fmt.Errorf("ext4: device number exceeds Linux encoding")
			}
			put32(inode, 44, (e.Minor&255)|(e.Major<<8)|((e.Minor&^255)<<12))
			continue
		case unixfs.FIFO, unixfs.Socket:
			continue
		}
		size := data.Size()
		if size < 0 || uint64(size) > uint64(total)*uint64(blockSize) {
			return nil, fmt.Errorf("ext4: invalid file size")
		}
		put32(inode, 4, uint32(size))
		put32(inode, 108, uint32(uint64(size)>>32))
		put32(inode, 32, 0x80000)
		extents, err := b.allocate(uint32((uint64(size) + 4095) / 4096))
		if err != nil {
			return nil, fmt.Errorf("ext4: %s: %w", e.Path, err)
		}
		var offset int64
		for _, x := range extents {
			length := min(int64(x.count)*4096, size-offset)
			b.fragments = append(b.fragments, fragment{int64(x.physical) * 4096, io.NewSectionReader(data, offset, length)})
			offset += length
		}
		treeBlocks, err := b.extentRoot(inode[40:100], extents)
		if err != nil {
			return nil, err
		}
		sectors := (uint64((size+4095)/4096) + uint64(treeBlocks)) * 8
		put32(inode, 28, uint32(sectors))
		put16(inode, 116, uint16(sectors>>32))
	}
	gdt := make([]byte, b.gdtBlocks*4096)
	var freeBlocks, freeInodes uint32
	for i, g := range b.groups {
		at := i * 32
		put32(gdt, at, g.start+1+b.gdtBlocks)
		put32(gdt, at+4, g.start+2+b.gdtBlocks)
		put32(gdt, at+8, g.start+3+b.gdtBlocks)
		fb := g.count - g.next
		fi := ipg - g.usedInodes
		freeBlocks += fb
		freeInodes += fi
		put16(gdt, at+12, uint16(fb))
		put16(gdt, at+14, uint16(fi))
		put16(gdt, at+16, uint16(g.dirs))
		b.addBytes(int64(g.start+1+b.gdtBlocks)*4096, g.bitmap)
		b.addBytes(int64(g.start+2+b.gdtBlocks)*4096, g.ibitmap)
		b.addBytes(int64(g.start+3+b.gdtBlocks)*4096, g.table)
	}
	sb := make([]byte, 1024)
	put32(sb, 0, uint32(ng)*ipg)
	put32(sb, 4, total)
	put32(sb, 12, freeBlocks)
	put32(sb, 16, freeInodes)
	put32(sb, 24, 2)
	put32(sb, 28, 2)
	put32(sb, 32, blocksPerGroup)
	put32(sb, 36, blocksPerGroup)
	put32(sb, 40, ipg)
	put16(sb, 54, 0xffff)
	put16(sb, 56, 0xef53)
	put16(sb, 58, 1)
	put16(sb, 60, 1)
	put32(sb, 76, 1)
	put32(sb, 84, 11)
	put16(sb, 88, 256)
	put32(sb, 96, 0x42)
	put32(sb, 100, 0x42)
	copy(sb[104:120], options.UUID[:])
	copy(sb[120:136], options.Label)
	put16(sb, 254, 32)
	put16(sb, 348, 32)
	put16(sb, 350, 32)
	for i, g := range b.groups {
		backup := append([]byte(nil), sb...)
		put16(backup, 90, uint16(i))
		off := int64(g.start) * 4096
		if i == 0 {
			off = 1024
		}
		b.addBytes(off, backup)
		b.addBytes(int64(g.start+1)*4096, gdt)
	}
	sort.Slice(b.fragments, func(i, j int) bool { return b.fragments[i].offset < b.fragments[j].offset })
	var ranges []storage.Range
	var pos int64
	for _, f := range b.fragments {
		if f.offset < pos {
			return nil, fmt.Errorf("ext4: overlapping construction fragments")
		}
		if f.offset > pos {
			ranges = append(ranges, storage.Range{Source: unixfs.Zero(f.offset - pos), Length: f.offset - pos})
		}
		ranges = append(ranges, storage.Range{Source: f.source, Length: f.source.Size()})
		pos = f.offset + f.source.Size()
	}
	if pos > options.Size {
		return nil, fmt.Errorf("ext4: image overflow")
	}
	ranges = append(ranges, storage.Range{Source: unixfs.Zero(options.Size - pos), Length: options.Size - pos})
	return storage.Compose(ranges...)
}
func bitSet(b []byte, n uint32) { b[n/8] |= 1 << (n % 8) }
func (b *imageBuilder) addBytes(off int64, data []byte) {
	b.fragments = append(b.fragments, fragment{off, bytes.NewReader(data)})
}
func (b *imageBuilder) allocate(count uint32) ([]extent, error) {
	var out []extent
	var logical uint32
	for count > 0 {
		for b.cursor < len(b.groups) && b.groups[b.cursor].next == b.groups[b.cursor].count {
			b.cursor++
		}
		if b.cursor == len(b.groups) {
			return nil, fmt.Errorf("no free blocks")
		}
		g := &b.groups[b.cursor]
		n := min(count, g.count-g.next, 32768)
		start := g.start + g.next
		out = append(out, extent{logical: logical, physical: uint64(start), count: n})
		for i := uint32(0); i < n; i++ {
			bitSet(g.bitmap, g.next+i)
		}
		g.next += n
		logical += n
		count -= n
	}
	return out, nil
}
func extentHeader(dst []byte, count, depth uint16) {
	put16(dst, 0, 0xf30a)
	put16(dst, 2, count)
	put16(dst, 4, uint16((len(dst)-12)/12))
	put16(dst, 6, depth)
}
func extentLeaf(dst []byte, x []extent) {
	extentHeader(dst, uint16(len(x)), 0)
	for i, e := range x {
		off := 12 + i*12
		put32(dst, off, e.logical)
		put16(dst, off+4, uint16(e.count))
		put16(dst, off+6, uint16(e.physical>>32))
		put32(dst, off+8, uint32(e.physical))
	}
}

type extentIndex struct {
	logical uint32
	block   uint64
}

func extentIndices(dst []byte, items []extentIndex, depth uint16) {
	extentHeader(dst, uint16(len(items)), depth)
	for i, e := range items {
		off := 12 + i*12
		put32(dst, off, e.logical)
		put32(dst, off+4, uint32(e.block))
		put16(dst, off+8, uint16(e.block>>32))
	}
}
func (b *imageBuilder) extentRoot(root []byte, items []extent) (uint32, error) {
	if len(items) <= 4 {
		extentLeaf(root, items)
		return 0, nil
	}
	var indices []extentIndex
	var blocks uint32
	for at := 0; at < len(items); at += 340 {
		end := min(at+340, len(items))
		allocated, err := b.allocate(1)
		if err != nil {
			return 0, err
		}
		data := make([]byte, 4096)
		extentLeaf(data, items[at:end])
		block := allocated[0].physical
		b.addBytes(int64(block)*4096, data)
		indices = append(indices, extentIndex{items[at].logical, block})
		blocks++
	}
	depth := uint16(1)
	for len(indices) > 4 {
		var next []extentIndex
		for at := 0; at < len(indices); at += 340 {
			end := min(at+340, len(indices))
			allocated, err := b.allocate(1)
			if err != nil {
				return 0, err
			}
			data := make([]byte, 4096)
			extentIndices(data, indices[at:end], depth)
			block := allocated[0].physical
			b.addBytes(int64(block)*4096, data)
			next = append(next, extentIndex{indices[at].logical, block})
			blocks++
		}
		indices = next
		depth++
	}
	extentIndices(root, indices, depth)
	return blocks, nil
}
func directoryData(n *buildNode, parent uint32) ([]byte, error) {
	type dirent struct {
		name string
		ino  uint32
		typ  byte
	}
	items := []dirent{{".", n.ino, 2}, {"..", parent, 2}}
	for _, child := range n.children {
		name := path.Base(child.entry.Path)
		if len(name) > 255 || name == "." || name == ".." {
			return nil, fmt.Errorf("ext4: invalid directory name")
		}
		typ := map[uint32]byte{unixfs.Regular: 1, unixfs.Directory: 2, unixfs.Character: 3, unixfs.Block: 4, unixfs.FIFO: 5, unixfs.Socket: 6, unixfs.Symlink: 7}[child.entry.Mode&0170000]
		items = append(items, dirent{name, child.ino, typ})
	}
	var out []byte
	block := make([]byte, 4096)
	pos, last := 0, 0
	flush := func() {
		if pos > 0 {
			put16(block, last+4, uint16(4096-last))
			out = append(out, block...)
			block = make([]byte, 4096)
			pos = 0
		}
	}
	for _, e := range items {
		need := (8 + len(e.name) + 3) &^ 3
		if pos+need > 4096 {
			flush()
		}
		put32(block, pos, e.ino)
		put16(block, pos+4, uint16(need))
		block[pos+6] = byte(len(e.name))
		block[pos+7] = e.typ
		copy(block[pos+8:], e.name)
		last = pos
		pos += need
	}
	flush()
	return out, nil
}
