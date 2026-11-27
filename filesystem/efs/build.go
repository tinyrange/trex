package efs

import (
	"fmt"
	"math"
	"math/bits"
	"path"
	"sort"
	"strings"

	"github.com/tinyrange/trex/filesystem"
	"github.com/tinyrange/trex/filesystem/unixfs"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

const (
	inodeSize      = 128
	inodesPerBlock = sectorSize / inodeSize
	extentLimit    = 248
	maxEFSBlocks   = 1<<24 - 1
)

type diskExtent struct {
	start, count, logical uint32
}

func (e diskExtent) encode(out []byte) {
	out[1], out[2], out[3] = byte(e.start>>16), byte(e.start>>8), byte(e.start)
	out[4] = byte(e.count)
	out[5], out[6], out[7] = byte(e.logical>>16), byte(e.logical>>8), byte(e.logical)
}

type efsBuilder struct {
	firstGroup, groups, groupSize, inodeBlocks uint32
	bitmap                                     []byte
	free, next                                 uint32
	inodes                                     [][]byte
	parts                                      []filesystem.ExtentSpec
}

func (b *efsBuilder) addBytes(start uint32, data []byte) {
	b.parts = append(b.parts, filesystem.ExtentSpec{Start: int64(start) * sectorSize, Size: int64(len(data)), Data: data})
}

func (b *efsBuilder) allocate(file storage.Reader) ([]diskExtent, error) {
	size := file.Size()
	if size < 0 || size > math.MaxInt32 {
		return nil, fmt.Errorf("invalid EFS file size %d", size)
	}
	total := uint32(storage.CeilDiv(size, sectorSize))
	if total > b.free {
		return nil, fmt.Errorf("EFS volume is full")
	}
	if total == 0 {
		return nil, nil
	}
	view := starfile.NewReader("EFS data", file)
	var extents []diskExtent
	for logical := uint32(0); logical < total; {
		groupEnd := b.next - (b.next-b.firstGroup)%b.groupSize + b.groupSize
		n := min(uint32(extentLimit), total-logical, groupEnd-b.next)
		start := b.next
		extents = append(extents, diskExtent{start, n, logical})
		offset := int64(logical) * sectorSize
		b.parts = append(b.parts, filesystem.ExtentSpec{
			Start: int64(start) * sectorSize, Size: min(int64(n)*sectorSize, size-offset), Offset: offset, File: view,
		})
		for block := start; block < start+n; block++ {
			b.bitmap[block/8] &^= 1 << (block % 8)
		}
		logical += n
		b.next += n
		b.free -= n
		if b.next == groupEnd {
			b.next += b.inodeBlocks
		}
	}
	return extents, nil
}

type dirItem struct {
	name string
	id   uint32
}

func efsDirectory(rows []dirItem) ([]byte, error) {
	var directory []byte
	for len(rows) != 0 {
		var block [sectorSize]byte
		be.PutUint16(block[:], 0xbeef)
		next, slots := len(block), 0
		for _, entry := range rows {
			length := len(entry.name)
			if length < 1 || length > 255 {
				return nil, fmt.Errorf("invalid EFS name %q", entry.name)
			}
			need := (5 + length + 1) &^ 1
			if next-need < 4+slots+1 {
				break
			}
			next -= need
			block[4+slots] = byte(next / 2)
			be.PutUint32(block[next:], entry.id)
			block[next+4] = byte(length)
			copy(block[next+5:], entry.name)
			slots++
		}
		block[2], block[3] = byte(next/2), byte(slots)
		directory = append(directory, block[:]...)
		rows = rows[slots:]
	}
	return directory, nil
}

func (b *efsBuilder) inode(id, links uint32, entry unixfs.Entry, file storage.Reader) error {
	if links > math.MaxInt16 || entry.UID > math.MaxUint16 || entry.GID > math.MaxUint16 {
		return fmt.Errorf("EFS inode metadata outside supported range for %q", entry.Path)
	}
	perGroup := b.inodeBlocks * inodesPerBlock
	group, index := id/perGroup, id%perGroup
	if b.inodes[group] == nil {
		b.inodes[group] = make([]byte, int(b.inodeBlocks)*sectorSize)
	}
	inode := b.inodes[group][index*inodeSize : (index+1)*inodeSize]
	be.PutUint16(inode, uint16(entry.Mode))
	be.PutUint16(inode[2:], uint16(links))
	be.PutUint16(inode[4:], uint16(entry.UID))
	be.PutUint16(inode[6:], uint16(entry.GID))
	for _, offset := range [...]int{12, 16, 20} {
		be.PutUint32(inode[offset:], entry.Mtime)
	}
	be.PutUint32(inode[24:], id)
	if entry.Mode&0170000 == unixfs.Character || entry.Mode&0170000 == unixfs.Block {
		return encodeDevice(inode, entry.Major, entry.Minor)
	}
	if file == nil {
		return nil
	}
	extents, err := b.allocate(file)
	if err != nil {
		return fmt.Errorf("%s: %w", entry.Path, err)
	}
	be.PutUint32(inode[8:], uint32(file.Size()))
	if len(extents) > math.MaxInt16 {
		return fmt.Errorf("too many EFS extents for %q", entry.Path)
	}
	be.PutUint16(inode[28:], uint16(len(extents)))
	if len(extents) > 12 {
		records := make([]byte, len(extents)*8)
		for i, extent := range extents {
			extent.encode(records[i*8:])
		}
		extents, err = b.allocate(&starfile.Bytes{Data: records})
		if err != nil {
			return err
		}
		if len(extents) > 12 {
			return fmt.Errorf("too many indirect EFS extents for %q", entry.Path)
		}
		extents[0].logical = uint32(len(extents))
	}
	for i, extent := range extents {
		extent.encode(inode[32+8*i:])
	}
	return nil
}

func encodeDevice(inode []byte, major, minor uint32) error {
	if major < 128 && minor < 256 {
		be.PutUint16(inode[32:], uint16(major<<8|minor))
		return nil
	}
	if major >= 512 || minor >= 1<<18 {
		return fmt.Errorf("EFS device number outside supported range")
	}
	be.PutUint16(inode[32:], 0xffff)
	be.PutUint32(inode[36:], major<<18|minor)
	return nil
}

func newEFSBuilder(size int64, entries int) (*efsBuilder, error) {
	if size < 256<<10 || size%sectorSize != 0 || size/sectorSize > maxEFSBlocks {
		return nil, fmt.Errorf("EFS requires 256 KiB to %d bytes in 512-byte blocks", maxEFSBlocks*sectorSize)
	}
	blocks := uint32(size / sectorSize)
	first := uint32(storage.Align(2+storage.CeilDiv(int64(blocks), 8*sectorSize), 32))
	available := blocks - first
	groupSize := min(uint32(8192), available)
	groups := available / groupSize
	perGroup := uint32(storage.CeilDiv(int64(entries)+2, int64(groups)*inodesPerBlock))
	inodeBlocks := max(uint32(8), perGroup*2)
	if inodeBlocks >= groupSize {
		return nil, fmt.Errorf("EFS volume has insufficient space for inodes")
	}
	b := &efsBuilder{
		firstGroup: first, groupSize: groupSize, groups: groups, inodeBlocks: inodeBlocks,
		bitmap: make([]byte, storage.CeilDiv(int64(first+groups*groupSize), 8)),
		inodes: make([][]byte, groups), free: (groupSize - inodeBlocks) * groups, next: first + inodeBlocks,
	}
	for group := uint32(0); group < groups; group++ {
		start := first + group*groupSize
		for block := start + inodeBlocks; block < start+groupSize; block++ {
			b.bitmap[block/8] |= 1 << (block % 8)
		}
	}
	return b, nil
}

// Build constructs a writable-on-overlay EFS volume. The returned image
// borrows file payloads and supplies unallocated sectors as zeroes.
func Build(input []unixfs.Entry, size int64, label string, modified uint32) (starfile.File, error) {
	if len(label) > 6 || strings.ContainsRune(label, 0) {
		return nil, fmt.Errorf("EFS label must be at most six bytes")
	}
	entries, err := unixfs.Normalize(input)
	if err != nil {
		return nil, err
	}
	b, err := newEFSBuilder(size, len(entries))
	if err != nil {
		return nil, err
	}
	ids := make(map[string]uint32, len(entries))
	nextID := uint32(2)
	for _, entry := range entries {
		if !entry.Hardlink {
			ids[entry.Path] = nextID
			nextID++
		}
	}
	children := make(map[string][]dirItem)
	links := make([]uint32, nextID)
	for _, entry := range entries {
		if entry.Hardlink {
			ids[entry.Path] = ids[entry.Target]
		}
		id := ids[entry.Path]
		links[id]++
		parent := path.Dir(entry.Path)
		if entry.Mode&0170000 == unixfs.Directory {
			if entry.Path != "." {
				links[id]++ // The directory's own "." entry.
			}
			children[entry.Path] = append([]dirItem{{".", id}, {"..", ids[parent]}}, children[entry.Path]...)
			links[ids[parent]]++
		}
		if entry.Path != "." {
			children[parent] = append(children[parent], dirItem{path.Base(entry.Path), id})
		}
	}
	for _, entry := range entries {
		if entry.Hardlink {
			continue
		}
		file := entry.Data
		switch entry.Mode & 0170000 {
		case unixfs.Directory:
			payload, err := efsDirectory(children[entry.Path])
			if err != nil {
				return nil, err
			}
			file = &starfile.Bytes{Data: payload}
		case unixfs.Symlink:
			file = &starfile.Bytes{Data: []byte(entry.Target)}
		}
		id := ids[entry.Path]
		if err := b.inode(id, links[id], entry, file); err != nil {
			return nil, err
		}
	}

	sb := make([]byte, sectorSize)
	blocks := b.firstGroup + b.groups*b.groupSize
	be.PutUint32(sb, blocks)
	be.PutUint32(sb[4:], b.firstGroup)
	be.PutUint32(sb[8:], b.groupSize)
	be.PutUint16(sb[12:], uint16(b.inodeBlocks))
	be.PutUint16(sb[14:], 32)
	be.PutUint16(sb[16:], 8)
	be.PutUint16(sb[18:], uint16(b.groups))
	be.PutUint32(sb[24:], modified)
	be.PutUint32(sb[28:], 0x072959)
	copy(sb[32:38], label)
	copy(sb[38:44], "nopack")
	be.PutUint32(sb[44:], uint32(len(b.bitmap)))
	be.PutUint32(sb[48:], b.free)
	be.PutUint32(sb[52:], b.groups*b.inodeBlocks*inodesPerBlock-nextID)
	var checksum uint32
	for i := 0; i < 88; i += 2 {
		checksum = bits.RotateLeft32(checksum^uint32(be.Uint16(sb[i:])), 1)
	}
	be.PutUint32(sb[88:], checksum)
	b.addBytes(1, sb)
	b.addBytes(2, b.bitmap)
	for i, inodes := range b.inodes {
		if inodes != nil {
			b.addBytes(b.firstGroup+uint32(i)*b.groupSize, inodes)
		}
	}
	sort.Slice(b.parts, func(i, j int) bool { return b.parts[i].Start < b.parts[j].Start })
	return filesystem.NewGeneratedImage("EFS filesystem", int64(blocks)*sectorSize, b.parts), nil
}

func BuildBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	var size int64
	var modified uint32
	var label string
	if err := starlark.UnpackArgs("efs_build", args, kwargs, "entries", &value, "size", &size,
		"label?", &label, "modified?", &modified); err != nil {
		return nil, err
	}
	entries, err := unixfs.ParseEntries(value)
	if err != nil {
		return nil, err
	}
	return Build(entries, size, label, modified)
}
