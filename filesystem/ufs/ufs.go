// Package ufs reads historical and 4.4BSD UFS1 (including OpenBSD FFS1).
// Geometry and inode layout facts are documented by NetBSD's sys/ufs/ffs/fs.h
// and OpenBSD's sys/ufs/{ffs/fs.h,ufs/dinode.h,ufs/dir.h}.
// This reader never mounts a filesystem.
package ufs

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/tinyrange/trex/filesystem"
	starfile "github.com/tinyrange/trex/storage/star"
)

type Entry struct {
	Path, Kind                                 string
	Inode                                      uint32
	Mode, Links                                uint16
	UID, GID                                   uint32
	Accessed, Modified, Changed, Flags, Device uint32
	Data                                       starfile.File
}
type Volume struct {
	Entries                         []Entry
	BlockSize, FragmentSize, Groups uint32
	InodeFormat                     int32
}
type reader struct {
	file                                                                 starfile.File
	order                                                                binary.ByteOrder
	block, fragment, groups, ipg, fpg, inodeBase, groupOffset, groupMask uint32
	limit                                                                uint64
	remaining                                                            int
	cache                                                                map[uint32]Entry
	modern                                                               bool
	inodeFormat                                                          int32
	maxSymlink                                                           uint64
}

func (r *reader) rangeOK(offset, size uint64) bool {
	return offset <= r.limit && size <= r.limit-offset && offset <= uint64(r.file.Size()) && size <= uint64(r.file.Size())-offset
}
func (r *reader) contents(raw []byte, size uint64) (starfile.File, error) {
	if size > math.MaxInt64 {
		return nil, fmt.Errorf("ufs: file size exceeds address space")
	}
	specs := []filesystem.ExtentSpec{}
	position := uint64(0)
	ancestors := map[uint32]bool{}
	var visit func(uint32, int) error
	visit = func(pointer uint32, level int) error {
		if position == size {
			return nil
		}
		if r.remaining == 0 {
			return fmt.Errorf("ufs: block mapping limit exceeded")
		}
		r.remaining--
		capacity := uint64(r.block)
		for i := 0; i < level; i++ {
			capacity *= uint64(r.block / 4)
		}
		length := min(capacity, size-position)
		if pointer == 0 {
			position += length
			return nil
		}
		offset := uint64(pointer) * uint64(r.fragment)
		if ancestors[pointer] {
			return fmt.Errorf("ufs: cyclic indirect block")
		}
		if level == 0 {
			if !r.rangeOK(offset, length) {
				return fmt.Errorf("ufs: data extent outside filesystem")
			}
			specs = append(specs, filesystem.ExtentSpec{Start: int64(position), Size: int64(length), File: r.file, Offset: int64(offset)})
			position += length
			return nil
		}
		if !r.rangeOK(offset, uint64(r.block)) {
			return fmt.Errorf("ufs: indirect block outside filesystem")
		}
		buf := make([]byte, r.block)
		ancestors[pointer] = true
		defer delete(ancestors, pointer)
		if _, err := starfile.ReadFullAt(r.file, buf, int64(offset)); err != nil {
			return err
		}
		for i := 0; i < len(buf) && position < size; i += 4 {
			if err := visit(r.order.Uint32(buf[i:]), level-1); err != nil {
				return err
			}
		}
		return nil
	}
	for i := 0; i < 12 && position < size; i++ {
		if err := visit(r.order.Uint32(raw[40+i*4:]), 0); err != nil {
			return nil, err
		}
	}
	for level := 1; level <= 3 && position < size; level++ {
		if err := visit(r.order.Uint32(raw[88+(level-1)*4:]), level); err != nil {
			return nil, err
		}
	}
	if position != size {
		return nil, fmt.Errorf("ufs: size exceeds inode block addressing")
	}
	return filesystem.NewGeneratedImage("ufs file", int64(size), specs), nil
}
func (r *reader) inode(number uint32) (Entry, error) {
	if e, ok := r.cache[number]; ok {
		return e, nil
	}
	e := Entry{Inode: number}
	if number < 2 || uint64(number) >= uint64(r.groups)*uint64(r.ipg) {
		return e, fmt.Errorf("ufs: inode outside groups")
	}
	group := number / r.ipg
	base := uint64(group)*uint64(r.fpg) + uint64(r.groupOffset)*uint64(group & ^r.groupMask) + uint64(r.inodeBase)
	offset := base*uint64(r.fragment) + uint64(number%r.ipg)*128
	if !r.rangeOK(offset, 128) {
		return e, fmt.Errorf("ufs: inode outside filesystem")
	}
	var raw [128]byte
	if _, err := starfile.ReadFullAt(r.file, raw[:], int64(offset)); err != nil {
		return e, err
	}
	e.Mode = r.order.Uint16(raw[:])
	e.Links = r.order.Uint16(raw[2:])
	e.UID = uint32(r.order.Uint16(raw[4:]))
	e.GID = uint32(r.order.Uint16(raw[6:]))
	if r.modern {
		e.UID = r.order.Uint32(raw[112:])
		e.GID = r.order.Uint32(raw[116:])
	}
	e.Accessed = r.order.Uint32(raw[16:])
	e.Modified = r.order.Uint32(raw[24:])
	e.Changed = r.order.Uint32(raw[32:])
	e.Flags = r.order.Uint32(raw[100:])
	size := r.order.Uint64(raw[8:])
	switch e.Mode & 0xf000 {
	case 0x4000:
		e.Kind = "directory"
	case 0x8000:
		e.Kind = "file"
	case 0xa000:
		e.Kind = "symlink"
	case 0x2000:
		e.Kind = "character_device"
	case 0x6000:
		e.Kind = "block_device"
	case 0x1000:
		e.Kind = "fifo"
	case 0xc000:
		e.Kind = "socket"
	default:
		return e, fmt.Errorf("ufs: unsupported inode mode %#x", e.Mode)
	}
	if e.Links == 0 {
		return e, fmt.Errorf("ufs: directory references unlinked inode")
	}
	if e.Kind == "symlink" && r.modern && size < r.maxSymlink {
		// Short links occupy the direct/indirect pointer area, not disk blocks.
		e.Data = &starfile.Bytes{Data: append([]byte(nil), raw[40:40+size]...)}
	} else if e.Kind == "file" || e.Kind == "directory" || e.Kind == "symlink" {
		var err error
		e.Data, err = r.contents(raw[:], size)
		if err != nil {
			return e, fmt.Errorf("ufs: inode %d: %w", number, err)
		}
	} else {
		e.Device = r.order.Uint32(raw[40:])
		e.Data = &starfile.Bytes{}
	}
	r.cache[number] = e
	return e, nil
}

// Open enumerates UFS1 directories, preserving hard-link inode
// identities. maximumBlocks bounds total data/indirect mapping work; file
// contents remain borrowed views, and zero pointers remain sparse zeroes.
// The declared inode format selects historical or 4.4BSD inode/directory
// semantics. Short 4.4BSD symlinks are exposed as bytes, never followed.
func Open(file starfile.File, maximumEntries, maximumBlocks int) (*Volume, error) {
	r, root, err := openReader(file, maximumEntries, maximumBlocks)
	if err != nil {
		return nil, err
	}
	entries, err := walk(root, r.order, maximumEntries, r.inode, r.modern)
	if err != nil {
		return nil, err
	}
	return &Volume{Entries: entries, BlockSize: r.block, FragmentSize: r.fragment, Groups: r.groups, InodeFormat: r.inodeFormat}, nil
}

func openReader(file starfile.File, maximumEntries, maximumBlocks int) (*reader, Entry, error) {
	if maximumEntries < 1 || maximumBlocks < 1 || file.Size() < 8192+1376 {
		return nil, Entry{}, fmt.Errorf("ufs: invalid input or limits")
	}
	var sb [1376]byte
	if _, err := starfile.ReadFullAt(file, sb[:], 8192); err != nil {
		return nil, Entry{}, err
	}
	var order binary.ByteOrder
	switch {
	case binary.LittleEndian.Uint32(sb[1372:]) == 0x11954:
		order = binary.LittleEndian
	case binary.BigEndian.Uint32(sb[1372:]) == 0x11954:
		order = binary.BigEndian
	default:
		return nil, Entry{}, fmt.Errorf("ufs: expected UFS1 superblock")
	}
	r := reader{file: file, order: order, block: order.Uint32(sb[48:]), fragment: order.Uint32(sb[52:]), groups: order.Uint32(sb[44:]), ipg: order.Uint32(sb[184:]), fpg: order.Uint32(sb[188:]), inodeBase: order.Uint32(sb[16:]), groupOffset: order.Uint32(sb[24:]), groupMask: order.Uint32(sb[28:]), remaining: maximumBlocks, cache: map[uint32]Entry{}}
	r.inodeFormat = int32(order.Uint32(sb[1324:]))
	switch r.inodeFormat {
	case -1, 0: // 4.2BSD; old media may leave the later format field zero.
	case 2: // FS_44INODEFMT
		r.modern = true
		r.maxSymlink = uint64(order.Uint32(sb[1320:]))
		if r.maxSymlink > 60 {
			return nil, Entry{}, fmt.Errorf("ufs: invalid inline symlink capacity")
		}
	default:
		return nil, Entry{}, fmt.Errorf("ufs: unsupported inode format %d", r.inodeFormat)
	}
	r.limit = uint64(order.Uint32(sb[36:])) * uint64(r.fragment)
	if r.block < 4096 || r.block > 65536 || r.block&(r.block-1) != 0 || r.fragment < 512 || r.fragment > r.block || r.fragment&(r.fragment-1) != 0 || r.block/r.fragment > 8 || order.Uint32(sb[56:]) != r.block/r.fragment || order.Uint32(sb[116:]) != r.block/4 || order.Uint32(sb[120:]) != r.block/128 || r.groups == 0 || r.ipg == 0 || r.fpg == 0 || r.inodeBase == 0 || r.ipg%(r.block/128) != 0 || r.limit > uint64(file.Size()) || r.limit < 8192+1376 {
		return nil, Entry{}, fmt.Errorf("ufs: invalid UFS1 geometry")
	}
	if uint64(r.inodeBase)*uint64(r.fragment)+uint64(r.ipg)*128 > uint64(r.fpg)*uint64(r.fragment) {
		return nil, Entry{}, fmt.Errorf("ufs: inode table exceeds group")
	}
	fragments := uint64(order.Uint32(sb[36:]))
	if uint64(r.groups) != (fragments+uint64(r.fpg)-1)/uint64(r.fpg) || r.groupOffset > r.fpg {
		return nil, Entry{}, fmt.Errorf("ufs: cylinder groups exceed filesystem geometry")
	}
	root, err := r.inode(2)
	if err != nil {
		return nil, Entry{}, err
	}
	if root.Kind != "directory" {
		return nil, Entry{}, fmt.Errorf("ufs: root is not a directory")
	}
	return &r, root, nil
}
