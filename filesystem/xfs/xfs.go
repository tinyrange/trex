// Package xfs reads version 4 and checksum-protected version 5 XFS volumes. Format facts follow the
// XFS project's Algorithms & Data Structures documentation; this reader does
// not use host filesystem drivers or replay the journal.
package xfs

import (
	"encoding/binary"
	"fmt"
	"math"
	"path"
	"strings"

	"github.com/tinyrange/trex/filesystem"
	starfile "github.com/tinyrange/trex/storage/star"
)

var be = binary.BigEndian

type Entry struct {
	Path, Kind         string
	Inode              uint64
	Mode               uint16
	UID, GID, Modified uint32
	Data               starfile.File
	local              bool
	extents            []extent
}
type Volume struct{ Entries []Entry }
type reader struct {
	file                                        starfile.File
	block, blocks, agBlocks, agCount, inodeSize uint64
	agLog, inoLog, dirLog                       byte
	dirV1                                       bool
	v5, ftype                                   bool
	uuid                                        [16]byte
	realtime                                    starfile.File
	rtBlocks                                    uint64
}

func (r *reader) physical(encoded, count uint64) (uint64, error) {
	ag, block := encoded>>r.agLog, encoded&((uint64(1)<<r.agLog)-1)
	if count == 0 || ag >= r.agCount || block >= r.agBlocks || count > r.agBlocks-block {
		return 0, fmt.Errorf("xfs: invalid physical extent")
	}
	start := ag*r.agBlocks + block
	if start >= r.blocks || count > r.blocks-start || (start+count)*r.block > uint64(r.file.Size()) {
		return 0, fmt.Errorf("xfs: extent outside image")
	}
	return start * r.block, nil
}

func (r *reader) inode(id uint64) (Entry, error) {
	e := Entry{Inode: id}
	offset, err := r.physical(id>>r.inoLog, 1)
	if err != nil {
		return e, err
	}
	offset += (id & ((uint64(1) << r.inoLog) - 1)) * r.inodeSize
	b := make([]byte, r.inodeSize)
	if _, err = starfile.ReadFullAt(r.file, b, int64(offset)); err != nil {
		return e, err
	}
	if be.Uint16(b) != 0x494e || (b[4] != 1 && b[4] != 2 && b[4] != 3) || (r.v5 != (b[4] == 3)) {
		return e, fmt.Errorf("xfs: invalid legacy inode %d", id)
	}
	if r.v5 {
		if err := checkCRC(b, 100); err != nil {
			return e, err
		}
		if be.Uint64(b[152:]) != id || string(b[160:176]) != string(r.uuid[:]) {
			return e, fmt.Errorf("xfs: inode identity mismatch")
		}
		if be.Uint64(b[120:])&((1<<3)|(1<<4)) != 0 {
			return e, fmt.Errorf("xfs: unsupported bigtime or large-extent inode")
		}
	}
	e.Mode, e.UID, e.GID, e.Modified = be.Uint16(b[2:]), be.Uint32(b[8:]), be.Uint32(b[12:]), be.Uint32(b[40:])
	switch e.Mode & 0170000 {
	case 0040000:
		e.Kind = "directory"
	case 0100000:
		e.Kind = "file"
	case 0120000:
		e.Kind = "symlink"
	case 0020000:
		e.Kind = "character_device"
	case 0060000:
		e.Kind = "block_device"
	case 0010000:
		e.Kind = "fifo"
	case 0140000:
		e.Kind = "socket"
	default:
		return e, fmt.Errorf("xfs: invalid inode mode %o", e.Mode)
	}
	if e.Kind != "file" && e.Kind != "directory" && e.Kind != "symlink" {
		return e, nil
	}
	realtime := be.Uint16(b[90:])&1 != 0
	if realtime && e.Kind != "file" {
		return e, fmt.Errorf("xfs: non-file realtime fork")
	}
	size := be.Uint64(b[56:])
	if size > math.MaxInt64 {
		return e, fmt.Errorf("xfs: inode size exceeds address range")
	}
	core := 100
	if r.v5 {
		core = 176
	}
	end := len(b)
	if b[82] != 0 {
		end = core + int(b[82])*8
	}
	if end > len(b) || end < core {
		return e, fmt.Errorf("xfs: invalid fork boundary")
	}
	fork := b[core:end]
	switch b[5] {
	case 1:
		if size > uint64(len(fork)) {
			return e, fmt.Errorf("xfs: oversized local fork")
		}
		e.local = true
		e.Data = &starfile.Bytes{Name: "xfs local fork", Data: fork[:size]}
	case 2, 3:
		count := uint64(be.Uint32(b[76:]))
		var records []extent
		if b[5] == 3 {
			records, err = r.bmap(fork, count, id)
			if err != nil {
				return e, err
			}
		} else {
			if count > uint64(len(fork)/16) {
				return e, fmt.Errorf("xfs: extent list exceeds fork")
			}
			for i := uint64(0); i < count; i++ {
				records = append(records, decodeExtent(fork[i*16:]))
			}
		}
		extents, err := r.dataExtents(records, size, realtime)
		if err != nil {
			return e, err
		}
		e.extents = records
		e.Data = filesystem.NewGeneratedImage(fmt.Sprintf("xfs inode %d", id), int64(size), extents)
	default:
		return e, fmt.Errorf("xfs: unsupported data fork format %d in inode %d", b[5], id)
	}
	return e, nil
}

type dirent struct {
	name  string
	inode uint64
}

func shortDirectory(data []byte) ([]dirent, error) { return shortDirectoryType(data, false) }
func shortDirectoryType(data []byte, ftype bool) ([]dirent, error) {
	if len(data) < 6 {
		return nil, fmt.Errorf("xfs: truncated short directory")
	}
	width := 4
	if data[1] != 0 {
		width = 8
	}
	pos := 2 + width
	var out []dirent
	for i := 0; i < int(data[0]); i++ {
		if pos+3 > len(data) {
			return nil, fmt.Errorf("xfs: truncated short directory entry")
		}
		n := int(data[pos])
		pos += 3
		extra := 0
		if ftype {
			extra = 1
		}
		if n == 0 || pos+n+width+extra > len(data) {
			return nil, fmt.Errorf("xfs: invalid short directory name")
		}
		name := string(data[pos : pos+n])
		pos += n
		if ftype {
			if data[pos] > 8 {
				return nil, fmt.Errorf("xfs: invalid directory file type")
			}
			pos++
		}
		id := uint64(be.Uint32(data[pos:]))
		if width == 8 {
			id = be.Uint64(data[pos:])
		}
		pos += width
		out = append(out, dirent{name, id})
	}
	if pos != len(data) {
		return nil, fmt.Errorf("xfs: trailing short directory bytes")
	}
	return out, nil
}
func blockDirectory(b []byte) ([]dirent, error) { return blockDirectoryType(b, false) }
func blockDirectoryType(b []byte, ftype bool) ([]dirent, error) {
	if len(b) < 24 {
		return nil, fmt.Errorf("xfs: truncated directory block")
	}
	end := len(b)
	switch be.Uint32(b) {
	case 0x58443242, 0x58444233:
		count, stale := uint64(be.Uint32(b[len(b)-8:])), uint64(be.Uint32(b[len(b)-4:]))
		if stale > count || count > uint64((len(b)-24)/8) {
			return nil, fmt.Errorf("xfs: invalid directory leaf count")
		}
		end -= 8 + int(count)*8
	case 0x58443244, 0x58444433:
	default:
		return nil, fmt.Errorf("xfs: invalid directory data magic %x", be.Uint32(b))
	}
	var out []dirent
	header := 16
	if be.Uint32(b) == 0x58444233 || be.Uint32(b) == 0x58444433 {
		header = 64
	}
	if len(b) < header {
		return nil, fmt.Errorf("xfs: truncated directory header")
	}
	for pos := header; pos < end; {
		if pos+4 > end {
			return nil, fmt.Errorf("xfs: truncated directory record")
		}
		unused := be.Uint16(b[pos:]) == 0xffff
		n := 0
		if unused {
			n = int(be.Uint16(b[pos+2:]))
		} else {
			if pos+9 > end {
				return nil, fmt.Errorf("xfs: truncated directory entry")
			}
			namesize := int(b[pos+8])
			if namesize == 0 {
				return nil, fmt.Errorf("xfs: empty directory name")
			}
			extra := 0
			if ftype {
				extra = 1
			}
			n = (9 + namesize + extra + 2 + 7) &^ 7
		}
		if n < 8 || n%8 != 0 || pos+n > end || int(be.Uint16(b[pos+n-2:])) != pos {
			return nil, fmt.Errorf("xfs: invalid directory record length or tag at %d", pos)
		}
		if !unused {
			if ftype && b[pos+9+int(b[pos+8])] > 8 {
				return nil, fmt.Errorf("xfs: invalid directory file type")
			}
			out = append(out, dirent{string(b[pos+9 : pos+9+int(b[pos+8])]), be.Uint64(b[pos:])})
		}
		pos += n
	}
	return out, nil
}

// Open enumerates the directory tree without following symlinks. File data is
// represented by borrowed extent views; unsupported generations fail explicitly.
func Open(file starfile.File, maximumEntries int) (*Volume, error) {
	return OpenRealtime(file, nil, maximumEntries)
}

// OpenRealtime accepts the separate realtime device explicitly; no device is inferred.
func OpenRealtime(file, realtime starfile.File, maximumEntries int) (*Volume, error) {
	if maximumEntries <= 0 {
		return nil, fmt.Errorf("xfs: maximum_entries must be positive")
	}
	var b [264]byte
	if _, err := starfile.ReadFullAt(file, b[:], 0); err != nil {
		return nil, err
	}
	version := be.Uint16(b[100:]) & 15
	if be.Uint32(b[:]) != 0x58465342 || (version != 4 && version != 5) {
		return nil, fmt.Errorf("xfs: expected version 4 or 5 superblock")
	}

	r := reader{file: file, block: uint64(be.Uint32(b[4:])), blocks: be.Uint64(b[8:]), agBlocks: uint64(be.Uint32(b[84:])), agCount: uint64(be.Uint32(b[88:])), inodeSize: uint64(be.Uint16(b[104:])), agLog: b[124], inoLog: b[123], dirLog: b[192]}
	if b[120] > 16 || b[120] < 9 || r.block != uint64(1)<<b[120] || r.inodeSize < 256 || r.inodeSize > r.block || b[122] > 16 || r.inodeSize != uint64(1)<<b[122] || r.inoLog > 8 || r.inodeSize<<r.inoLog != r.block || r.agLog > 32 || r.agBlocks == 0 || r.agBlocks > uint64(1)<<r.agLog || r.agCount == 0 || r.blocks == 0 || r.blocks > math.MaxInt64/r.block || r.blocks*r.block > uint64(file.Size()) || (r.agCount-1)*r.agBlocks >= r.blocks || r.agCount*r.agBlocks < r.blocks || r.dirLog > 7 || r.block<<r.dirLog > 65536 {
		return nil, fmt.Errorf("xfs: invalid or truncated geometry")
	}
	r.v5 = version == 5
	r.realtime = realtime
	r.rtBlocks = be.Uint64(b[16:])
	copy(r.uuid[:], b[32:48])
	r.ftype = be.Uint32(b[200:])&0x200 != 0
	if r.v5 {
		incompat := be.Uint32(b[216:])
		if incompat&^uint32(7) != 0 || be.Uint32(b[220:]) != 0 {
			return nil, fmt.Errorf("xfs: unsupported incompatible feature bits")
		}
		r.ftype = incompat&1 != 0
		if incompat&4 != 0 {
			copy(r.uuid[:], b[248:264])
		}
		sector := uint64(be.Uint16(b[102:]))
		if sector < 512 || sector > r.block || sector&(sector-1) != 0 {
			return nil, fmt.Errorf("xfs: invalid superblock sector size")
		}
		full := make([]byte, sector)
		if _, err := starfile.ReadFullAt(file, full, 0); err != nil {
			return nil, err
		}
		if err := checkCRC(full, 224); err != nil {
			return nil, err
		}
	}
	if realtime != nil && (r.rtBlocks == 0 || r.rtBlocks > math.MaxInt64/r.block || r.rtBlocks*r.block > uint64(realtime.Size())) {
		return nil, fmt.Errorf("xfs: invalid realtime geometry")
	}
	r.dirV1 = !r.v5 && be.Uint16(b[100:])&0x2000 == 0
	root, err := r.inode(be.Uint64(b[56:]))
	if err != nil {
		return nil, err
	}
	if root.Kind != "directory" {
		return nil, fmt.Errorf("xfs: root is not a directory")
	}
	root.Path = "/"
	v := &Volume{Entries: []Entry{root}}
	seenDirs := map[uint64]bool{root.Inode: true}
	seenPaths := map[string]bool{"/": true}
	for index := 0; index < len(v.Entries); index++ {
		dir := v.Entries[index]
		if dir.Kind != "directory" {
			continue
		}
		var children []dirent
		if r.dirV1 {
			children, err = r.directoryV1(dir, maximumEntries)
			if err != nil {
				return nil, fmt.Errorf("xfs: directory %s: %w", dir.Path, err)
			}
		} else if dir.local {
			data, err := starfile.ReadAll(dir.Data)
			if err != nil {
				return nil, err
			}
			children, err = shortDirectoryType(data, r.ftype)
			if err != nil {
				return nil, err
			}
		} else {
			size := int64(r.block << r.dirLog)
			if dir.Data.Size()%size != 0 || dir.Data.Size()/size > int64(maximumEntries) {
				return nil, fmt.Errorf("xfs: invalid directory size")
			}
			block := make([]byte, size)
			for off := int64(0); off < dir.Data.Size(); off += size {
				if _, err := starfile.ReadFullAt(dir.Data, block, off); err != nil {
					return nil, err
				}
				if r.v5 {
					physical, err := r.directoryPhysical(dir, uint64(off))
					if err != nil {
						return nil, err
					}
					if err = r.metadata(block, 4, 24, 40, 8, dir.Inode, physical); err != nil {
						return nil, err
					}
					magic := be.Uint32(block)
					if magic != 0x58444233 && magic != 0x58444433 {
						return nil, fmt.Errorf("xfs: expected version 3 directory data")
					}
				}
				entries, err := blockDirectoryType(block, r.ftype)
				if err != nil {
					return nil, fmt.Errorf("xfs: directory %s: %w", dir.Path, err)
				}
				children = append(children, entries...)
			}
		}
		for _, child := range children {
			if child.name == "." || child.name == ".." {
				continue
			}
			if child.name == "" || strings.ContainsAny(child.name, "/\x00") {
				return nil, fmt.Errorf("xfs: invalid directory name")
			}
			name := path.Join(dir.Path, child.name)
			if seenPaths[name] {
				return nil, fmt.Errorf("xfs: duplicate path %s", name)
			}
			seenPaths[name] = true
			if len(v.Entries) >= maximumEntries {
				return nil, fmt.Errorf("xfs: entry limit exceeded")
			}
			e, err := r.inode(child.inode)
			if err != nil {
				return nil, fmt.Errorf("xfs: %s: %w", name, err)
			}
			e.Path = name
			if e.Kind == "directory" {
				if seenDirs[e.Inode] {
					return nil, fmt.Errorf("xfs: directory cycle or alias")
				}
				seenDirs[e.Inode] = true
			}
			v.Entries = append(v.Entries, e)
		}
	}
	return v, nil
}
