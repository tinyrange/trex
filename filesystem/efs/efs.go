// Package efs reads IRIX Extent File System volumes. Geometry, inode and extent
// layouts follow SGI's efs(4)/inode(4) documentation (007-2159-004, pp.42–44,
// 108–109). Directory slot layout is validated against the original media.
package efs

import (
	"encoding/binary"
	"fmt"
	filesystem "github.com/tinyrange/trex/filesystem"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"path"
	"strings"
)

const sectorSize = 512

type Entry struct {
	Path, Kind     string
	Inode          uint32
	Mode, UID, GID uint16
	Modified       uint32
	Data           starfile.File
}
type Volume struct{ Entries []Entry }
type reader struct {
	file                       starfile.File
	blocks, firstCG, groupSize uint32
	inodeBlocks, groups        uint16
}

var be = binary.BigEndian

func u24(p []byte) uint32 { return uint32(p[0])<<16 | uint32(p[1])<<8 | uint32(p[2]) }

func (r *reader) inode(id uint32) (Entry, error) {
	perGroup := uint32(r.inodeBlocks) * 4
	if id >= perGroup*uint32(r.groups) {
		return Entry{}, fmt.Errorf("efs: inode %d outside geometry", id)
	}
	off := (int64(r.firstCG)+int64(id/perGroup)*int64(r.groupSize))*sectorSize + int64(id%perGroup)*128
	var b [128]byte
	if _, err := starfile.ReadFullAt(r.file, b[:], off); err != nil {
		return Entry{}, err
	}
	e := Entry{Inode: id, Mode: be.Uint16(b[:]), UID: be.Uint16(b[4:]), GID: be.Uint16(b[6:]), Modified: be.Uint32(b[16:])}
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
		return e, fmt.Errorf("efs: invalid inode mode %o for %d", e.Mode, id)
	}
	size := int64(be.Uint32(b[8:]))
	count := int(be.Uint16(b[28:]))
	if e.Kind != "file" && e.Kind != "directory" && e.Kind != "symlink" {
		return e, nil
	}
	if e.Kind == "symlink" && count == 0 {
		if size > 96 {
			return e, fmt.Errorf("efs: inline symlink too large")
		}
		e.Data = &starfile.Bytes{Name: "efs symlink", Data: append([]byte(nil), b[32:32+size]...)}
		return e, nil
	}
	var extents []filesystem.ExtentSpec
	var end int64
	add := func(p []byte) error {
		start, length, logical := int64(u24(p[1:4])), int64(p[4]), int64(u24(p[5:8]))
		if p[0] != 0 || length == 0 || start+length > int64(r.blocks) || (start+length)*sectorSize > r.file.Size() {
			return fmt.Errorf("efs: invalid extent for inode %d", id)
		}
		if logical*sectorSize < end {
			return fmt.Errorf("efs: overlapping or unordered extents for inode %d", id)
		}
		if logical*sectorSize < size {
			extents = append(extents, filesystem.ExtentSpec{Start: logical * sectorSize, Size: min(length*sectorSize, size-logical*sectorSize), File: r.file, Offset: start * sectorSize})
		}
		end = (logical + length) * sectorSize
		return nil
	}
	if count <= 12 {
		for i := 0; i < count; i++ {
			if err := add(b[32+i*8 : 40+i*8]); err != nil {
				return e, err
			}
		}
	} else {
		indirect := int(u24(b[37:40]))
		if indirect < 1 || indirect > 12 {
			return e, fmt.Errorf("efs: invalid indirect extent count")
		}
		remaining := count
		for i := 0; i < indirect; i++ {
			p := b[32+i*8 : 40+i*8]
			start, length := int64(u24(p[1:4])), int64(p[4])
			if p[0] != 0 || length == 0 || start+length > int64(r.blocks) || (start+length)*sectorSize > r.file.Size() {
				return e, fmt.Errorf("efs: invalid indirect range")
			}
			for block := int64(0); block < length && remaining > 0; block++ {
				var descriptors [512]byte
				if _, err := starfile.ReadFullAt(r.file, descriptors[:], (start+block)*sectorSize); err != nil {
					return e, err
				}
				for j := 0; j < 64 && remaining > 0; j++ {
					if err := add(descriptors[j*8 : j*8+8]); err != nil {
						return e, err
					}
					remaining--
				}
			}
		}
		if remaining != 0 {
			return e, fmt.Errorf("efs: missing indirect extents")
		}
	}
	if end < size {
		return e, fmt.Errorf("efs: extents shorter than inode %d size", id)
	}
	e.Data = filesystem.NewGeneratedImage(fmt.Sprintf("efs inode %d", id), size, extents)
	return e, nil
}

// Open reads the directory tree and inode metadata; regular file contents stay
// as borrowed extent views. Symbolic links are exposed, never followed.
func Open(file starfile.File, maximumEntries int) (*Volume, error) {
	if maximumEntries <= 0 {
		return nil, fmt.Errorf("efs: maximum_entries must be positive")
	}
	var b [512]byte
	if _, err := starfile.ReadFullAt(file, b[:], 512); err != nil {
		return nil, err
	}
	magic := be.Uint32(b[28:])
	if magic != 0x072959 && magic != 0x07295a {
		return nil, fmt.Errorf("efs: invalid superblock magic %x", magic)
	}
	r := reader{file: file, blocks: be.Uint32(b[:]), firstCG: be.Uint32(b[4:]), groupSize: be.Uint32(b[8:]), inodeBlocks: be.Uint16(b[12:]), groups: be.Uint16(b[18:])}
	if r.blocks == 0 || r.groups == 0 || r.inodeBlocks == 0 || uint32(r.inodeBlocks) > r.groupSize || uint64(r.firstCG)+uint64(r.groups-1)*uint64(r.groupSize)+uint64(r.inodeBlocks) > uint64(r.blocks) {
		return nil, fmt.Errorf("efs: invalid geometry")
	}
	if int64(r.blocks)*sectorSize > file.Size() {
		// Standalone miniroots can omit the free end of their nominal
		// filesystem. Prove the omitted range is free from the on-media
		// allocation bitmap; never synthesize bytes for allocated extents.
		if file.Size()%sectorSize != 0 {
			return nil, fmt.Errorf("efs: partial trailing sector")
		}
		bitmapBytes := int64(be.Uint32(b[44:]))
		bitmapBlock := int64(be.Uint32(b[56:]))
		if bitmapBlock == 0 {
			bitmapBlock = 2
		}
		end := (int64(r.blocks) + 7) / 8
		if bitmapBytes < end || bitmapBlock*sectorSize > file.Size()-bitmapBytes {
			return nil, fmt.Errorf("efs: missing allocation bitmap for trimmed image")
		}
		var bits [4096]byte
		firstMissing := file.Size() / sectorSize
		for off := firstMissing / 8; off < end; {
			n := min(int64(len(bits)), end-off)
			if _, err := starfile.ReadFullAt(file, bits[:n], bitmapBlock*sectorSize+off); err != nil {
				return nil, err
			}
			for i, value := range bits[:n] {
				// EFS numbers allocation bits low-to-high within each byte.
				// Only omitted blocks matter at either boundary; adjacent
				// present blocks may be allocated and must not be rejected.
				block := (off + int64(i)) * 8
				lo, hi := max(int64(0), firstMissing-block), min(int64(8), int64(r.blocks)-block)
				mask := byte((uint16(1)<<hi - 1) &^ (uint16(1)<<lo - 1))
				if value&mask != mask {
					return nil, fmt.Errorf("efs: trimmed image omits allocated blocks")
				}
			}
			off += n
		}
	}
	root, err := r.inode(2)
	if err != nil {
		return nil, err
	}
	if root.Kind != "directory" {
		return nil, fmt.Errorf("efs: root is not directory")
	}
	root.Path = "/"
	v := &Volume{Entries: []Entry{root}}
	seenDirs := map[uint32]bool{2: true}
	seenPaths := map[string]bool{"/": true}
	for index := 0; index < len(v.Entries); index++ {
		dir := v.Entries[index]
		if dir.Kind != "directory" {
			continue
		}
		if dir.Data.Size()%512 != 0 {
			return nil, fmt.Errorf("efs: unaligned directory %s", dir.Path)
		}
		for off := int64(0); off < dir.Data.Size(); off += 512 {
			var block [512]byte
			if _, err := starfile.ReadFullAt(dir.Data, block[:], off); err != nil {
				return nil, err
			}
			if be.Uint16(block[:]) != 0xbeef {
				return nil, fmt.Errorf("efs: invalid directory block in %s", dir.Path)
			}
			slots := int(block[3])
			if slots+4 > 512 {
				return nil, fmt.Errorf("efs: invalid directory slots")
			}
			for i := 0; i < slots; i++ {
				pos := int(block[4+i]) * 2
				if pos == 0 {
					continue
				}
				if pos < 4+slots || pos+5 > 512 {
					return nil, fmt.Errorf("efs: invalid directory slot")
				}
				id := be.Uint32(block[pos:])
				n := int(block[pos+4])
				if n == 0 || pos+5+n > 512 {
					return nil, fmt.Errorf("efs: invalid directory name")
				}
				name := string(block[pos+5 : pos+5+n])
				if name == "." || name == ".." {
					continue
				}
				if strings.ContainsAny(name, "/\x00") {
					return nil, fmt.Errorf("efs: invalid name %q", name)
				}
				e, err := r.inode(id)
				if err != nil {
					return nil, err
				}
				e.Path = path.Join(dir.Path, name)
				if seenPaths[e.Path] {
					return nil, fmt.Errorf("efs: duplicate path %s", e.Path)
				}
				seenPaths[e.Path] = true
				if e.Kind == "directory" {
					if seenDirs[id] {
						return nil, fmt.Errorf("efs: directory cycle or alias at %s", e.Path)
					}
					seenDirs[id] = true
				}
				if len(v.Entries) >= maximumEntries {
					return nil, fmt.Errorf("efs: entry limit exceeded")
				}
				v.Entries = append(v.Entries, e)
			}
		}
	}
	return v, nil
}

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	maximum := 1000000
	if err := starlark.UnpackArgs("efs", args, kwargs, "file", &value, "maximum_entries?", &maximum); err != nil {
		return nil, err
	}
	f, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("efs: expected file")
	}
	v, err := Open(f, maximum)
	if err != nil {
		return nil, err
	}
	entries := make([]starlark.Value, len(v.Entries))
	paths := make([]starlark.Value, len(v.Entries))
	index := map[string]starlark.Value{}
	for i, e := range v.Entries {
		var data starlark.Value = starlark.None
		var size int64
		if e.Data != nil {
			data = e.Data
			size = e.Data.Size()
		}
		record := starfile.NewRecord(starlark.StringDict{"path": starlark.String(e.Path), "entry_type": starlark.String(e.Kind), "size": starlark.MakeInt64(size), "data": data, "inode": starlark.MakeUint(uint(e.Inode)), "mode": starlark.MakeUint(uint(e.Mode)), "uid": starlark.MakeUint(uint(e.UID)), "gid": starlark.MakeUint(uint(e.GID)), "modified": starlark.MakeUint(uint(e.Modified))})
		entries[i] = record
		paths[i] = starlark.String(e.Path)
		index[e.Path] = record
	}
	find := starlark.NewBuiltin("efs.find", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var name string
		if err := starlark.UnpackArgs("find", args, kwargs, "path", &name); err != nil {
			return nil, err
		}
		value := index[path.Clean("/"+name)]
		if value == nil {
			return starlark.None, nil
		}
		return value, nil
	})
	return starfile.NewRecord(starlark.StringDict{"entries": starlark.NewList(entries), "files": starlark.NewList(paths), "find": find}), nil
}
