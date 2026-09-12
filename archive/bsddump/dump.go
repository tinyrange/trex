// Package bsddump reads full historical BSD dump streams. Layout facts follow
// NetBSD include/protocols/dumprestore.h and independent original-media probes.
package bsddump

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/tinyrange/trex/filesystem"
	"github.com/tinyrange/trex/filesystem/ufs"
	starfile "github.com/tinyrange/trex/storage/star"
)

type Archive struct {
	Entries                 []ufs.Entry
	Date                    uint32
	AllocatedMap, DumpedMap starfile.File
}
type inodeBuild struct {
	entry        ufs.Entry
	size, mapped uint64
	specs        []filesystem.ExtentSpec
}

func Open(file starfile.File, maximumEntries int, maximumBytes int64) (*Archive, error) {
	if maximumEntries < 1 || maximumBytes < 0 || file.Size() < 1024 || file.Size()%1024 != 0 || file.Size() > maximumBytes {
		return nil, fmt.Errorf("bsd dump: input outside limits")
	}
	var first [1024]byte
	if _, err := starfile.ReadFullAt(file, first[:], 0); err != nil {
		return nil, err
	}
	var order binary.ByteOrder
	switch {
	case binary.LittleEndian.Uint32(first[24:]) == 60012:
		order = binary.LittleEndian
	case binary.BigEndian.Uint32(first[24:]) == 60012:
		order = binary.BigEndian
	default:
		return nil, fmt.Errorf("bsd dump: unsupported dump generation")
	}
	a := &Archive{Date: order.Uint32(first[4:])}
	if order.Uint32(first[8:]) != 0 {
		return nil, fmt.Errorf("bsd dump: incremental backup requires a base image")
	}
	inodes := map[uint32]ufs.Entry{}
	var current *inodeBuild
	remaining := uint64(maximumBytes)
	finish := func() error {
		if current == nil {
			return nil
		}
		if current.mapped != (current.size+1023)/1024*1024 {
			return fmt.Errorf("bsd dump: incomplete inode %d", current.entry.Inode)
		}
		data := filesystem.NewGeneratedImage("bsd dump inode", int64(current.size), current.specs)
		current.entry.Data = data
		inodes[current.entry.Inode] = current.entry
		current = nil
		return nil
	}
	ended := false
	for block := int64(0); block < file.Size()/1024; {
		var h [1024]byte
		if _, err := starfile.ReadFullAt(file, h[:], block*1024); err != nil {
			return nil, err
		}
		var checksum uint32
		for i := 0; i < 1024; i += 4 {
			checksum += order.Uint32(h[i:])
		}
		if order.Uint32(h[24:]) != 60012 || checksum != 84446 {
			return nil, fmt.Errorf("bsd dump: invalid header checksum/magic at block %d", block)
		}
		if order.Uint32(h[4:]) != a.Date || order.Uint32(h[8:]) != 0 || order.Uint32(h[12:]) != 1 || uint64(order.Uint32(h[16:])) != uint64(block) {
			return nil, fmt.Errorf("bsd dump: inconsistent tape identity at block %d", block)
		}
		kind, number, count := order.Uint32(h[:]), order.Uint32(h[20:]), order.Uint32(h[160:])
		if count > 512 {
			return nil, fmt.Errorf("bsd dump: address count exceeds header")
		}
		if ended && kind != 5 {
			return nil, fmt.Errorf("bsd dump: data after end marker")
		}
		if block == 0 && kind != 1 {
			return nil, fmt.Errorf("bsd dump: missing tape header")
		}
		block++
		switch kind {
		case 1:
			if block != 1 || count != 0 {
				return nil, fmt.Errorf("bsd dump: unsupported additional tape header")
			}
		case 3, 6:
			if current != nil || len(inodes) != 0 || count == 0 || int64(count) > file.Size()/1024-block {
				return nil, fmt.Errorf("bsd dump: invalid inode map")
			}
			data := &starfile.Slice{Base: file, Offset: block * 1024, Length: int64(count) * 1024}
			if kind == 3 {
				if a.DumpedMap != nil {
					return nil, fmt.Errorf("bsd dump: repeated dump map")
				}
				a.DumpedMap = data
			} else {
				if a.AllocatedMap != nil {
					return nil, fmt.Errorf("bsd dump: repeated allocation map")
				}
				a.AllocatedMap = data
			}
			block += int64(count)
		case 2, 4:
			if kind == 2 {
				if err := finish(); err != nil {
					return nil, err
				}
				if number < 2 || len(inodes) >= maximumEntries {
					return nil, fmt.Errorf("bsd dump: inode identity or entry limit")
				}
				if _, ok := inodes[number]; ok {
					return nil, fmt.Errorf("bsd dump: duplicate inode")
				}
				raw := h[32:160]
				size := order.Uint64(raw[8:])
				if size > remaining || size > math.MaxInt64 {
					return nil, fmt.Errorf("bsd dump: decoded size limit")
				}
				remaining -= size
				e := ufs.Entry{Inode: number, Mode: order.Uint16(raw), Links: order.Uint16(raw[2:]), UID: order.Uint16(raw[4:]), GID: order.Uint16(raw[6:]), Accessed: order.Uint32(raw[16:]), Modified: order.Uint32(raw[24:]), Changed: order.Uint32(raw[32:]), Flags: order.Uint32(raw[100:])}
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
					return nil, fmt.Errorf("bsd dump: unsupported inode mode")
				}
				if e.Kind == "character_device" || e.Kind == "block_device" {
					e.Device = order.Uint32(raw[40:])
				}
				if e.Links == 0 {
					return nil, fmt.Errorf("bsd dump: unlinked inode")
				}
				current = &inodeBuild{entry: e, size: size}
			}
			if current == nil || current.entry.Inode != number {
				return nil, fmt.Errorf("bsd dump: unexpected continuation")
			}
			expected := (current.size + 1023) / 1024 * 1024
			if uint64(count)*1024 > expected-current.mapped {
				return nil, fmt.Errorf("bsd dump: addresses exceed inode size")
			}
			for _, present := range h[164 : 164+count] {
				if present > 1 {
					return nil, fmt.Errorf("bsd dump: invalid address flag")
				}
				length := min(uint64(1024), current.size-current.mapped)
				if present != 0 {
					if block >= file.Size()/1024 {
						return nil, fmt.Errorf("bsd dump: truncated inode payload")
					}
					current.specs = append(current.specs, filesystem.ExtentSpec{Start: int64(current.mapped), Size: int64(length), File: file, Offset: block * 1024})
					block++
				}
				current.mapped += 1024
			}
		case 5:
			if err := finish(); err != nil {
				return nil, err
			}
			ended = true
		default:
			return nil, fmt.Errorf("bsd dump: unknown record type %d", kind)
		}
	}
	if !ended || a.DumpedMap == nil || a.AllocatedMap == nil {
		return nil, fmt.Errorf("bsd dump: incomplete stream")
	}
	dumped, err := starfile.ReadAll(a.DumpedMap)
	if err != nil {
		return nil, err
	}
	allocated, err := starfile.ReadAll(a.AllocatedMap)
	if err != nil {
		return nil, err
	}
	for number := range inodes {
		bit := uint64(number) - 1
		if bit/8 >= uint64(len(dumped)) || dumped[bit/8]&(1<<(bit%8)) == 0 {
			return nil, fmt.Errorf("bsd dump: inode %d absent from dump map", number)
		}
	}
	for index, value := range dumped {
		for bit := uint(0); bit < 8; bit++ {
			if value&(1<<bit) == 0 {
				continue
			}
			number := uint32(index*8) + uint32(bit) + 1
			if _, ok := inodes[number]; !ok {
				return nil, fmt.Errorf("bsd dump: missing mapped inode %d", number)
			}
			if index >= len(allocated) || allocated[index]&(1<<bit) == 0 {
				return nil, fmt.Errorf("bsd dump: dumped inode %d not allocated", number)
			}
		}
	}
	root, ok := inodes[2]
	if !ok {
		return nil, fmt.Errorf("bsd dump: missing root inode")
	}
	lookup := func(number uint32) (ufs.Entry, error) {
		e, ok := inodes[number]
		if !ok {
			return e, fmt.Errorf("bsd dump: directory references missing inode %d", number)
		}
		return e, nil
	}
	entries, err := ufs.Walk(root, order, maximumEntries, lookup)
	if err != nil {
		return nil, err
	}
	seen := map[uint32]bool{}
	for _, e := range entries {
		seen[e.Inode] = true
	}
	if len(seen) != len(inodes) {
		return nil, fmt.Errorf("bsd dump: unreachable inodes")
	}
	a.Entries = entries
	return a, nil
}
