package mipscoff

import (
	"encoding/binary"
	"fmt"
)

// MessageLengthPatch describes a checked replacement for an early NT
// MESSAGE_RESOURCE_ENTRY length word. Offset is relative to the source file.
type MessageLengthPatch struct {
	Offset int64
	Before uint16
	After  uint16
}

// MessageLengthPatches identifies the early compiler's text-only lengths.
// RtlFindMessage in the April 1991 runtime expects the entire aligned entry
// length, which includes the header, text, NUL and padding.
func (im *Image) MessageLengthPatches() ([]MessageLengthPatch, error) {
	if im.ROM {
		return nil, nil
	}
	for index, section := range im.Sections {
		if section.Name != ".rsrc" {
			continue
		}
		if section.ZeroFill() || section.Size > 16<<20 {
			return nil, fmt.Errorf("MIPS COFF: invalid resource section")
		}
		data := make([]byte, section.Size)
		if err := im.ReadSection(index, 0, data); err != nil {
			return nil, err
		}
		var patches []MessageLengthPatch
		seen := make(map[uint32]bool)
		remaining := uint32(len(data))
		err := walkResourceDirectory(data, 0, func(kind, child uint32) error {
			if kind != 11 {
				return nil
			}
			if child&0x80000000 == 0 {
				return fmt.Errorf("MIPS COFF: invalid message resource directory")
			}
			return walkResourceDirectory(data, child&0x7fffffff, func(_ uint32, leaf uint32) error {
				if leaf&0x80000000 != 0 || uint64(leaf)+8 > uint64(len(data)) {
					return fmt.Errorf("MIPS COFF: invalid message resource leaf")
				}
				address := binary.LittleEndian.Uint32(data[leaf:])
				size := binary.LittleEndian.Uint32(data[leaf+4:])
				base := uint64(im.Base) + uint64(section.Address)
				if uint64(address) < base || uint64(address)-base+uint64(size) > uint64(len(data)) {
					return fmt.Errorf("MIPS COFF: message resource outside resource section")
				}
				offset := uint32(uint64(address) - base)
				if seen[offset] || size > remaining {
					return fmt.Errorf("MIPS COFF: overlapping or oversized message resources")
				}
				seen[offset] = true
				remaining -= size
				fixups, err := messageLengthPatches(data[offset:offset+size], int64(section.Offset)+int64(offset))
				patches = append(patches, fixups...)
				return err
			})
		})
		if err != nil {
			return nil, err
		}
		return patches, nil
	}
	return nil, nil
}

func walkResourceDirectory(data []byte, offset uint32, visit func(id, child uint32) error) error {
	if uint64(offset)+4 > uint64(len(data)) {
		return fmt.Errorf("MIPS COFF: resource directory outside section")
	}
	le := binary.LittleEndian
	count := uint32(le.Uint16(data[offset:])) + uint32(le.Uint16(data[offset+2:]))
	start := offset + 4
	if uint64(start)+uint64(count)*8 > uint64(len(data)) {
		return fmt.Errorf("MIPS COFF: resource entries outside section")
	}
	for i := uint32(0); i < count; i++ {
		entry := data[start+i*8:]
		if err := visit(le.Uint32(entry), le.Uint32(entry[4:])); err != nil {
			return err
		}
	}
	return nil
}

type messageBlock struct {
	start, end int
	count      uint64
}

func messageLengthPatches(data []byte, fileOffset int64) ([]MessageLengthPatch, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("MIPS COFF: truncated message table")
	}
	le := binary.LittleEndian
	n := uint64(le.Uint32(data))
	tableEnd := 4 + n*12
	if n == 0 || tableEnd > uint64(len(data)) {
		return nil, fmt.Errorf("MIPS COFF: message block headers outside resource")
	}
	blocks := make([]messageBlock, int(n))
	for i := range blocks {
		header := data[4+i*12:]
		lo, hi, start := le.Uint32(header), le.Uint32(header[4:]), uint64(le.Uint32(header[8:]))
		end := uint64(len(data))
		if i+1 < len(blocks) {
			end = uint64(le.Uint32(header[20:]))
		}
		if hi < lo || start < tableEnd || start >= end || end > uint64(len(data)) || start&3 != 0 {
			return nil, fmt.Errorf("MIPS COFF: invalid range for message block %d", i)
		}
		count := uint64(hi) - uint64(lo) + 1
		if count > (end-start)/4 {
			return nil, fmt.Errorf("MIPS COFF: truncated entries in message block %d", i)
		}
		blocks[i] = messageBlock{int(start), int(end), count}
	}
	if _, ok := walkMessageEntries(data, blocks, fileOffset, false); ok {
		return nil, nil
	}
	patches, ok := walkMessageEntries(data, blocks, fileOffset, true)
	if !ok {
		return nil, fmt.Errorf("MIPS COFF: unrecognized message entry lengths")
	}
	return patches, nil
}

func walkMessageEntries(data []byte, blocks []messageBlock, fileOffset int64, textOnly bool) ([]MessageLengthPatch, bool) {
	var patches []MessageLengthPatch
	for _, block := range blocks {
		at := block.start
		for i := uint64(0); i < block.count; i++ {
			if block.end-at < 4 {
				return nil, false
			}
			raw := binary.LittleEndian.Uint16(data[at:])
			stride := int(raw)
			if textOnly {
				// The legacy field excludes the header and terminating NUL.
				stride = (stride + 4 + 1 + 3) &^ 3
				if stride > 0xffff || stride > block.end-at {
					return nil, false
				}
				for _, padding := range data[at+4+int(raw) : at+stride] {
					if padding != 0 {
						return nil, false
					}
				}
				patches = append(patches, MessageLengthPatch{fileOffset + int64(at), raw, uint16(stride)})
			}
			if stride < 4 || stride&3 != 0 || stride > block.end-at {
				return nil, false
			}
			at += stride
		}
		if at != block.end {
			return nil, false
		}
	}
	return patches, true
}
