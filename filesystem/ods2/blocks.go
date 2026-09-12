// Package ods2 reads Files-11 structure-level-2 metadata without mounting it.
package ods2

import (
	"encoding/binary"
	"fmt"

	"github.com/tinyrange/trex/storage"
)

const BlockSize = 512

var le = binary.LittleEndian

func checksum(b []byte) uint16 {
	var sum uint16
	for i := 0; i < len(b); i += 2 {
		sum += le.Uint16(b[i:])
	}
	return sum
}
func readBlock(f storage.File, lbn uint32) ([]byte, error) {
	offset := int64(lbn) * BlockSize
	if offset > f.Size() || BlockSize > f.Size()-offset {
		return nil, fmt.Errorf("ods2: block %d outside image", lbn)
	}
	b := make([]byte, BlockSize)
	n, err := f.ReadAt(b, offset)
	if n != len(b) {
		return nil, fmt.Errorf("ods2: short block %d: %v", lbn, err)
	}
	return b, nil
}

type Home struct {
	Raw                                                     []byte
	LBN, AlternateHome, AlternateIndex                      uint32
	Structure, Cluster                                      uint16
	HomeVBN, AlternateHomeVBN, AlternateIndexVBN, BitmapVBN uint16
	BitmapLBN, MaximumFiles                                 uint32
	BitmapBlocks, ReservedFiles                             uint16
	VolumeName                                              []byte
}

// ReadHome validates one explicitly selected home block. It does not silently
// select an alternate home or infer filesystem bounds from an outer CD trailer.
func ReadHome(f storage.File, lbn uint32) (*Home, error) {
	b, err := readBlock(f, lbn)
	if err != nil {
		return nil, err
	}
	if string(b[496:508]) != "DECFILE11B  " {
		return nil, fmt.Errorf("ods2: invalid home format")
	}
	if checksum(b[:58]) != le.Uint16(b[58:]) || checksum(b[:510]) != le.Uint16(b[510:]) {
		return nil, fmt.Errorf("ods2: home checksum mismatch")
	}
	h := &Home{Raw: b, LBN: le.Uint32(b), AlternateHome: le.Uint32(b[4:]), AlternateIndex: le.Uint32(b[8:]), Structure: le.Uint16(b[12:]), Cluster: le.Uint16(b[14:]), HomeVBN: le.Uint16(b[16:]), AlternateHomeVBN: le.Uint16(b[18:]), AlternateIndexVBN: le.Uint16(b[20:]), BitmapVBN: le.Uint16(b[22:]), BitmapLBN: le.Uint32(b[24:]), MaximumFiles: le.Uint32(b[28:]), BitmapBlocks: le.Uint16(b[32:]), ReservedFiles: le.Uint16(b[34:]), VolumeName: append([]byte(nil), b[472:484]...)}
	if h.LBN != lbn || lbn == 0 || h.AlternateHome == 0 || h.AlternateIndex == 0 || h.Structure != 0x0201 || h.Cluster == 0 || h.BitmapVBN == 0 || h.MaximumFiles == 0 || h.BitmapBlocks == 0 {
		return nil, fmt.Errorf("ods2: unsupported or invalid home geometry")
	}
	if uint64(h.BitmapBlocks)*4096 < uint64(h.MaximumFiles) || uint32(h.ReservedFiles) > h.MaximumFiles {
		return nil, fmt.Errorf("ods2: invalid index bitmap capacity")
	}
	for _, v := range []struct{ start, blocks uint32 }{{h.AlternateHome, 1}, {h.AlternateIndex, 1}, {h.BitmapLBN, uint32(h.BitmapBlocks)}} {
		if (uint64(v.start)+uint64(v.blocks))*BlockSize > uint64(f.Size()) {
			return nil, fmt.Errorf("ods2: home pointer outside image")
		}
	}
	return h, nil
}

// FileID retains the volume-relative identity and its reuse sequence. Number
// combines the low word and the high byte, not the relative-volume byte.
type FileID struct {
	Number   uint32
	Sequence uint16
	Volume   byte
}

func fileID(b []byte) FileID {
	return FileID{Number: uint32(le.Uint16(b)) | uint32(b[5])<<16, Sequence: le.Uint16(b[2:]), Volume: b[4]}
}

type Extent struct{ LBN, Blocks uint32 }
type Header struct {
	Raw                []byte
	ID, Extension      FileID
	Segment, Structure uint16
	Characteristics    uint32
	RecordAttributes   []byte
	AllocatedBlocks    uint32
	Size               int64
	Extents            []Extent
}

func invertedLong(b []byte) uint32 { return uint32(le.Uint16(b))<<16 | uint32(le.Uint16(b[2:])) }

// DecodeHeader checks a single 512-byte header and decodes its retrieval map.
// Extension IDs are retained for the caller to follow; this function does not
// claim that one header necessarily describes the entire file allocation.
func DecodeHeader(input []byte) (*Header, error) {
	if len(input) != BlockSize {
		return nil, fmt.Errorf("ods2: invalid header length")
	}
	b := append([]byte(nil), input...)
	if checksum(b[:510]) != le.Uint16(b[510:]) {
		return nil, fmt.Errorf("ods2: file header checksum mismatch")
	}
	h := &Header{Raw: b, ID: fileID(b[8:14]), Extension: fileID(b[14:20]), Segment: le.Uint16(b[4:]), Structure: le.Uint16(b[6:]), Characteristics: le.Uint32(b[52:]), RecordAttributes: append([]byte(nil), b[20:52]...), AllocatedBlocks: invertedLong(b[24:28])}
	if h.Structure != 0x0201 || h.ID.Number == 0 {
		return nil, fmt.Errorf("ods2: unsupported or invalid header identity")
	}
	start, end := int(b[1])*2, int(b[1])*2+int(b[58])*2
	if start < 80 || start > 510 || end > 510 || int(b[0])*2 < 80 || int(b[0])*2 > start {
		return nil, fmt.Errorf("ods2: invalid header area offsets")
	}
	eof, free := invertedLong(b[28:32]), le.Uint16(b[32:])
	if free >= BlockSize {
		return nil, fmt.Errorf("ods2: invalid EOF byte")
	}
	if eof == 0 {
		if free != 0 {
			return nil, fmt.Errorf("ods2: invalid zero EOF")
		}
	} else {
		h.Size = int64(eof-1)*BlockSize + int64(free)
	}
	for p := start; p < end; {
		word := le.Uint16(b[p:])
		kind := word >> 14
		var e Extent
		switch kind {
		case 1:
			if end-p < 4 {
				return nil, fmt.Errorf("ods2: truncated format-1 extent")
			}
			e = Extent{LBN: uint32(word>>8&63)<<16 | uint32(le.Uint16(b[p+2:])), Blocks: uint32(word&255) + 1}
			p += 4
		case 2:
			if end-p < 6 {
				return nil, fmt.Errorf("ods2: truncated format-2 extent")
			}
			e = Extent{LBN: le.Uint32(b[p+2:]), Blocks: uint32(word&16383) + 1}
			p += 6
		case 3:
			if end-p < 8 {
				return nil, fmt.Errorf("ods2: truncated format-3 extent")
			}
			e = Extent{LBN: le.Uint32(b[p+4:]), Blocks: ((uint32(word&16383) << 16) | uint32(le.Uint16(b[p+2:]))) + 1}
			p += 8
		default:
			return nil, fmt.Errorf("ods2: unsupported retrieval format %d", kind)
		}
		h.Extents = append(h.Extents, e)
	}
	return h, nil
}
