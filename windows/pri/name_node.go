package pri

import (
	"fmt"
	"unicode/utf16"
)

// NameNode is the normalized small/large hierarchical-name record. Parent and
// Index refer to tables in the same hierarchical-name section, not file offsets.
type NameNode struct {
	Parent              uint32
	FullLength, Initial uint16
	SegmentLength       uint8
	Scope, ByteString   bool
	StringOffset, Index uint32
}

// ParseNameNode decodes one exact 12-byte small or 20-byte large record.
// Table bounds, parent chains and index ownership require the enclosing schema.
func ParseNameNode(data []byte, large bool) (NameNode, error) {
	var n NameNode
	if (!large && len(data) != 12) || (large && len(data) != 20) {
		return n, fmt.Errorf("pri: invalid name-node extent")
	}
	var flags byte
	if large {
		n.Parent = le.Uint32(data)
		n.FullLength = le.Uint16(data[4:])
		n.Initial = le.Uint16(data[6:])
		n.SegmentLength = data[8]
		flags = data[9]
		n.StringOffset = uint32(flags&15)<<24 | uint32(data[10])<<16 | uint32(le.Uint16(data[12:]))
		n.Index = le.Uint32(data[16:])
	} else {
		n.Parent = uint32(le.Uint16(data))
		n.FullLength = le.Uint16(data[2:])
		n.Initial = le.Uint16(data[4:])
		n.SegmentLength = data[6]
		flags = data[7]
		high := (flags>>2)&0x30 | flags&15
		n.StringOffset = uint32(high)<<16 | uint32(le.Uint16(data[8:]))
		n.Index = uint32(le.Uint16(data[10:]))
	}
	n.Scope = flags&0x10 != 0
	n.ByteString = flags&0x20 != 0
	return n, nil
}

// Segment reads exactly the recorded code-unit count and requires a following
// NUL in the selected pool. StringOffset counts bytes in the byte pool and
// UTF-16 code units in the UTF-16 pool. No case folding or URI parsing occurs.
func (n NameNode) Segment(utf16Pool, bytePool []byte) (string, error) {
	offset, count := uint64(n.StringOffset), uint64(n.SegmentLength)
	units := make([]uint16, count)
	if n.ByteString {
		if offset+count >= uint64(len(bytePool)) || bytePool[offset+count] != 0 {
			return "", fmt.Errorf("pri: invalid byte name extent/terminator")
		}
		for i := range units {
			// CopyNameSegment uses MOVSX byte -> UTF-16 word, not UTF-8.
			units[i] = uint16(int16(int8(bytePool[offset+uint64(i)])))
		}
	} else {
		if len(utf16Pool)%2 != 0 || (offset+count+1)*2 > uint64(len(utf16Pool)) || le.Uint16(utf16Pool[(offset+count)*2:]) != 0 {
			return "", fmt.Errorf("pri: invalid UTF-16 name extent/terminator")
		}
		for i := range units {
			units[i] = le.Uint16(utf16Pool[(offset+uint64(i))*2:])
		}
	}
	for i := 0; i < len(units); i++ {
		u := units[i]
		if u == 0 {
			return "", fmt.Errorf("pri: embedded NUL in name")
		}
		if u >= 0xd800 && u <= 0xdbff {
			if i+1 >= len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
				return "", fmt.Errorf("pri: invalid name surrogate")
			}
			i++
		} else if u >= 0xdc00 && u <= 0xdfff {
			return "", fmt.Errorf("pri: invalid name surrogate")
		}
	}
	return string(utf16.Decode(units)), nil
}
