package xpress

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// One literal and one offset-1 match, with a two-symbol one-bit code.
// Raw extended lengths follow the two prefetched little-endian coding words.
func repeatedBlock(value byte, length uint32) []byte {
	data := make([]byte, 260)
	data[int(value)/2] |= 1 << (4 * (value & 1))
	data[271/2] |= 1 << 4
	binary.LittleEndian.PutUint16(data[256:], 0x4000) // literal 0, match 1
	data = append(data, 255)
	if length-4 > 65535 {
		data = append(data, 0, 0)
		data = binary.LittleEndian.AppendUint32(data, length-4)
	} else {
		data = binary.LittleEndian.AppendUint16(data, uint16(length-4))
	}
	return data
}

func TestHuffmanBlockBoundariesAndLongMatches(t *testing.T) {
	for _, lengths := range [][2]uint32{{65536, 4464}, {70000, 64}} {
		data := append(repeatedBlock('A', lengths[0]), repeatedBlock('B', lengths[1])...)
		want := append(bytes.Repeat([]byte{'A'}, int(lengths[0])), bytes.Repeat([]byte{'B'}, int(lengths[1]))...)
		got, err := HuffmanDecompress(data, len(want))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("lengths %v: got %d bytes, error %v", lengths, len(got), err)
		}
		if _, err := HuffmanDecompress(data, len(want)-1); err == nil {
			t.Fatal("accepted output overrun")
		}
	}
}
