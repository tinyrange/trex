package bzip2

import (
	"bytes"
	"testing"
)

func TestDerandomizationBeforeRunExpansion(t *testing.T) {
	// The first random bit flips at byte617 (zero-based). Put the
	// run-length count there, so applying the mask after RLE is wrong.
	encoded := make([]byte, 2000)
	for i := range encoded {
		encoded[i] = byte(i % 251)
	}
	for i := 613; i < 617; i++ {
		encoded[i] = 'A'
	}
	encoded[617] = 3
	want := append([]byte{}, encoded[:613]...)
	want = append(want, bytes.Repeat([]byte{'A'}, 7)...)
	want = append(want, encoded[618:]...)
	// Independent position calculation, not the reader's countdown.
	position := -2
	for _, gap := range randomNumbers {
		position += gap
		if position >= len(encoded) {
			break
		}
		encoded[position] ^= 1
	}
	for _, chunk := range []int{1, 7, 1024} {
		r := reader{randomized: true, lastByte: -1, preRLE: make([]uint32, len(encoded))}
		for i, b := range encoded {
			r.preRLE[i] = uint32((i+1)%len(encoded))<<8 | uint32(b)
		}
		var got []byte
		buf := make([]byte, chunk)
		for {
			n := r.readFromBlock(buf)
			if n == 0 {
				break
			}
			got = append(got, buf[:n]...)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("chunk %d: got %d bytes, want %d", chunk, len(got), len(want))
		}
	}
}
