package lzx

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestMatchCopyAgainstBytewiseReference(t *testing.T) {
	for _, start := range []int{0, 1, 17, 32767, 32760, 65536, 65543} {
		for _, offset := range []int{1, 2, 3, 7, 16, 257, 32767, 32768} {
			for _, length := range []int{2, 3, 7, 16, 128, 257, 258} {
				d, _ := newLZXDecoder(15)
				out := make([]byte, start, start+length)
				var window [32768]byte
				for i := range out {
					out[i] = byte(i*13 + i/257)
					window[i&32767] = out[i]
				}
				want := make([]byte, length)
				for i := range want {
					want[i] = window[(start+i-offset)&32767]
					window[(start+i)&32767] = want[i]
				}
				d.putMatch(&out, offset, length)
				if !bytes.Equal(out[start:], want) {
					t.Fatalf("start=%d offset=%d length=%d", start, offset, length)
				}
			}
		}
	}
}

func TestMatchAcrossE8FrameBoundary(t *testing.T) {
	var w lzxTestBitWriter
	w.writeBits(1, 1)
	w.writeBits(0, 16)
	w.writeBits(10000, 16)
	w.writeBits(lzxBlockUncompressed, 3)
	w.writeBits(lzxFrameSize>>8, 16)
	w.writeBits(0, 8)
	w.align16()
	w.writeUint32(lzxFrameSize)
	w.writeUint32(1)
	w.writeUint32(1)
	first := make([]byte, lzxFrameSize)
	copy(first[1:], []byte{0xe8, 50, 0, 0, 0})
	w.writeRaw(first)
	w.writeBits(lzxBlockVerbatim, 3)
	w.writeBits(0, 16)
	w.writeBits(128, 8)
	main := make([]byte, 256+lzxPositionSlots(15)*8)
	main[263] = 1
	lengths := make([]byte, lzxNumSecondaryLengths)
	lengths[119] = 1
	lzxTestWriteLengths(&w, main[:256])
	lzxTestWriteLengths(&w, main[256:])
	lzxTestWriteLengths(&w, lengths)
	lzxTestWriteSymbol(&w, main, 263)
	lzxTestWriteSymbol(&w, lengths, 119)
	out, err := Decompress(w.bytes(), 15, lzxFrameSize+128)
	if err != nil {
		t.Fatal(err)
	}
	want := append(bytes.Clone(first), first[:128]...)
	binary.LittleEndian.PutUint32(want[2:6], 49)
	secondValue := int32(50 - lzxFrameSize - 1)
	binary.LittleEndian.PutUint32(want[lzxFrameSize+2:lzxFrameSize+6], uint32(secondValue))
	if !bytes.Equal(out, want) {
		t.Fatal("cross-frame match did not preserve pre-E8 history")
	}
}
