package lzx

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestLZXFinalUncompressedBlockDoesNotRequirePadding(t *testing.T) {
	first := bytes.Repeat([]byte{0xa5}, lzxFrameSize)
	second := []byte{0x5a}
	data := lzxTestUncompressedStream(first, second)
	out, err := Decompress(data, 15, len(first)+len(second))
	if err != nil {
		t.Fatal(err)
	}
	want := append(append([]byte(nil), first...), second...)
	if !bytes.Equal(out, want) {
		t.Fatalf("decoded data mismatch")
	}
}

func TestLZXWIMFinalUncompressedBlockDoesNotRequirePadding(t *testing.T) {
	var writer lzxTestBitWriter
	writer.writeBits(lzxBlockUncompressed, 3)
	writer.writeBits(0, 1)
	writer.writeBits(1, 16)
	writer.align16()
	writer.writeUint32(1)
	writer.writeUint32(1)
	writer.writeUint32(1)
	writer.writeRaw([]byte{0x5a})
	out, err := DecompressWIMChunk(writer.bytes(), 15, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, []byte{0x5a}) {
		t.Fatalf("decoded data = %x", out)
	}
}

func TestLZXMatchUsesUntransformedWindowHistory(t *testing.T) {
	decoder, err := newLZXDecoder(15)
	if err != nil {
		t.Fatal(err)
	}
	// The new decoder retains raw history in its output and defers E8
	// restoration. Matches must copy absolute operands, not restored ones.
	output := make([]byte, 32, 64)
	copy(output[1:], []byte{0xe8, 50, 0, 0, 0})
	decoder.putMatch(&output, 32, 32)
	if !bytes.Equal(output[:32], output[32:]) {
		t.Fatal("match altered raw history")
	}
	decoder.intelStarted, decoder.intelSize = true, 10000
	decoder.undoE8(output[:32], 0)
	decoder.undoE8(output[32:], 32)
	if first, second := binary.LittleEndian.Uint32(output[2:6]), binary.LittleEndian.Uint32(output[34:38]); first != 49 || second != 17 {
		t.Fatalf("restored operands = %d, %d; want 49, 17", first, second)
	}
}

func BenchmarkBuildLZXHuffman512(b *testing.B) {
	lengths := make([]byte, 512)
	for index := range lengths {
		lengths[index] = 9
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := newLZXHuffman(lengths); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRebuildLZXHuffman512(b *testing.B) {
	lengths := make([]byte, 512)
	for index := range lengths {
		lengths[index] = 9
	}
	tree := &lzxHuffman{}
	if err := tree.reset(lengths); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := tree.reset(lengths); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeLZXHuffman256(b *testing.B) {
	lengths := make([]byte, 256)
	for index := range lengths {
		lengths[index] = 8
	}
	tree, err := newLZXHuffman(lengths)
	if err != nil {
		b.Fatal(err)
	}
	data := make([]byte, 64<<10)
	reader := newLZXBitReader(data)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if reader.remaining() < 4 {
			reader = newLZXBitReader(data)
		}
		if _, err := tree.decode(reader); err != nil {
			b.Fatal(err)
		}
	}
}

func lzxTestUncompressedStream(blocks ...[]byte) []byte {
	var w lzxTestBitWriter
	w.writeBits(0, 1)
	for idx, block := range blocks {
		w.writeBits(lzxBlockUncompressed, 3)
		w.writeBits(uint32(len(block)>>8), 16)
		w.writeBits(uint32(len(block)&0xff), 8)
		w.align16()
		w.writeUint32(1)
		w.writeUint32(1)
		w.writeUint32(1)
		w.writeRaw(block)
		if len(block)&1 != 0 && idx+1 < len(blocks) {
			w.writeRaw([]byte{0})
		}
	}
	return w.bytes()
}

type lzxTestBitWriter struct {
	out   []byte
	word  uint16
	count uint
}

func (w *lzxTestBitWriter) writeBits(value uint32, bits uint) {
	for bit := bits; bit > 0; bit-- {
		w.word <<= 1
		w.word |= uint16((value >> (bit - 1)) & 1)
		w.count++
		if w.count == 16 {
			w.flushWord()
		}
	}
}

func (w *lzxTestBitWriter) align16() {
	if w.count == 0 {
		return
	}
	w.word <<= 16 - w.count
	w.flushWord()
}

func (w *lzxTestBitWriter) writeUint32(value uint32) {
	w.align16()
	var data [4]byte
	binary.LittleEndian.PutUint32(data[:], value)
	w.out = append(w.out, data[:]...)
}

func (w *lzxTestBitWriter) writeRaw(data []byte) {
	w.align16()
	w.out = append(w.out, data...)
}

func (w *lzxTestBitWriter) bytes() []byte {
	w.align16()
	return w.out
}

func (w *lzxTestBitWriter) flushWord() {
	var data [2]byte
	binary.LittleEndian.PutUint16(data[:], w.word)
	w.out = append(w.out, data[:]...)
	w.word = 0
	w.count = 0
}
