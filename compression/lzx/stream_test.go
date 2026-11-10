package lzx

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// Cross-window matches copy E8 operands in their encoded form even after their
// earlier frames were emitted with different absolute positions. The final
// compressed block crosses frames, after several streaming history trims.
func lzxStreamingHistoryFixture(windowBits int) ([]byte, int) {
	var w lzxTestBitWriter
	w.writeBits(1, 1)
	w.writeBits(0, 16)
	w.writeBits(30000, 16)
	window := 1 << windowBits
	for i := 0; i < 2*window/lzxFrameSize+3; i++ {
		block := bytes.Repeat([]byte{byte(i)}, lzxFrameSize)
		for off := 13; off < len(block)-10; off += 113 {
			block[off] = 0xe8
			binary.LittleEndian.PutUint32(block[off+1:], 12345)
		}
		w.writeBits(lzxBlockUncompressed, 3)
		w.writeBits(lzxFrameSize>>8, 16)
		w.writeBits(0, 8)
		w.align16()
		w.writeUint32(uint32(window))
		w.writeUint32(1)
		w.writeUint32(1)
		w.writeRaw(block)
	}
	w.writeBits(lzxBlockVerbatim, 3)
	w.writeBits(4*lzxFrameSize>>8, 16)
	w.writeBits(0, 8)
	main := make([]byte, 256+lzxPositionSlots(windowBits)*8)
	lengths := make([]byte, lzxNumSecondaryLengths)
	for i := 0; i < 256; i++ {
		main[i] = 9
	}
	for i := 256; i < 384; i++ {
		main[i] = 8
	}
	for i := 0; i < 128; i++ {
		lengths[i] = 7
	}
	lzxTestWriteLengths(&w, main[:256])
	lzxTestWriteLengths(&w, main[256:])
	lzxTestWriteLengths(&w, lengths)
	for pos := 0; pos < 4*lzxFrameSize; pos += 128 {
		lzxTestWriteSymbol(&w, main, 263)
		lzxTestWriteSymbol(&w, lengths, 119)
		if (pos+128)%lzxFrameSize == 0 {
			w.align16()
		}
	}
	return w.bytes(), 2*window + 7*lzxFrameSize
}

func TestDecompressToHistoryAndFrames(t *testing.T) {
	for _, window := range []int{15, 17, 21} {
		input, size := lzxStreamingHistoryFixture(window)
		want, err := Decompress(input, window, size)
		if err != nil {
			t.Fatal(err)
		}
		var got bytes.Buffer
		if err := DecompressTo(&got, input, window, size); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Bytes(), want) {
			t.Fatalf("window %d: mismatched history/Intel transform", window)
		}
	}
	for _, blocks := range [][][]byte{
		{bytes.Repeat([]byte{0x71}, 100001), bytes.Repeat([]byte{0x28}, 65539), {1}},
		{bytes.Repeat([]byte{0xe8}, 32767), {1, 2, 3}, bytes.Repeat([]byte{0x43}, 32766)},
	} {
		input := lzxTestUncompressedStream(blocks...)
		size := 0
		for _, block := range blocks {
			size += len(block)
		}
		want, err := Decompress(input, 15, size)
		if err != nil {
			t.Fatal(err)
		}
		var got bytes.Buffer
		if err := DecompressTo(&got, input, 15, size); err != nil || !bytes.Equal(got.Bytes(), want) {
			t.Fatalf("partial frame: %v", err)
		}
	}
}

type lzxFailWriter struct{ err error }

func (w lzxFailWriter) Write(p []byte) (int, error) { return len(p) - 1, w.err }

func TestDecompressToWriterFailure(t *testing.T) {
	input := lzxTestUncompressedStream(make([]byte, 32768))
	sentinel := errors.New("sink failure")
	if err := DecompressTo(lzxFailWriter{sentinel}, input, 15, 32768); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	if err := DecompressTo(lzxFailWriter{}, input, 15, 32768); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
}

func FuzzDecompressTo(f *testing.F) {
	for _, kind := range []string{"literals", "matches", "uncompressed"} {
		input, want := lzxBenchmarkStream(kind, false)
		f.Add(input, uint32(len(want)), uint8(0))
	}
	input, size := lzxStreamingHistoryFixture(15)
	f.Add(input, uint32(size), uint8(0))
	f.Fuzz(func(t *testing.T, input []byte, size uint32, window uint8) {
		if len(input) > 1<<20 {
			t.Skip()
		}
		n := int(size % (1 << 20))
		bits := 15 + int(window%7)
		want, oldErr := Decompress(input, bits, n)
		var got bytes.Buffer
		err := DecompressTo(&got, input, bits, n)
		if (err == nil) != (oldErr == nil) {
			t.Fatalf("stream %v, full %v", err, oldErr)
		}
		if err == nil && !bytes.Equal(got.Bytes(), want) {
			t.Fatal("stream/full bytes differ")
		}
		got.Reset()
		readerErr := DecompressReaderTo(&got, bytes.NewReader(input), int64(len(input)), bits, n)
		if (readerErr == nil) != (oldErr == nil) || (readerErr == nil && !bytes.Equal(got.Bytes(), want)) {
			t.Fatalf("reader/full differ: %v / %v", readerErr, oldErr)
		}
	})
}

func BenchmarkLZXStreamMemory(b *testing.B) {
	blocks := make([][]byte, 2048)
	for i := range blocks {
		blocks[i] = make([]byte, lzxFrameSize)
	}
	input := lzxTestUncompressedStream(blocks...)
	size := len(blocks) * lzxFrameSize
	for _, stream := range []bool{false, true} {
		name := "full"
		if stream {
			name = "stream"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				if stream {
					if err := DecompressTo(io.Discard, input, 15, size); err != nil {
						b.Fatal(err)
					}
				} else {
					if _, err := Decompress(input, 15, size); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}
