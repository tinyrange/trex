package lzx

import (
	"bytes"
	"testing"
)

// Synthetic fixtures are generated in memory and contain no third-party data.
// The real-media companion is archive/cab.BenchmarkLZXMedia.
func BenchmarkDecompress(b *testing.B) {
	for _, kind := range []string{"literals", "matches", "uncompressed"} {
		for _, wim := range []bool{false, true} {
			name := "CAB/" + kind
			if wim {
				name = "WIM/" + kind
			}
			b.Run(name, func(b *testing.B) {
				input, want := lzxBenchmarkStream(kind, wim)
				decode := Decompress
				if wim {
					decode = DecompressWIMChunk
				}
				out, err := decode(input, 15, len(want))
				if err != nil || !bytes.Equal(out, want) {
					b.Fatalf("fixture: %v, output matches=%v", err, bytes.Equal(out, want))
				}
				b.SetBytes(int64(len(want)))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					out, err = decode(input, 15, len(want))
					if err != nil {
						b.Fatal(err)
					}
				}
				b.StopTimer()
				if !bytes.Equal(out, want) {
					b.Fatal("decoded output mismatch")
				}
			})
		}
	}
}

func lzxBenchmarkStream(kind string, wim bool) ([]byte, []byte) {
	var w lzxTestBitWriter
	if !wim {
		w.writeBits(0, 1)
	}
	blockType := uint32(lzxBlockVerbatim)
	if kind == "uncompressed" {
		blockType = lzxBlockUncompressed
	}
	w.writeBits(blockType, 3)
	if wim {
		w.writeBits(1, 1)
	} else {
		w.writeBits(lzxFrameSize>>8, 16)
		w.writeBits(0, 8)
	}
	want := bytes.Repeat([]byte{'A'}, lzxFrameSize)
	if kind == "uncompressed" {
		w.align16()
		w.writeUint32(1)
		w.writeUint32(1)
		w.writeUint32(1)
		w.writeRaw(want)
		return w.bytes(), want
	}
	main := make([]byte, 256+lzxPositionSlots(15)*8)
	lengths := make([]byte, lzxNumSecondaryLengths)
	for i := 0; i < 256; i++ {
		main[i] = 8
	}
	if kind == "matches" {
		for i := 0; i < 256; i++ {
			main[i] = 9
		}
		for i := 256; i < 384; i++ {
			main[i] = 8
		}
		for i := 0; i < 128; i++ {
			lengths[i] = 7
		}
	}
	lzxTestWriteLengths(&w, main[:256])
	lzxTestWriteLengths(&w, main[256:])
	lzxTestWriteLengths(&w, lengths)
	for pos := 0; pos < len(want); {
		if kind == "matches" && pos > 0 && len(want)-pos >= 128 {
			lzxTestWriteSymbol(&w, main, 263) // r0, length 9 + secondary
			lzxTestWriteSymbol(&w, lengths, 119)
			pos += 128
		} else {
			lzxTestWriteSymbol(&w, main, int(want[pos]))
			pos++
		}
	}
	return w.bytes(), want
}

func lzxTestWriteLengths(w *lzxTestBitWriter, lengths []byte) {
	pre := make([]byte, 20)
	for i := range pre {
		if i < 12 {
			pre[i] = 4
		} else {
			pre[i] = 5
		}
		w.writeBits(uint32(pre[i]), 4)
	}
	for _, length := range lengths {
		lzxTestWriteSymbol(w, pre, (17-int(length))%17)
	}
}

func lzxTestWriteSymbol(w *lzxTestBitWriter, lengths []byte, sym int) {
	var count, next [17]uint32
	for _, n := range lengths {
		if n != 0 {
			count[n]++
		}
	}
	for n := 1; n <= 16; n++ {
		next[n] = (next[n-1] + count[n-1]) << 1
	}
	for i, n := range lengths {
		if n == 0 {
			continue
		}
		if i == sym {
			w.writeBits(next[n], uint(n))
			return
		}
		next[n]++
	}
	panic("missing test symbol")
}

func TestCompressedFixtures(t *testing.T) {
	for _, kind := range []string{"literals", "matches", "uncompressed"} {
		for _, wim := range []bool{false, true} {
			input, want := lzxBenchmarkStream(kind, wim)
			decode := Decompress
			if wim {
				decode = DecompressWIMChunk
			}
			out, err := decode(input, 15, len(want))
			if err != nil || !bytes.Equal(out, want) {
				t.Fatalf("%s wim=%v: %v", kind, wim, err)
			}
		}
	}
}
