package lzx

import (
	"bytes"
	"testing"
)

func FuzzDecompress(f *testing.F) {
	for _, kind := range []string{"literals", "matches", "uncompressed"} {
		for _, wim := range []bool{false, true} {
			input, out := lzxBenchmarkStream(kind, wim)
			f.Add(input, uint16(len(out)), uint8(0), wim)
		}
	}
	f.Add([]byte{}, uint16(1), uint8(0), false)
	f.Fuzz(func(t *testing.T, input []byte, size uint16, window uint8, wim bool) {
		if len(input) > 1<<16 {
			t.Skip()
		}
		decode := Decompress
		if wim {
			decode = DecompressWIMChunk
		}
		out, err := decode(input, 15+int(window%7), int(size))
		if err == nil && len(out) != int(size) {
			t.Fatalf("output size %d, want %d", len(out), size)
		}
	})
}

func TestTruncatedFixtures(t *testing.T) {
	for _, kind := range []string{"literals", "matches", "uncompressed"} {
		for _, wim := range []bool{false, true} {
			input, want := lzxBenchmarkStream(kind, wim)
			decode := Decompress
			if wim {
				decode = DecompressWIMChunk
			}
			for _, end := range []int{0, 1, 2, 8, len(input) / 2, len(input) - 2} {
				if _, err := decode(input[:end], 15, len(want)); err == nil {
					t.Fatalf("accepted %s wim=%v truncated at %d", kind, wim, end)
				}
			}
		}
	}
}

func TestNegativeOutputSize(t *testing.T) {
	if _, err := Decompress(nil, 15, -1); err == nil {
		t.Fatal("accepted negative size")
	}
	if _, err := DecompressWIMChunk(nil, 15, -1); err == nil {
		t.Fatal("accepted negative size")
	}
}

func TestWIMStoredChunkOwnsOutput(t *testing.T) {
	input := []byte{1, 2, 3}
	out, err := DecompressWIMChunk(input, 15, len(input))
	if err != nil || !bytes.Equal(out, input) {
		t.Fatalf("stored chunk: %v", err)
	}
	out[0] = 4
	if input[0] != 1 {
		t.Fatal("output aliases input")
	}
}
