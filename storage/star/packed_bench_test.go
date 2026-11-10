package star

import (
	"bytes"
	"math/rand/v2"
	"testing"
)

func BenchmarkPackedChunks(b *testing.B) {
	// A mixture of repeated instructions, zero regions, and incompressible data.
	data := make([]byte, 8*PackedChunkBytes)
	rng := rand.New(rand.NewPCG(41, 92))
	for i := range data {
		data[i] = byte(rng.Uint32())
	}
	for off := 0; off < len(data); off += PackedChunkBytes {
		copy(data[off:off+PackedChunkBytes/2], bytes.Repeat([]byte("registry and executable metadata\x00"), 2048))
		clear(data[off+PackedChunkBytes/2 : off+3*PackedChunkBytes/4])
	}
	b.Run("pack", func(b *testing.B) {
		store, err := NewPackedFileStore(0, false)
		if err != nil {
			b.Fatal(err)
		}
		b.SetBytes(int64(len(data)))
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			f, err := store.Pack("bench", data)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportMetric(float64(f.(*PackedFile).RetainedBytes()), "retained-B")
		}
	})
	b.Run("read", func(b *testing.B) {
		store, err := NewPackedFileStore(0, false)
		if err != nil {
			b.Fatal(err)
		}
		f, err := store.Pack("bench", data)
		if err != nil {
			b.Fatal(err)
		}
		dst := make([]byte, len(data))
		b.SetBytes(int64(len(data)))
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			if _, err := f.ReadAt(dst, 0); err != nil {
				b.Fatal(err)
			}
		}
		if !bytes.Equal(dst, data) {
			b.Fatal("decoded bytes differ")
		}
	})
}
