package lzx

import (
	"bytes"
	"testing"
)

// Alternate far-apart reads so each iteration restores a checkpoint rather
// than measuring the hot-frame fast path. Validate every returned byte.
func BenchmarkLZXIndexedRandomSeek(b *testing.B) {
	input, size := lzxStreamingHistoryFixture(21)
	want, err := Decompress(input, 21, size)
	if err != nil {
		b.Fatal(err)
	}
	r, err := NewIndexedReader(bytes.NewReader(input), int64(len(input)), 21, size, 2<<20)
	if err != nil {
		b.Fatal(err)
	}
	defer r.ReleaseReadCache()
	buf := make([]byte, 4096)
	offsets := []int{size - 4096, 0, size / 2}
	for _, off := range offsets {
		if _, err := r.ReadAt(buf, int64(off)); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		off := offsets[i%len(offsets)]
		if _, err := r.ReadAt(buf, int64(off)); err != nil || !bytes.Equal(buf, want[off:off+len(buf)]) {
			b.Fatalf("read at %d: %v", off, err)
		}
	}
}
