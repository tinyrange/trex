package lzx

import (
	"bytes"
	"io"
	"math/rand"
	"sync"
	"testing"
)

func checkLZXIndexed(t *testing.T, input []byte, bits, size, spacing int) {
	t.Helper()
	want, err := Decompress(input, bits, size)
	if err != nil {
		t.Fatal(err)
	}
	indexed, err := NewIndexedReader(bytes.NewReader(input), int64(len(input)), bits, size, spacing)
	if err != nil {
		t.Fatal(err)
	}
	defer indexed.ReleaseReadCache()
	check := func(off, n int) {
		t.Helper()
		got := make([]byte, n)
		count, err := indexed.ReadAt(got, int64(off))
		end := min(off+n, size)
		if count != end-off || !bytes.Equal(got[:count], want[off:end]) || (err == io.EOF) != (n > count) || (err != nil && err != io.EOF) {
			t.Fatalf("offset %d length %d: %d %v", off, n, count, err)
		}
	}
	// Exercise every checkpoint, including resuming within an incomplete frame.
	for i := len(indexed.checkpoints) - 1; i >= 0; i-- {
		cp := indexed.checkpoints[i]
		check(max(0, cp.output-19), min(70001, size-max(0, cp.output-19)))
		indexed.ReleaseReadCache()
		check(cp.output, min(8193, size-cp.output))
	}
	rng := rand.New(rand.NewSource(91))
	for i := 0; i < 250; i++ {
		check(rng.Intn(size), rng.Intn(70000)+1)
	}
	check(0, size)
	check(size, 1)
	if _, err := indexed.ReadAt(make([]byte, 1), -1); err == nil {
		t.Fatal("negative offset")
	}
	if _, err := indexed.ReadAt(nil, int64(size)+1); err != nil {
		t.Fatal("empty EOF read", err)
	}
}
func TestLZXIndexedHistoryAndSeeks(t *testing.T) {
	for _, bits := range []int{15, 17, 21} {
		input, size := lzxStreamingHistoryFixture(bits)
		checkLZXIndexed(t, input, bits, size, 1<<bits)
	}
	for _, kind := range []string{"literals", "matches", "uncompressed"} {
		input, want := lzxBenchmarkStream(kind, false)
		checkLZXIndexed(t, input, 15, len(want), 32768)
	}
	// Raw blocks on both sides of a checkpoint straddle output-frame boundaries.
	blocks := [][]byte{bytes.Repeat([]byte{0xe8}, 100001), bytes.Repeat([]byte{0x55}, 65537), {1, 2, 3}, bytes.Repeat([]byte{0x77}, 131071)}
	size := 0
	for _, b := range blocks {
		size += len(b)
	}
	checkLZXIndexed(t, lzxTestUncompressedStream(blocks...), 15, size, 32768)
}
func TestLZXIndexedConcurrentReadsAndRelease(t *testing.T) {
	input, size := lzxStreamingHistoryFixture(17)
	want, err := Decompress(input, 17, size)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewIndexedReader(bytes.NewReader(input), int64(len(input)), 17, size, 1<<17)
	if err != nil {
		t.Fatal(err)
	}
	defer r.ReleaseReadCache()
	var group sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		group.Add(1)
		go func(seed int) {
			defer group.Done()
			rng := rand.New(rand.NewSource(int64(seed)))
			for i := 0; i < 35; i++ {
				off := rng.Intn(size - 4096)
				got := make([]byte, 4096)
				n, err := r.ReadAt(got, int64(off))
				if err != nil || n != len(got) || !bytes.Equal(got, want[off:off+len(got)]) {
					t.Errorf("parallel read %d: %v", off, err)
					return
				}
				if i%5 == 0 {
					r.ReleaseReadCache()
				}
			}
		}(worker)
	}
	group.Wait()
}
func FuzzLZXIndexed(f *testing.F) {
	for _, kind := range []string{"literals", "matches", "uncompressed"} {
		input, want := lzxBenchmarkStream(kind, false)
		f.Add(input, uint32(len(want)), uint8(0), uint32(0))
	}
	input, size := lzxStreamingHistoryFixture(15)
	f.Add(input, uint32(size), uint8(0), uint32(70000))
	f.Fuzz(func(t *testing.T, input []byte, size uint32, window uint8, offset uint32) {
		if len(input) > 1<<20 {
			t.Skip()
		}
		n := int(size % (1 << 20))
		bits := 15 + int(window%7)
		want, oldErr := Decompress(input, bits, n)
		r, err := NewIndexedReader(bytes.NewReader(input), int64(len(input)), bits, n, 1<<bits)
		if (err == nil) != (oldErr == nil) {
			t.Fatalf("indexed %v/full %v", err, oldErr)
		}
		if err != nil {
			return
		}
		defer r.ReleaseReadCache()
		if n == 0 {
			return
		}
		start := int(offset % uint32(n))
		got := make([]byte, min(70001, n-start))
		if _, err := r.ReadAt(got, int64(start)); err != nil || !bytes.Equal(got, want[start:start+len(got)]) {
			t.Fatalf("bytes at %d: %v", start, err)
		}
	})
}
