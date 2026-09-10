package native

import (
	"bytes"
	"fmt"
	"io"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/tinyrange/trex/storage"
	starvalue "github.com/tinyrange/trex/storage/star"
)

func TestVerifiedFileBoundedEvictionAndRevalidation(t *testing.T) {
	cache, err := newVerifiedFileCache(retainedChunkBytes + 256)
	if err != nil {
		t.Fatal(err)
	}
	input := make([]byte, retainedChunkBytes)
	rng := rand.New(rand.NewPCG(12, 34))
	for i := range input {
		input[i] = byte(rng.Uint32())
	}
	want := bytes.Clone(input)
	reads := 0
	first, err := newVerifiedFile(cache, "first", input, func() (storage.Reader, error) {
		reads++
		return &starvalue.Bytes{Data: input}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	otherInput := bytes.Clone(input)
	otherInput[0] ^= 1
	if reads != 0 || cache.used == 0 || cache.used > cache.maximum {
		t.Fatal("construction did not retain bounded verified bytes")
	}
	input[0] ^= 1
	got := make([]byte, len(input))
	if _, err := first.ReadAt(got, 0); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("first read: %v", err)
	}
	input[0] ^= 1
	if _, err := first.ReadAt(got[:10], 13); err != nil || reads != 0 {
		t.Fatal("cache hit reopened file")
	}
	second, err := newVerifiedFile(cache, "second", otherInput, func() (storage.Reader, error) { return &starvalue.Bytes{Data: otherInput}, nil })
	if err != nil {
		t.Fatal(err)
	}
	if cache.entries[first] != nil || cache.entries[second] == nil {
		t.Fatal("initial admission did not evict least recently used file")
	}
	if _, err := second.ReadAt(got, 0); err != nil || len(cache.entries) != 1 || cache.used > cache.maximum {
		t.Fatalf("cache unbounded: %d, %v", cache.used, err)
	}
	if _, err := first.ReadAt(got, 0); err != nil || reads != 1 || !bytes.Equal(got, want) {
		t.Fatalf("eviction changed bytes: %v", err)
	}
	// Mutating a source cannot alter cached immutable bytes, or pass the
	// verification boundary when the source is reconstructed after eviction.
	input[0] ^= 1
	if _, err := first.ReadAt(got, 0); err != nil || !bytes.Equal(got, want) {
		t.Fatal("cached bytes alias source")
	}
	if _, err := second.ReadAt(got[:1], 0); err != nil {
		t.Fatal(err)
	}
	if n, err := first.ReadAt(got, 0); err == nil || n != 0 {
		t.Fatal("served changed source bytes")
	}
	if cache.codec.chunks != nil {
		t.Fatal("dedup index pins evicted chunks")
	}
}

func TestVerifiedFileConcurrentReadersAndBounds(t *testing.T) {
	cache, err := newVerifiedFileCache(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("verified output"), 20000)
	var opened atomic.Int32
	file, err := newVerifiedFile(cache, "concurrent", data, func() (storage.Reader, error) { opened.Add(1); return &starvalue.Bytes{Data: data}, nil })
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for index := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for off := index; off < len(data); off += 8191 {
				got := make([]byte, min(8192, len(data)-off))
				if _, err := file.ReadAt(got, int64(off)); err != nil || !bytes.Equal(got, data[off:off+len(got)]) {
					t.Errorf("read: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	if opened.Load() != 0 {
		t.Fatalf("concurrent cache misses: %d", opened.Load())
	}
	if n, err := file.ReadAt(nil, file.Size()); n != 0 || err != nil {
		t.Fatal("empty read")
	}
	if n, err := file.ReadAt(make([]byte, 1), file.Size()); n != 0 || err != io.EOF {
		t.Fatal("EOF")
	}
	if _, err := file.ReadAt(make([]byte, 1), -1); err == nil {
		t.Fatal("negative offset")
	}
	if _, err := file.WriteAt([]byte{1}, 0); err == nil {
		t.Fatal("mutable file")
	}
}

func TestVerifiedFileOversizedCacheEntryAndErrors(t *testing.T) {
	cache, err := newVerifiedFileCache(0)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		data []byte
		err  error
	}{{[]byte("short"), nil}, {nil, fmt.Errorf("reconstruction failed")}} {
		file, err := newVerifiedFile(cache, "bad", []byte("original bytes"), func() (storage.Reader, error) { return &starvalue.Bytes{Data: tc.data}, tc.err })
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.ReadAt(make([]byte, 1), 0); err == nil {
			t.Fatal("accepted changed length or reconstruction error")
		}
	}
	data := []byte("valid uncached bytes")
	file, err := newVerifiedFile(cache, "uncached", data, func() (storage.Reader, error) { return &starvalue.Bytes{Data: data}, nil })
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(data))
	if _, err := file.ReadAt(got, 0); err != nil || !bytes.Equal(got, data) || cache.used != 0 || len(cache.entries) != 0 {
		t.Fatalf("oversized entry: %v", err)
	}
}
