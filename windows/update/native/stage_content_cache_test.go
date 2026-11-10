package native

import (
	"bytes"
	"crypto/sha256"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/tinyrange/trex/storage"
	bytecache "github.com/tinyrange/trex/storage/cache"
	starfile "github.com/tinyrange/trex/storage/star"
)

func stageTestCache(t *testing.T, limit int64) *stageContentCache {
	t.Helper()
	cache, err := newStageContentCache(limit)
	if err != nil {
		t.Fatal(err)
	}
	return cache
}
func TestStageCompressedCacheLargeTargetSmallRandomReads(t *testing.T) {
	data := bytes.Repeat([]byte("large verified target; random disk reads\n"), 65536)
	digest := sha256.Sum256(data)
	cache := stageTestCache(t, 128<<10)
	var opens atomic.Int32
	reader := &reopenedStageReader{size: int64(len(data)), expectedSHA256: &digest, compressed: cache, open: func() (storage.Reader, error) {
		opens.Add(1)
		return &starfile.Bytes{Data: data}, nil
	}}
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for off := i; off+100 < len(data); off += 65521 {
				got := make([]byte, 100)
				if _, err := reader.ReadAt(got, int64(off)); err != nil || !bytes.Equal(got, data[off:off+100]) {
					t.Errorf("read at %d: %v", off, err)
					return
				}
			}
		}()
	}
	wg.Wait()
	if opens.Load() != 1 {
		t.Fatalf("adjacent/concurrent reads reconstructed target %d times", opens.Load())
	}
	if s := cache.Stats(); s.Bytes > 128<<10 || s.Bytes == 0 {
		t.Fatalf("encoded working set: %+v", s)
	}
	if cache.codec.Deduplicates() {
		t.Fatal("unbounded dedup index")
	}
	if hot := cache.codec.CacheStats().Bytes; hot > maximumRetainedReadCache {
		t.Fatal("decoded cache unbounded", hot)
	}

}

// An incompressible file larger than the ordinary LRU must not be rebuilt for
// every sector read, including when small library reads are interleaved. A
// second oversized target replaces only the dedicated slot, with revalidation.
func TestStageCompressedCacheOversizedAdmission(t *testing.T) {
	const limit = 64 << 10
	data := make([]byte, 256<<10)
	rng := rand.New(rand.NewPCG(1, 2))
	for i := range data {
		data[i] = byte(rng.Uint32())
	}
	digest := sha256.Sum256(data)
	cache := stageTestCache(t, limit)
	var opens int
	large := &reopenedStageReader{size: int64(len(data)), expectedSHA256: &digest, compressed: cache, key: bytecache.Key{Index: 1}, open: func() (storage.Reader, error) { opens++; return &starfile.Bytes{Data: data}, nil }}
	small := &reopenedStageReader{size: 4096, compressed: cache, key: bytecache.Key{Index: 2}, open: func() (storage.Reader, error) { return &starfile.Bytes{Data: make([]byte, 4096)}, nil }}
	if _, err := cache.get(small); err != nil {
		t.Fatal(err)
	}
	for _, off := range []int64{0, 65530, 131071, 200000} {
		if _, err := cache.get(small); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 512)
		if _, err := large.ReadAt(got, off); err != nil || !bytes.Equal(got, data[off:off+512]) {
			t.Fatalf("read %d: %v", off, err)
		}
	}
	if opens != 1 {
		t.Fatalf("large file reconstructed %d times", opens)
	}
	if s := cache.Stats(); s.Entries != 2 || s.Bytes <= limit || s.Bytes > maximumStageCacheEntry+limit {
		t.Fatalf("oversized admission: %+v", s)
	}
	if _, err := cache.get(small); err != nil {
		t.Fatal(err)
	}
	if cache.used > limit {
		t.Fatalf("ordinary LRU exceeded budget: %d", cache.used)
	}
	otherLarge := &reopenedStageReader{size: int64(len(data)), key: bytecache.Key{Index: 3}, open: func() (storage.Reader, error) { return &starfile.Bytes{Data: data}, nil }}
	if _, err := cache.get(otherLarge); err != nil {
		t.Fatal(err)
	}
	if s := cache.Stats(); s.Entries != 2 || s.Bytes > maximumStageCacheEntry+limit {
		t.Fatalf("unbounded oversized slots: %+v", s)
	}
	// Re-admission must validate again, not reuse the discarded content proof.
	large.open = func() (storage.Reader, error) { return &starfile.Bytes{Data: make([]byte, len(data))}, nil }
	if _, err := large.ReadAt(make([]byte, 1), 0); err == nil {
		t.Fatal("evicted oversized target bypassed hash validation")
	}
}
