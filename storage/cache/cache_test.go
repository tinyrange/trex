package bytecache

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"
)

func TestBoundedByteCacheCoalescesConcurrentLoads(t *testing.T) {
	cache := New(1024)
	key := Key{Source: 1, Kind: 1, Index: 7}
	started := make(chan struct{})
	release := make(chan struct{})
	var loads atomic.Int32
	load := func() ([]byte, error) {
		if loads.Add(1) == 1 {
			close(started)
		}
		<-release
		return []byte("folder"), nil
	}

	const readers = 8
	results := make(chan []byte, readers)
	errors := make(chan error, readers)
	var group sync.WaitGroup
	group.Add(readers)
	for range readers {
		go func() {
			defer group.Done()
			data, err := cache.Get(key, load)
			results <- data
			errors <- err
		}()
	}
	<-started
	close(release)
	group.Wait()
	close(results)
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	for data := range results {
		if !bytes.Equal(data, []byte("folder")) {
			t.Fatalf("cached data = %q", data)
		}
	}
	if got := loads.Load(); got != 1 {
		t.Fatalf("loader calls = %d, want 1", got)
	}
	stats := cache.Stats()
	if stats.Misses != 1 || stats.Hits != readers-1 || stats.Bytes != 6 {
		t.Fatalf("cache stats = %+v", stats)
	}
}

func TestBoundedByteCacheEvictsLeastRecentlyUsed(t *testing.T) {
	cache := New(6)
	load := func(value string) func() ([]byte, error) {
		return func() ([]byte, error) { return []byte(value), nil }
	}
	first := Key{Source: 1, Index: 1}
	second := Key{Source: 1, Index: 2}
	third := Key{Source: 1, Index: 3}
	if _, err := cache.Get(first, load("111")); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Get(second, load("222")); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Get(first, load("unused")); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Get(third, load("333")); err != nil {
		t.Fatal(err)
	}

	stats := cache.Stats()
	if stats.Evictions != 1 || stats.Bytes != 6 {
		t.Fatalf("cache stats = %+v", stats)
	}
	var secondLoads int
	if _, err := cache.Get(second, func() ([]byte, error) {
		secondLoads++
		return []byte("222"), nil
	}); err != nil {
		t.Fatal(err)
	}
	if secondLoads != 1 {
		t.Fatalf("evicted entry loader calls = %d, want 1", secondLoads)
	}
}
