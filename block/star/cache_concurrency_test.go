package star

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type cacheConcurrencyBase struct {
	concurrent bool
	active     atomic.Int32
	entered    chan struct{}
	release    chan struct{}
}

func (b *cacheConcurrencyBase) Geometry() BlockGeometry {
	return BlockGeometry{Size: 128 * 512, LogicalBlockSize: 512}
}
func (b *cacheConcurrencyBase) Capabilities() BlockCapabilities {
	return BlockCapabilities{Concurrent: b.concurrent, Extents: true}
}
func (b *cacheConcurrencyBase) begin() error {
	n := b.active.Add(1)
	if !b.concurrent && n != 1 {
		b.active.Add(-1)
		return fmt.Errorf("overlapping backing operations")
	}
	if b.entered != nil {
		b.entered <- struct{}{}
		<-b.release
	}
	runtime.Gosched()
	return nil
}
func (b *cacheConcurrencyBase) ReadAt(p []byte, off int64) (int, error) {
	if err := b.begin(); err != nil {
		return 0, err
	}
	defer b.active.Add(-1)
	for i := range p {
		p[i] = byte((off + int64(i)) / 512)
	}
	return len(p), nil
}
func (b *cacheConcurrencyBase) Extents(off, length int64) ([]BlockExtent, error) {
	if err := b.begin(); err != nil {
		return nil, err
	}
	defer b.active.Add(-1)
	return []BlockExtent{{Offset: off, Length: length, Allocated: true}}, nil
}
func TestBlockCacheSerializesNonConcurrentBackingOperations(t *testing.T) {
	base := &cacheConcurrencyBase{}
	cache, err := NewCachedDevice(base, 128*512, 512)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errors := make(chan error, 96)
	for i := range 32 {
		for _, op := range []string{"read", "prefetch", "extents"} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				off := int64(i * 512)
				switch op {
				case "read":
					p := make([]byte, 512)
					_, err := cache.ReadAt(p, off)
					if err == nil && p[0] != byte(i) {
						err = fmt.Errorf("data at %d: %d", off, p[0])
					}
					errors <- err
				case "prefetch":
					errors <- cache.Prefetch(off, 512)
				case "extents":
					_, err := cache.Extents(off, 512)
					errors <- err
				}
			}()
		}
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Error(err)
		}
	}
}
func TestBlockCacheRetainsParallelReadsForConcurrentBase(t *testing.T) {
	base := &cacheConcurrencyBase{concurrent: true, entered: make(chan struct{}, 2), release: make(chan struct{})}
	cache, err := NewCachedDevice(base, 1024, 512)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	for i := range 2 {
		go func() {
			defer wg.Done()
			if _, err := cache.ReadAt(make([]byte, 512), int64(i*512)); err != nil {
				t.Error(err)
			}
		}()
	}
	defer func() { close(base.release); wg.Wait() }()
	for range 2 {
		select {
		case <-base.entered:
		case <-time.After(time.Second):
			t.Fatal("concurrent base reads were serialized")
		}
	}
}
