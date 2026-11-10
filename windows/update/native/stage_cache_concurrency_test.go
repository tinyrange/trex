package native

import (
	"github.com/tinyrange/trex/storage"
	bytecache "github.com/tinyrange/trex/storage/cache"
	starfile "github.com/tinyrange/trex/storage/star"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStageCacheHitDoesNotWaitForUnrelatedMiss(t *testing.T) {
	c := stageTestCache(t, 1<<20)
	hot := &reopenedStageReader{size: 3, key: bytecache.Key{Index: 1}, open: func() (storage.Reader, error) { return &starfile.Bytes{Data: []byte("hot")}, nil }}
	if _, err := c.get(hot); err != nil {
		t.Fatal(err)
	}
	started, resume := make(chan struct{}), make(chan struct{})
	var opens atomic.Int32
	slow := &reopenedStageReader{size: 4, key: bytecache.Key{Index: 2}, open: func() (storage.Reader, error) {
		opens.Add(1)
		close(started)
		<-resume
		return &starfile.Bytes{Data: []byte("slow")}, nil
	}}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := c.get(slow); err != nil {
			t.Error(err)
		}
	}()
	<-started
	// Cleanup unblocks the loader even if the bounded responsiveness assertion fails.
	defer func() { close(resume); wg.Wait() }()
	hit := make(chan error, 1)
	go func() { _, err := c.get(hot); hit <- err }()
	select {
	case err := <-hit:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cache hit blocked behind unrelated miss")
	}
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f, err := c.get(slow)
			if err != nil || f.Size() != 4 {
				t.Errorf("shared miss: %v", err)
			}
		}()
	}
	// Test cleanup runs after the deferred loader release and waiter join.
	t.Cleanup(func() {
		if opens.Load() != 1 {
			t.Errorf("shared miss opened %d times", opens.Load())
		}
	})
}
