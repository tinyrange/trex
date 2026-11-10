package native

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/tinyrange/trex/storage"
	bytecache "github.com/tinyrange/trex/storage/cache"
	starfile "github.com/tinyrange/trex/storage/star"
)

func TestStageCacheParallelSmallExclusiveLarge(t *testing.T) {
	c := stageTestCache(t, 1<<20)
	started := make(chan int, 4)
	release := []chan struct{}{make(chan struct{}), make(chan struct{}), make(chan struct{})}
	var once [3]sync.Once
	unblock := func(i int) { once[i].Do(func() { close(release[i]) }) }
	var wg sync.WaitGroup
	defer func() {
		for i := range release {
			unblock(i)
		}
		wg.Wait()
	}()
	launch := func(i int, size int64) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := &reopenedStageReader{size: size, key: bytecache.Key{Index: i + 1}, open: func() (storage.Reader, error) {
				started <- i
				<-release[i]
				if i == 2 {
					return nil, errors.New("deliberate large load failure")
				}
				return &starfile.Bytes{Data: []byte("ok")}, nil
			}}
			f, err := c.get(r)
			if i == 2 {
				if err == nil {
					t.Error("large load error lost")
				}
				return
			}
			if err != nil || f.Size() != size {
				t.Errorf("small load: %v", err)
			}
		}()
	}
	await := func() int {
		t.Helper()
		select {
		case i := <-started:
			return i
		case <-time.After(5 * time.Second):
			t.Fatal("independent reconstruction did not progress")
			return -1
		}
	}
	launch(0, 2)
	if await() != 0 {
		t.Fatal("unexpected first loader")
	}
	launch(1, 2)
	if await() != 1 {
		t.Fatal("unexpected second loader")
	}
	launch(2, 8<<20)
	select {
	case <-started:
		t.Fatal("large load overlapped small loads")
	case <-time.After(30 * time.Millisecond):
	}
	unblock(0)
	select {
	case <-started:
		t.Fatal("large load overlapped remaining small load")
	case <-time.After(30 * time.Millisecond):
	}
	unblock(1)
	if await() != 2 {
		t.Fatal("large load did not acquire exclusive admission")
	}
	unblock(2)
}
