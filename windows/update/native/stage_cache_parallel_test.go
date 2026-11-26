package native

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/tinyrange/trex/storage"
	bytecache "github.com/tinyrange/trex/storage/cache"
	starfile "github.com/tinyrange/trex/storage/star"
)

type stageDiskCacheFunc func(func() ([]byte, error)) (storage.Reader, error)

func (f stageDiskCacheFunc) GetOrBuildContent(_ context.Context, _ [sha256.Size]byte, _ int64, build func() ([]byte, error)) (storage.Reader, error) {
	return f(build)
}

func TestStageDiskHitBypassesReconstructionAdmission(t *testing.T) {
	c := stageTestCache(t, 1<<20)
	data := []byte("verified disk hit")
	digest := sha256.Sum256(data)
	c.disk = stageDiskCacheFunc(func(_ func() ([]byte, error)) (storage.Reader, error) {
		return &starfile.Bytes{Data: data}, nil
	})
	r := &reopenedStageReader{
		size: int64(len(data)), expectedSHA256: &digest, cacheOnDisk: true,
		open: func() (storage.Reader, error) { return nil, errors.New("disk hit reconstructed source") },
	}
	c.loadMu.Lock()
	done := make(chan error, 1)
	go func() {
		f, err := c.get(r)
		if err == nil && f.Size() != r.size {
			err = errors.New("wrong cached length")
		}
		done <- err
	}()
	select {
	case err := <-done:
		c.loadMu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		c.loadMu.Unlock()
		<-done
		t.Fatal("verified disk hit waited behind active reconstruction")
	}
}

func TestStageDiskPublicationFailureReusesVerifiedBytes(t *testing.T) {
	c := stageTestCache(t, 1<<20)
	data := []byte("verified source")
	digest := sha256.Sum256(data)
	c.disk = stageDiskCacheFunc(func(build func() ([]byte, error)) (storage.Reader, error) {
		if _, err := build(); err != nil {
			return nil, err
		}
		return nil, errors.New("cannot publish disk record")
	})
	opens := 0
	r := &reopenedStageReader{
		size: int64(len(data)), expectedSHA256: &digest, cacheOnDisk: true,
		open: func() (storage.Reader, error) {
			opens++
			return &starfile.Bytes{Data: data}, nil
		},
	}
	f, err := c.get(r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := starfile.ReadAll(f)
	if err != nil || string(got) != string(data) || opens != 1 {
		t.Fatalf("fallback got %q, %v; source opened %d times", got, err, opens)
	}
}

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
