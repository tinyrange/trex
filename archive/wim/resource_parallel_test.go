package wim

import (
	"bytes"
	"errors"
	bytecache "github.com/tinyrange/trex/storage/cache"
	"io"
	"sync"
	"testing"
	"time"
)

func TestParallelResourceRanges(t *testing.T) {
	r, resource, want := metadataFixture()
	a := &Archive{file: r, chunkSize: 32768, cacheStore: bytecache.New(0)}
	for _, start := range []int64{0, 17, 32767, 32769} {
		f := newResourceFileRange("slice", a, resource, start, int64(len(want))-start-11)
		for _, off := range []int64{0, 3, 65539} {
			for _, size := range []int{0, 4096, 131072, 287013, len(want)} {
				dst := bytes.Repeat([]byte{0xcc}, size+2)
				n, err := f.ReadAt(dst[1:len(dst)-1], off)
				expected := min(size, int(f.Size()-off))
				if n != expected || (err != nil && err != io.EOF) || (n < size && err != io.EOF) || (n == size && err != nil) {
					t.Fatalf("start=%d off=%d size=%d: n=%d err=%v", start, off, size, n, err)
				}
				if dst[0] != 0xcc || dst[len(dst)-1] != 0xcc || !bytes.Equal(dst[1:1+n], want[start+off:start+off+int64(n)]) {
					t.Fatal("read changed sentinel, order, or subfile boundaries")
				}
			}
		}
	}
}

func TestParallelResourceJoinsOnFailure(t *testing.T) {
	r, resource, _ := metadataFixture()
	r.entered = make(chan struct{}, 64)
	r.release = make(chan struct{})
	r.fail = true
	var once sync.Once
	release := func() { once.Do(func() { close(r.release) }) }
	defer release()
	f := newResourceFile("failure", &Archive{file: r, chunkSize: 32768, cacheStore: bytecache.New(0)}, resource)
	done := make(chan error, 1)
	go func() {
		n, err := f.ReadAt(make([]byte, 131072), 0)
		if n != 0 {
			err = errors.New("reported bytes after failed prefix")
		}
		done <- err
	}()
	for i := 0; i < 4; i++ {
		select {
		case <-r.entered:
		case <-time.After(3 * time.Second):
			t.Fatal("workers not concurrent")
		}
	}
	select {
	case <-done:
		t.Fatal("returned before all destination writers stopped")
	case <-time.After(20 * time.Millisecond):
	}
	release()
	select {
	case err := <-done:
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("workers not joined")
	}
}
