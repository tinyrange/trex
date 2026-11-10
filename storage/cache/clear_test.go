package bytecache

import (
	"bytes"
	"sync/atomic"
	"testing"
)

func TestClearPreservesReadersAndInflightLoads(t *testing.T) {
	c := New(16)
	first, err := c.Get(Key{Index: 1}, func() ([]byte, error) { return []byte("first"), nil })
	if err != nil {
		t.Fatal(err)
	}
	started, resume, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	go func() {
		defer close(done)
		_, err := c.Get(Key{Index: 2}, func() ([]byte, error) { calls.Add(1); close(started); <-resume; return []byte("second"), nil })
		if err != nil {
			t.Error(err)
		}
	}()
	<-started
	c.Clear()
	if s := c.Stats(); s.Bytes != 0 || s.Entries != 1 {
		t.Fatalf("clear state: %+v", s)
	}
	if !bytes.Equal(first, []byte("first")) {
		t.Fatal("clear invalidated caller bytes")
	}
	close(resume)
	<-done
	second, err := c.Get(Key{Index: 2}, func() ([]byte, error) { calls.Add(1); return nil, nil })
	if err != nil || string(second) != "second" || calls.Load() != 1 {
		t.Fatalf("inflight load changed: %q %v %d", second, err, calls.Load())
	}
	c.Clear()
	c.Clear()
	if s := c.Stats(); s.Bytes != 0 || s.Entries != 0 {
		t.Fatalf("cache not empty: %+v", s)
	}
	reread, _ := c.Get(Key{Index: 1}, func() ([]byte, error) { return []byte("reload"), nil })
	if string(reread) != "reload" {
		t.Fatal("stale entry survived clear")
	}
}
