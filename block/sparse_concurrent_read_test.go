package block

import (
	"bytes"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type pausedSparseBase struct {
	sparseTestBase
	armed   atomic.Bool
	entered chan struct{}
	resume  chan struct{}
}

func (b *pausedSparseBase) Capabilities() Capabilities { return Capabilities{Concurrent: true} }
func (b *pausedSparseBase) ReadAt(p []byte, off int64) (int, error) {
	n, err := b.sparseTestBase.ReadAt(p, off)
	if len(p) > int(SparseChunkSize) && b.armed.CompareAndSwap(true, false) {
		close(b.entered)
		<-b.resume
	}
	return n, err
}

func TestSparseSlowBaseReadReconcilesConcurrentWrites(t *testing.T) {
	for _, failWrite := range []bool{false, true} {
		name := "content"
		if failWrite {
			name = "terminal failure"
		}
		t.Run(name, func(t *testing.T) {
			original := bytes.Repeat([]byte{17}, 3*int(SparseChunkSize))
			base := &pausedSparseBase{sparseTestBase: original, entered: make(chan struct{}), resume: make(chan struct{})}
			backing := &sparseTestBacking{data: make([]byte, len(original))}
			d, err := NewSparseOverlay(base, backing)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = d.WriteAt([]byte{21}, 2*SparseChunkSize); err != nil {
				t.Fatal(err)
			}
			injected := errors.New("parallel backing write failed")
			if failWrite {
				backing.fault = injected
			}
			base.armed.Store(true)
			var wg sync.WaitGroup
			var once sync.Once
			release := func() { once.Do(func() { close(base.resume) }) }
			defer func() { release(); wg.Wait() }()
			got := make([]byte, len(original))
			readDone := make(chan error, 1)
			wg.Add(1)
			go func() { defer wg.Done(); _, err := d.ReadAt(got, 0); readDone <- err }()
			select {
			case <-base.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("base read did not start")
			}
			writeDone := make(chan error, 1)
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := d.WriteAt([]byte{33}, 2*SparseChunkSize); err != nil {
					writeDone <- err
					return
				}
				if _, err := d.WriteAt([]byte{42}, 0); err != nil {
					writeDone <- err
					return
				}
				one := make([]byte, 1)
				_, err := d.ReadAt(one, 2*SparseChunkSize)
				if err == nil && one[0] != 33 {
					err = errors.New("dirty read returned stale data")
				}
				writeDone <- err
			}()
			select {
			case err := <-writeDone:
				if failWrite {
					if !errors.Is(err, injected) {
						t.Fatal(err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("slow clean read blocked independent overlay I/O")
			}
			release()
			err = <-readDone
			if failWrite {
				if !errors.Is(err, injected) {
					t.Fatalf("in-flight read ignored terminal failure: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := bytes.Clone(original)
			want[0] = 42
			want[2*SparseChunkSize] = 33
			if !bytes.Equal(got, want) {
				t.Fatal("in-flight read failed to reconcile new and previously dirty chunks")
			}
		})
	}
}
