package storage

import (
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type profileTestClock struct{ now atomic.Int64 }

func (c *profileTestClock) Now() time.Duration { return time.Duration(c.now.Load()) }

type profileTestReader struct {
	clock *profileTestClock
	delay time.Duration
	err   error
}

func (*profileTestReader) Size() int64 { return 2 }
func (r *profileTestReader) ReadAt(p []byte, off int64) (int, error) {
	r.clock.now.Add(int64(r.delay))
	if off != 0 {
		return 0, io.EOF
	}
	n := copy(p, []byte{0, 255})
	return n, r.err
}
func TestReadProfilerPreservesReadsAndBoundsAttribution(t *testing.T) {
	clock := &profileTestClock{}
	p, err := NewReadProfiler(clock, 1, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New("source failure")
	a, _ := p.Wrap(&profileTestReader{clock: clock, delay: time.Second, err: io.EOF}, "a")
	b, _ := p.Wrap(&profileTestReader{clock: clock, delay: 3 * time.Second, err: failure}, "b")
	c, _ := p.Wrap(&profileTestReader{clock: clock, delay: 2 * time.Second}, "a")
	buf := make([]byte, 3)
	if n, err := a.ReadAt(buf, 0); n != 2 || err != io.EOF || buf[0] != 0 || buf[1] != 255 || a.Size() != 2 {
		t.Fatalf("read = %d %v %v", n, err, buf)
	}
	if n, err := b.ReadAt(buf, 0); n != 2 || err != failure {
		t.Fatalf("error not preserved: %d %v", n, err)
	}
	c.ReadAt(buf, 0)
	s := p.Snapshot(0)
	if s.Total.Calls != 3 || s.Total.Bytes != 6 || s.Total.Requested != 9 || s.Total.Errors != 1 || s.Total.Total != 6*time.Second || s.Total.Max != 3*time.Second {
		t.Fatalf("totals: %+v", s.Total)
	}
	if s.TrackedFiles != 1 || s.Unattributed != 1 || s.Files[0].Calls != 2 || s.Files[0].Total != 3*time.Second {
		t.Fatalf("attribution: %+v", s)
	}
	if len(s.Events) != 2 || s.SlowReads != 3 || s.Events[0].Label != "b" || s.Events[0].Error != failure.Error() || s.Events[1].Duration != 2*time.Second {
		t.Fatalf("slowest: %+v", s.Events)
	}
	s.Files[0].Calls = 900
	if p.Snapshot(0).Files[0].Calls != 2 {
		t.Fatal("snapshot aliases mutable state")
	}
	p.Reset()
	if s := p.Snapshot(0); s.Total.Calls != 0 || len(s.Events) != 0 || s.Elapsed != 0 {
		t.Fatalf("reset: %+v", s)
	}
}

type blockingProfileReader struct {
	entered chan struct{}
	release chan struct{}
}

func (*blockingProfileReader) Size() int64 { return 1 }
func (r *blockingProfileReader) ReadAt(p []byte, _ int64) (int, error) {
	r.entered <- struct{}{}
	<-r.release
	p[0] = 42
	return 1, nil
}
func TestReadProfilerConcurrentReadsSnapshotAndReset(t *testing.T) {
	p, _ := NewReadProfiler(&profileTestClock{}, 4, 2, 0)
	source := &blockingProfileReader{entered: make(chan struct{}, 2), release: make(chan struct{})}
	r, _ := p.Wrap(source, "concurrent")
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); r.ReadAt(make([]byte, 1), 0) }()
	}
	for range 2 {
		select {
		case <-source.entered:
		case <-time.After(time.Second):
			close(source.release)
			wg.Wait()
			t.Fatal("profiler serialized source reads")
		}
	}
	p.Snapshot(0) // Must not wait for source I/O.
	p.Reset()
	close(source.release)
	wg.Wait()
	if p.Snapshot(0).Total.Calls != 0 {
		t.Fatal("pre-reset inflight reads leaked into new phase")
	}
	r.ReadAt(make([]byte, 1), 0)
	if p.Snapshot(1).Total.Calls != 1 {
		t.Fatal("post-reset read not recorded")
	}
}
func TestReadProfilerRejectsInvalidBounds(t *testing.T) {
	clock := &profileTestClock{}
	for _, bounds := range [][2]int{{0, 1}, {1, -1}, {1000001, 0}, {1, 65537}} {
		if _, err := NewReadProfiler(clock, bounds[0], bounds[1], 0); err == nil {
			t.Fatalf("accepted %v", bounds)
		}
	}
	p, _ := NewReadProfiler(clock, 1, 0, 0)
	if _, err := p.Wrap(nil, "a"); err == nil {
		t.Fatal("nil source")
	}
	if _, err := p.Wrap(&profileTestReader{clock: clock}, ""); err == nil {
		t.Fatal("empty label")
	}
}

func TestReadProfilerBoundsErrorSamplesWithoutChangingSourceError(t *testing.T) {
	clock := &profileTestClock{}
	profile, err := NewReadProfiler(clock, 1, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	failure := errors.New(strings.Repeat("source failure ", 1024))
	reader, err := profile.Wrap(&profileTestReader{clock: clock, err: failure}, "source")
	if err != nil {
		t.Fatal(err)
	}
	var out [2]byte
	if n, err := reader.ReadAt(out[:], 0); n != 2 || err != failure || out != [2]byte{0, 255} {
		t.Fatalf("source result changed: %d %v %v", n, err, out)
	}
	snapshot := profile.Snapshot(0)
	if len(snapshot.Events) != 1 || len(snapshot.Events[0].Error) != 4096 || !strings.HasSuffix(snapshot.Events[0].Error, "...") || snapshot.Total.Errors != 1 {
		t.Fatal("long source error did not remain bounded in the profile")
	}
}
