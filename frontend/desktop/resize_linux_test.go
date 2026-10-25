//go:build linux

package desktop

import (
	"context"
	"errors"
	"image"
	"sync/atomic"
	"testing"
	"time"
)

type resizeDisplay struct {
	ready    atomic.Bool
	requests chan image.Point
	block    bool
}

func (d *resizeDisplay) ResizeReady(context.Context) (bool, error) { return d.ready.Load(), nil }
func (d *resizeDisplay) Resize(ctx context.Context, w, h int) error {
	d.requests <- image.Pt(w, h)
	if d.block {
		<-ctx.Done()
		return ctx.Err()
	}
	return errors.New("mode rejected")
}

func TestViewportLimitPreservesAspect(t *testing.T) {
	for input, want := range map[image.Point]image.Point{
		image.Pt(3840, 2160): image.Pt(1920, 1080),
		image.Pt(800, 1200):  image.Pt(720, 1080),
		image.Pt(800, 600):   image.Pt(800, 600),
		image.Pt(1, 1e9):     image.Pt(1, 1080),
		image.Pt(1e9, 1):     image.Pt(1920, 1),
	} {
		if got := viewportSize(input); got != want {
			t.Fatalf("%v: got %v, want %v", input, got, want)
		}
	}
}

func TestResizeWorkerCoalescesWaitsAndDoesNotRetryRejectedSize(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := &resizeDisplay{requests: make(chan image.Point, 4)}
	sizes := make(chan image.Point, 4)
	done := make(chan struct{})
	go func() { defer close(done); resizeWorker(ctx, d, sizes) }()
	sizes <- image.Pt(800, 600)
	sizes <- image.Pt(1024, 768)
	select {
	case <-d.requests:
		t.Fatal("requested resize before guest became ready")
	case <-time.After(300 * time.Millisecond):
	}
	d.ready.Store(true)
	select {
	case size := <-d.requests:
		if size != image.Pt(1024, 768) {
			t.Fatal("did not coalesce viewport changes", size)
		}
	case <-time.After(time.Second):
		t.Fatal("did not observe readiness")
	}
	sizes <- image.Pt(1024, 768)
	select {
	case <-d.requests:
		t.Fatal("retried rejected size without a viewport change")
	case <-time.After(300 * time.Millisecond):
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker leaked")
	}
}

func TestResizeWorkerCancelsPendingRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := &resizeDisplay{requests: make(chan image.Point, 1), block: true}
	d.ready.Store(true)
	sizes := make(chan image.Point, 1)
	done := make(chan struct{})
	go func() { defer close(done); resizeWorker(ctx, d, sizes) }()
	sizes <- image.Pt(800, 600)
	select {
	case <-d.requests:
	case <-time.After(time.Second):
		t.Fatal("resize never started")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("pending request was not canceled")
	}
}
