package native

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tinyrange/trex/lifecycle"
	windowsupdate "github.com/tinyrange/trex/windows/update"
)

func TestCatalogRequestOverlapsAndPublishesOnce(t *testing.T) {
	resources := lifecycle.New()
	defer resources.Close()
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	request, err := newCatalogRequest(resources, windowsupdate.ScanOptions{}, windowsupdate.ClientProtocol{}, func(ctx context.Context) (*windowsupdate.Catalog, error) {
		calls.Add(1)
		close(started)
		select {
		case <-release:
			return &windowsupdate.Catalog{Rounds: 4}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("scan not started")
	}
	select {
	case <-request.done:
		t.Fatal("request did not remain in flight")
	default:
	}
	close(release)
	var results [8]*catalogValue
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			value, err := request.result()
			if err != nil {
				t.Error(err)
			}
			results[i] = value
		}()
	}
	wg.Wait()
	if calls.Load() != 1 || results[0] == nil || results[0].catalog.Rounds != 4 {
		t.Fatal("lost or repeated synchronization")
	}
	for _, result := range results {
		if result != results[0] {
			t.Fatal("result was rebuilt")
		}
	}
	if err := request.Close(); err != nil {
		t.Fatal(err)
	}
	value, err := request.result()
	if err != nil || value != results[0] {
		t.Fatal("completed result changed after close")
	}
}

func TestCatalogRequestCancellationAndFailedResultDoNotRetry(t *testing.T) {
	for _, executionClose := range []bool{false, true} {
		resources := lifecycle.New()
		var calls atomic.Int32
		request, err := newCatalogRequest(resources, windowsupdate.ScanOptions{}, windowsupdate.ClientProtocol{}, func(ctx context.Context) (*windowsupdate.Catalog, error) {
			calls.Add(1)
			<-ctx.Done()
			return nil, ctx.Err()
		})
		if err != nil {
			t.Fatal(err)
		}
		closed := make(chan struct{})
		go func() {
			if executionClose {
				resources.Close()
			} else {
				request.Close()
			}
			close(closed)
		}()
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Fatal("cancellation did not join worker")
		}
		for range 2 {
			if _, err := request.result(); !errors.Is(err, context.Canceled) {
				t.Fatalf("wanted cancellation, got %v", err)
			}
		}
		if calls.Load() != 1 {
			t.Fatal("failed result repeated scan")
		}
		resources.Close()
	}
	resources := lifecycle.New()
	resources.Close()
	_, err := newCatalogRequest(resources, windowsupdate.ScanOptions{}, windowsupdate.ClientProtocol{}, func(context.Context) (*windowsupdate.Catalog, error) {
		t.Error("closed execution launched scan")
		return nil, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("closed execution: %v", err)
	}
}

func TestCompletedCatalogRequestNotPinnedByExecution(t *testing.T) {
	resources := lifecycle.New()
	defer resources.Close()
	collected := make(chan struct{})
	func() {
		request, err := newCatalogRequest(resources, windowsupdate.ScanOptions{}, windowsupdate.ClientProtocol{}, func(context.Context) (*windowsupdate.Catalog, error) { return &windowsupdate.Catalog{}, nil })
		if err != nil {
			t.Fatal(err)
		}
		runtime.SetFinalizer(request, func(*catalogRequest) { close(collected) })
		if _, err := request.result(); err != nil {
			t.Fatal(err)
		}
	}()
	deadline := time.After(5 * time.Second)
	for {
		runtime.GC()
		select {
		case <-collected:
			runtime.KeepAlive(resources)
			return
		case <-deadline:
			t.Fatal("completed request retained by live execution")
		case <-time.After(10 * time.Millisecond):
		}
	}
}
