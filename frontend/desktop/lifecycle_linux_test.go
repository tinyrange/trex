//go:build linux

package desktop

import (
	"context"
	"image"
	"strings"
	"testing"
	"time"

	"github.com/tinyrange/trex/vmm"
)

type lifecycleDisplay struct {
	vmm.Driver
	state  vmm.State
	result vmm.Result
}

func (d *lifecycleDisplay) Status(context.Context) (vmm.State, error) { return d.state, nil }
func (d *lifecycleDisplay) Wait(context.Context) (vmm.Result, error)  { return d.result, nil }
func (d *lifecycleDisplay) Capture(context.Context) (*image.RGBA, error) {
	return image.NewRGBA(image.Rect(0, 0, 2, 2)), nil
}
func (d *lifecycleDisplay) Input(context.Context, vmm.Input) error { return nil }

func TestDisplayWorkerGuestTermination(t *testing.T) {
	for _, clean := range []bool{true, false} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		source := &lifecycleDisplay{state: vmm.State{Name: "stopped"}, result: vmm.Result{Clean: clean, Reason: "guest_failure", Detail: "CPU2: x86 triple fault"}}
		err := displayWorker(ctx, source, make(chan vmm.Input), make(chan capturedFrame, 1))
		cancel()
		if clean && err != nil {
			t.Fatal(err)
		}
		if !clean && (err == nil || !strings.Contains(err.Error(), "CPU2: x86 triple fault")) {
			t.Fatalf("guest failure lost: %v", err)
		}
	}
}

func TestDisplayWorkerPausedGuestStaysOpen(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	frames := make(chan capturedFrame, 1)
	done := make(chan error, 1)
	source := &lifecycleDisplay{state: vmm.State{Name: "paused"}}
	go func() { done <- displayWorker(ctx, source, make(chan vmm.Input), frames) }()
	select {
	case <-frames:
	case err := <-done:
		t.Fatalf("paused guest closed window: %v", err)
	case <-ctx.Done():
		t.Fatal("paused guest stopped producing frames")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
