//go:build linux

package desktop

import (
	"context"
	window "github.com/tinyrange/trex/frontend/desktop/internal/xwindow"
	"github.com/tinyrange/trex/vmm"
	"image"
	"testing"
	"time"
)

func TestLetterboxAndPointerEndpoints(t *testing.T) {
	r := viewport(1000, 1000, 1280, 720)
	if r != image.Rect(0, 219, 1000, 781) {
		t.Fatal(r)
	}
	x, y := absolutePoint(r, 0, 219)
	if x != 0 || y != 0 {
		t.Fatal(x, y)
	}
	x, y = absolutePoint(r, 999, 780)
	if x != 32767 || y != 32767 {
		t.Fatal(x, y)
	}
	x, y = absolutePoint(r, -20, 1100)
	if x != 0 || y != 32767 {
		t.Fatal(x, y)
	}
}
func TestInputReleaseAndDragOutside(t *testing.T) {
	s := inputState{absolute: true}
	r := image.Rect(0, 10, 100, 90)
	s.event(window.InputEvent{Type: window.InputEventKeyDown, Key: window.KeyLeftControl}, r)
	s.event(window.InputEvent{Type: window.InputEventKeyDown, Key: window.KeyA}, r)
	if v := s.event(window.InputEvent{Type: window.InputEventMouseDown, Button: window.ButtonLeft, MouseX: 20, MouseY: 2}, r); len(v) != 0 {
		t.Fatal("letterbox click", v)
	}
	s.event(window.InputEvent{Type: window.InputEventMouseDown, Button: window.ButtonLeft, MouseX: 20, MouseY: 20}, r)
	v := s.event(window.InputEvent{Type: window.InputEventMouseMove, MouseX: 300, MouseY: 300}, r)
	if len(v) != 1 || v[0].X != 32767 || len(v[0].Buttons) != 1 {
		t.Fatal(v)
	}
	released := s.release()
	if len(released) != 3 {
		t.Fatal(released)
	}
	for _, e := range released {
		if e.Down || len(e.Buttons) != 0 {
			t.Fatal(e)
		}
	}
	if len(s.release()) != 0 {
		t.Fatal("duplicate releases")
	}
	if len(s.event(window.InputEvent{Type: window.InputEventKeyUp, Key: window.KeyA}, r)) != 0 {
		t.Fatal("stale key up")
	}
}

type testDisplay struct{ received chan vmm.Input }

func (d *testDisplay) Capture(ctx context.Context) (*image.RGBA, error) {
	return image.NewRGBA(image.Rect(0, 0, 2, 2)), nil
}
func (d *testDisplay) Input(ctx context.Context, in vmm.Input) error {
	select {
	case d.received <- in:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func TestDisplayWorkerInputAndCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source := &testDisplay{make(chan vmm.Input, 2)}
	inputs := make(chan vmm.Input, 2)
	frames := make(chan capturedFrame, 1)
	done := make(chan error, 1)
	go func() { done <- displayWorker(ctx, source, inputs, frames) }()
	inputs <- vmm.Input{Kind: "key", Key: "a", Down: true}
	inputs <- vmm.Input{Kind: "key", Key: "a", Down: false}
	for _, down := range []bool{true, false} {
		select {
		case got := <-source.received:
			if got.Down != down {
				t.Fatal(got)
			}
		case <-time.After(time.Second):
			t.Fatal("input stalled")
		}
	}
	select {
	case <-frames:
	case <-time.After(time.Second):
		t.Fatal("no frame")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("worker leaked")
	}
}
