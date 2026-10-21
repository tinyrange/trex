//go:build linux

package desktop

import (
	window "github.com/tinyrange/trex/frontend/desktop/internal/xwindow"
	"image"
	"testing"
)

func TestWheelPositionButtonsAndFractionalSteps(t *testing.T) {
	s := inputState{absolute: true}
	r := image.Rect(0, 10, 101, 111)
	s.event(window.InputEvent{Type: window.InputEventMouseDown, Button: window.ButtonLeft, MouseX: 10, MouseY: 20}, r)
	for i, want := range []int{0, 0, 0, 1} {
		got := s.event(window.InputEvent{Type: window.InputEventScroll, MouseX: 100, MouseY: 110, ScrollY: 0.25}, r)
		if len(got) != 1 || got[0].Wheel != want || got[0].X != 32767 || got[0].Y != 32767 || len(got[0].Buttons) != 1 || got[0].Buttons[0] != "left" {
			t.Fatalf("step %d: %+v", i, got)
		}
	}
	got := s.event(window.InputEvent{Type: window.InputEventScroll, ScrollY: -1}, r)
	if got[0].Wheel != -1 {
		t.Fatal(got)
	}
	s.event(window.InputEvent{Type: window.InputEventScroll, ScrollY: 0.75}, r)
	s.release()
	got = s.event(window.InputEvent{Type: window.InputEventScroll, ScrollY: 0.25}, r)
	if got[0].Wheel != 0 || len(got[0].Buttons) != 0 {
		t.Fatal("focus loss retained input", got)
	}
}
