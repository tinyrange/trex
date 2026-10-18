//go:build linux

package xwindow

import (
	"bufio"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/ebitengine/purego"
)

func TestCaptureQueuedMotionAndFocusLoss(t *testing.T) {
	if os.Getenv("TREX_TEST_X11") != "1" {
		t.Skip("set TREX_TEST_X11=1")
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	server := exec.Command("Xvfb", "-displayfd", "3", "-screen", "0", "640x480x24", "-nolisten", "tcp")
	server.ExtraFiles = []*os.File{w}
	if err := server.Start(); err != nil {
		w.Close()
		t.Fatal(err)
	}
	w.Close()
	defer func() { server.Process.Kill(); server.Wait() }()
	ready := make(chan string, 1)
	go func() { s, _ := bufio.NewReader(r).ReadString('\n'); ready <- strings.TrimSpace(s) }()
	select {
	case n := <-ready:
		if n == "" {
			t.Fatal("Xvfb failed")
		}
		t.Setenv("DISPLAY", ":"+n)
	case <-time.After(10 * time.Second):
		t.Fatal("Xvfb readiness timeout")
	}
	v, err := New("capture test", 320, 240, true)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	win := v.(*x11Window)
	var sync func(uintptr, int32) int32
	purego.RegisterLibFunc(&sync, x11lib, "XSync")
	var focus func(uintptr, uintptr, int32, uint64) int32
	purego.RegisterLibFunc(&focus, x11lib, "XSetInputFocus")
	sync(win.display, 0)
	focus(win.display, win.window, 1, 0)
	sync(win.display, 0)
	win.Poll()
	if !win.SetCaptured(true) {
		t.Fatal("capture failed")
	}
	sync(win.display, 0)
	win.Poll()
	win.DrainInputEvents()
	if !win.captured || win.hiddenCursor == 0 {
		t.Fatal("grab focus notification released capture or cursor not hidden")
	}
	for _, p := range [][2]int32{{170, 130}, {180, 135}} {
		e := xButtonEvent{Type: motionNotify, Display: win.display, Window: win.window, X: p[0], Y: p[1], SameScreen: 1}
		xSendEvent(win.display, win.window, 0, pointerMotionMask, unsafe.Pointer(&e))
	}
	sync(win.display, 0)
	win.Poll()
	var dx, dy float32
	for _, e := range win.DrainInputEvents() {
		if e.Type == InputEventMouseMove {
			dx += e.MouseDeltaX
			dy += e.MouseDeltaY
		}
	}
	if dx != 20 || dy != 15 {
		t.Fatalf("queued motion doubled: (%g,%g), want (20,15)", dx, dy)
	}
	sync(win.display, 0)
	win.Poll()
	for _, e := range win.DrainInputEvents() {
		if e.Type == InputEventMouseMove && (e.MouseDeltaX != 0 || e.MouseDeltaY != 0) {
			t.Fatal("warp leaked as motion", e)
		}
	}
	focus(win.display, xRootWindow(win.display, xDefaultScreen(win.display)), 1, 0)
	sync(win.display, 0)
	win.Poll()
	lost := false
	for _, e := range win.DrainInputEvents() {
		lost = lost || e.Type == InputEventFocusLost
	}
	if !lost || win.captured {
		t.Fatal("real focus loss did not release capture")
	}
}
