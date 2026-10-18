//go:build linux

package desktop

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/tinyrange/gowin/gl"
	window "github.com/tinyrange/trex/frontend/desktop/internal/xwindow"
	"image"
	"image/color"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"
)

// An isolated X server is a test fixture, never a production dependency.
func testXServer(t *testing.T) {
	t.Helper()
	if os.Getenv("TREX_TEST_X11") != "1" {
		t.Skip("set TREX_TEST_X11=1 to exercise real X11/GLX")
	}
	exe, err := exec.LookPath("Xvfb")
	if err != nil {
		t.Fatal("Xvfb required for isolated X11 test:", err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	cmd := exec.Command(exe, "-displayfd", "3", "-screen", "0", "1280x800x24", "-nolisten", "tcp")
	cmd.ExtraFiles = []*os.File{w}
	var logs bytes.Buffer
	cmd.Stderr = &logs
	if err := cmd.Start(); err != nil {
		w.Close()
		t.Fatal(err)
	}
	w.Close()
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	ready := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(r).ReadString('\n'); ready <- strings.TrimSpace(line) }()
	select {
	case n := <-ready:
		if n == "" {
			t.Fatal("Xvfb failed")
		}
		t.Setenv("DISPLAY", ":"+n)
	case <-time.After(10 * time.Second):
		t.Fatal("Xvfb readiness timeout")
	}
}
func TestNativeFramebufferPixels(t *testing.T) {
	testXServer(t)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	win, err := window.New("trex framebuffer test", 320, 240, true)
	if err != nil {
		t.Fatal(err)
	}
	defer win.Close()
	api, err := win.GL()
	if err != nil {
		t.Fatal(err)
	}
	render, err := newRenderer(api)
	if err != nil {
		t.Fatal(err)
	}
	defer render.close()
	// A padded subimage proves upload respects row stride and top-left orientation.
	backing := image.NewRGBA(image.Rect(0, 0, 10, 8))
	frame := backing.SubImage(image.Rect(1, 1, 9, 5)).(*image.RGBA)
	for y := 1; y < 5; y++ {
		for x := 1; x < 9; x++ {
			c := color.RGBA{255, 0, 0, 255}
			if y >= 3 {
				c = color.RGBA{0, 0, 255, 255}
			}
			frame.SetRGBA(x, y, c)
		}
	}
	render.upload(frame)
	w, h := win.BackingSize()
	render.draw(w, h)
	pixel := func(x, y int) color.RGBA {
		b := [4]byte{}
		api.ReadPixels(int32(x), int32(h-y-1), 1, 1, gl.RGBA, gl.UnsignedByte, unsafe.Pointer(&b[0]))
		return color.RGBA{b[0], b[1], b[2], b[3]}
	}
	for _, check := range []struct {
		x, y int
		want color.RGBA
	}{{160, 70, color.RGBA{255, 0, 0, 255}}, {160, 170, color.RGBA{0, 0, 255, 255}}} {
		if got := pixel(check.x, check.y); got != check.want {
			t.Fatal(fmt.Sprintf("pixel %d,%d: %v want %v", check.x, check.y, got, check.want))
		}
	}
	if c := pixel(10, 10); c.R > 20 || c.G > 20 || c.B > 25 {
		t.Fatal("letterbox not cleared", c)
	}
}
