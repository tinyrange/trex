package rfb

import (
	"bytes"
	"context"
	"github.com/tinyrange/trex/vmm"
	"image"
	"image/color"
	"io"
	"net"
	"testing"
	"time"
)

type testDisplay struct {
	frame  *image.RGBA
	inputs chan vmm.Input
}

func (d *testDisplay) Capture(context.Context) (*image.RGBA, error) {
	f := image.NewRGBA(d.frame.Rect)
	copy(f.Pix, d.frame.Pix)
	return f, nil
}
func (d *testDisplay) Input(_ context.Context, i vmm.Input) error { d.inputs <- i; return nil }
func TestSessionPixelsInputAndRelease(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	_ = b.SetDeadline(time.Now().Add(3 * time.Second))
	d := &testDisplay{image.NewRGBA(image.Rect(0, 0, 2, 1)), make(chan vmm.Input, 16)}
	d.frame.SetRGBA(0, 0, color.RGBA{1, 2, 3, 255})
	done := make(chan error, 1)
	go func() { done <- Serve(context.Background(), a, d) }()
	read := func(n int) []byte {
		t.Helper()
		p := make([]byte, n)
		if _, err := io.ReadFull(b, p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write := func(p []byte) {
		t.Helper()
		if _, err := b.Write(p); err != nil {
			t.Fatal(err)
		}
	}
	if string(read(12)) != "RFB 003.008\n" {
		t.Fatal("version")
	}
	write([]byte("RFB 003.008\n"))
	read(2)
	write([]byte{1})
	read(4)
	write([]byte{1})
	init := read(24)
	read(int(be.Uint32(init[20:])))
	write([]byte{3, 0, 0, 0, 0, 0, 0, 2, 0, 1})
	pixels := read(24)
	if string(pixels[16:20]) != string([]byte{3, 2, 1, 0}) {
		t.Fatalf("pixels %v", pixels)
	}
	write([]byte{3, 1, 0, 0, 0, 0, 0, 2, 0, 1})
	if got := read(4); got[3] != 0 {
		t.Fatal(got)
	}
	write([]byte{4, 1, 0, 0, 0, 0, 0, 'a'})
	if i := <-d.inputs; i.Key != "a" || !i.Down {
		t.Fatal(i)
	}
	b.Close()
	<-done
	if i := <-d.inputs; i.Key != "a" || i.Down {
		t.Fatal(i)
	}
}
func TestPixelFormatValidation(t *testing.T) {
	p := []byte{32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0}
	if err := validFormat(p); err != nil {
		t.Fatal(err)
	}
	p[10] = 8
	if validFormat(p) == nil {
		t.Fatal("accepted overlapping channels")
	}
}

type bufferChannel struct{ bytes.Buffer }

func (*bufferChannel) Close() error { return nil }

type modeDisplay struct {
	*testDisplay
	absolute bool
}

func (d *modeDisplay) AbsolutePointer(context.Context) (bool, error) { return d.absolute, nil }

func TestPointerModeChangesAndCoordinates(t *testing.T) {
	d := &modeDisplay{&testDisplay{image.NewRGBA(image.Rect(0, 0, 1280, 720)), make(chan vmm.Input, 8)}, true}
	ch := &bufferChannel{}
	s := session{ctx: context.Background(), ch: ch, display: d, width: 1280, height: 720, pointerTypes: true}
	req := []byte{1, 0, 0, 0, 0, 5, 0, 2, 208}
	if err := s.update(req); err != nil {
		t.Fatal(err)
	}
	if b := ch.Bytes(); len(b) != 16 || be.Uint16(b[4:]) != 1 || int32(be.Uint32(b[12:])) != -257 {
		t.Fatalf("mode: %v", b)
	}
	ch.Reset()
	ch.Write([]byte{1 | 8, 4, 255, 2, 207})
	if err := s.pointerEvent(); err != nil {
		t.Fatal(err)
	}
	if i := <-d.inputs; !i.Absolute || i.X != 32767 || i.Y != 32767 || i.Wheel != 1 || len(i.Buttons) != 1 {
		t.Fatal(i)
	}
	ch.Write([]byte{0, 255, 255, 255, 255})
	if err := s.pointerEvent(); err != nil {
		t.Fatal(err)
	}
	if i := <-d.inputs; i.X != 32767 || i.Y != 32767 {
		t.Fatal("out-of-bounds pointer was not clamped", i)
	}
	d.absolute = false
	if err := s.update(req); err != nil {
		t.Fatal(err)
	}
	if b := ch.Bytes(); len(b) != 16 || be.Uint16(b[4:]) != 0 {
		t.Fatalf("relative mode: %v", b)
	}
	ch.Reset()
	ch.Write([]byte{0, 128, 4, 127, 252})
	if err := s.pointerEvent(); err != nil {
		t.Fatal(err)
	}
	if i := <-d.inputs; i.Absolute || i.X != 5 || i.Y != -3 {
		t.Fatal("incorrect relative delta", i)
	}
}

func TestDirtyRectangleAndDesktopResize(t *testing.T) {
	f := image.NewRGBA(image.Rect(0, 0, 4, 3))
	old := image.NewRGBA(f.Rect)
	d := &testDisplay{f, make(chan vmm.Input, 1)}
	ch := &bufferChannel{}
	s := session{ctx: context.Background(), ch: ch, display: d, width: 4, height: 3, resize: true, previous: old, format: []byte{32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0}}
	f.SetRGBA(2, 1, color.RGBA{R: 7, A: 255})
	if err := s.update([]byte{1, 0, 0, 0, 0, 0, 4, 0, 3}); err != nil {
		t.Fatal(err)
	}
	b := ch.Bytes()
	if len(b) != 20 || be.Uint16(b[4:]) != 2 || be.Uint16(b[6:]) != 1 || be.Uint16(b[8:]) != 1 || be.Uint16(b[10:]) != 1 {
		t.Fatalf("dirty rectangle %v", b)
	}
	ch.Reset()
	d.frame = image.NewRGBA(image.Rect(0, 0, 8, 6))
	if err := s.update([]byte{1, 0, 0, 0, 0, 0, 4, 0, 3}); err != nil {
		t.Fatal(err)
	}
	b = ch.Bytes()
	if len(b) != 16 || int32(be.Uint32(b[12:])) != -223 || be.Uint16(b[8:]) != 8 || be.Uint16(b[10:]) != 6 {
		t.Fatalf("resize %v", b)
	}
}
