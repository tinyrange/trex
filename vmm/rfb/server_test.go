package rfb

import (
	"bytes"
	"context"
	"errors"
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

type resizingDisplay struct {
	*testDisplay
	ready, reject, unchanged bool
	requests                 []image.Point
}

func (d *resizingDisplay) ResizeReady(context.Context) (bool, error) { return d.ready, nil }
func (d *resizingDisplay) Resize(_ context.Context, w, h int) error {
	d.requests = append(d.requests, image.Pt(w, h))
	if d.reject {
		return errors.New("guest rejected mode")
	}
	if !d.unchanged {
		d.frame = image.NewRGBA(image.Rect(0, 0, w, h))
	}
	return nil
}

func TestResizeAdvertisementWaitsForGuest(t *testing.T) {
	d := &resizingDisplay{testDisplay: &testDisplay{image.NewRGBA(image.Rect(0, 0, 4, 3)), make(chan vmm.Input, 1)}}
	ch := &bufferChannel{}
	s := session{ctx: context.Background(), ch: ch, display: d, width: 4, height: 3, resize: true, extendedResize: true, previous: d.frame, format: []byte{32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0}}
	req := []byte{1, 0, 0, 0, 0, 0, 4, 0, 3}
	if err := s.update(req); err != nil {
		t.Fatal(err)
	}
	if s.resizeAdvertised || ch.Len() != 4 {
		t.Fatal("advertised before guest was ready")
	}
	d.ready = true
	ch.Reset()
	if err := s.update(req); err != nil {
		t.Fatal(err)
	}
	if b := ch.Bytes(); !s.resizeAdvertised || len(b) != 36 || int32(be.Uint32(b[12:])) != -308 || be.Uint16(b[8:]) != 4 || be.Uint16(b[10:]) != 3 {
		t.Fatalf("missing late capability advertisement: %v", b)
	}
	// Every non-incremental request gets a layout update and a separate pixel
	// update, so clients requesting full frames repeatedly still receive pixels.
	ch.Reset()
	req[0] = 0
	if err := s.update(req); err != nil || ch.Len() != 36+16+4*3*4 {
		t.Fatalf("non-incremental layout: %v, %v", ch.Bytes(), err)
	}
	if b := ch.Bytes(); be.Uint16(b[2:]) != 1 || be.Uint16(b[38:]) != 1 || be.Uint32(b[48:]) != 0 {
		t.Fatalf("layout and pixels were not separate updates: %v", b)
	}
}

func resizeMessage(width, height int) []byte {
	b := make([]byte, 24)
	b[0], b[6] = 251, 1
	be.PutUint16(b[2:], uint16(width))
	be.PutUint16(b[4:], uint16(height))
	be.PutUint32(b[8:], 17)
	be.PutUint16(b[16:], uint16(width))
	be.PutUint16(b[18:], uint16(height))
	be.PutUint32(b[20:], 0x10203040) // Unrecognized flags must be preserved.
	return b
}

func TestClientResizeRequiresAppliedGeometry(t *testing.T) {
	for _, variant := range []struct {
		name                     string
		ready, reject, unchanged bool
		invalid                  bool
		status                   uint16
		calls                    int
	}{
		{"applied", true, false, false, false, 0, 1},
		{"rejected", true, true, false, false, 3, 1},
		{"unapplied", true, false, true, false, 3, 1},
		{"not-ready", false, false, false, false, 1, 0},
		{"invalid-layout", true, false, false, true, 3, 0},
	} {
		t.Run(variant.name, func(t *testing.T) {
			d := &resizingDisplay{testDisplay: &testDisplay{image.NewRGBA(image.Rect(0, 0, 4, 3)), make(chan vmm.Input, 1)}, ready: variant.ready, reject: variant.reject, unchanged: variant.unchanged}
			ch := &bufferChannel{}
			s := session{ctx: context.Background(), ch: ch, display: d, width: 4, height: 3, extendedResize: true, resizeAdvertised: true}
			b := resizeMessage(8, 6)
			if variant.invalid {
				b[12] = 1 // Screen x-coordinate does not cover the framebuffer.
			}
			ch.Write(b)
			if err := s.message(); err != nil {
				t.Fatal(err)
			}
			b = ch.Bytes()
			if len(b) != 36 || be.Uint16(b[4:]) != 1 || be.Uint16(b[6:]) != variant.status || len(d.requests) != variant.calls {
				t.Fatalf("response %v, calls %v", b, d.requests)
			}
			if variant.status == 0 {
				if s.width != 8 || s.height != 6 || be.Uint32(b[20:]) != 17 || be.Uint32(b[32:]) != 0x10203040 {
					t.Fatal("successful response did not echo exact layout", b)
				}
			} else if s.width != 4 || s.height != 3 {
				t.Fatal("failed request changed reported geometry")
			}
		})
	}
}

func TestResizeUnavailableSourcesAndMalformedMessages(t *testing.T) {
	d := &testDisplay{image.NewRGBA(image.Rect(0, 0, 4, 3)), make(chan vmm.Input, 1)}
	ch := &bufferChannel{}
	s := session{ctx: context.Background(), ch: ch, display: d, width: 4, height: 3, extendedResize: true}
	if ready, err := s.resizeReady(); err != nil || ready {
		t.Fatal("fixed display advertised resize", ready, err)
	}
	ch.Write(resizeMessage(8, 6))
	if err := s.message(); err == nil {
		t.Fatal("accepted resize without negotiation")
	}
	ch.Reset()
	b := resizeMessage(8, 6)
	ch.Write(b[:len(b)-1])
	if err := s.message(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated layout: %v", err)
	}
}
