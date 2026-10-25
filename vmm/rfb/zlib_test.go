package rfb

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"image"
	"image/color"
	"io"
	"testing"

	"github.com/tinyrange/trex/vmm"
)

func negotiate(t *testing.T, s *session, ch *bufferChannel, encodings ...int32) {
	t.Helper()
	ch.Reset()
	var packet []byte
	packet = append(packet, 0)
	packet = be.AppendUint16(packet, uint16(len(encodings)))
	for _, encoding := range encodings {
		packet = be.AppendUint32(packet, uint32(encoding))
	}
	ch.Write(packet)
	if err := s.setEncodings(); err != nil {
		t.Fatal(err)
	}
	ch.Reset()
}

func TestZlibPersistentStreamAcrossDirtyUpdatesFormatsAndNegotiation(t *testing.T) {
	frame := image.NewRGBA(image.Rect(0, 0, 3, 2))
	for y := 0; y < 2; y++ {
		for x := 0; x < 3; x++ {
			frame.SetRGBA(x, y, color.RGBA{R: byte(x + 1), G: byte(y + 2), B: 9, A: 255})
		}
	}
	d := &testDisplay{frame, make(chan vmm.Input, 1)}
	ch := &bufferChannel{}
	s := session{ctx: context.Background(), ch: ch, display: d, width: 3, height: 2,
		format: []byte{32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 0, 8, 16, 0, 0, 0}}
	negotiate(t, &s, ch, 6, 0, -223)
	var compressed, expected []byte
	updates := 0
	update := func(incremental bool, wantRect image.Rectangle, wantEncoding int32, wantPixels []byte) {
		t.Helper()
		ch.Reset()
		req := []byte{0, 0, 0, 0, 0}
		if incremental {
			req[0] = 1
		}
		req = be.AppendUint16(req, uint16(s.width))
		req = be.AppendUint16(req, uint16(s.height))
		if err := s.update(req); err != nil {
			t.Fatal(err)
		}
		packet := ch.Bytes()
		if len(packet) < 16 || be.Uint16(packet[2:]) != 1 || int32(be.Uint32(packet[12:])) != wantEncoding {
			t.Fatalf("unexpected rectangle header: %x", packet)
		}
		gotRect := image.Rectangle{Min: image.Pt(int(be.Uint16(packet[4:])), int(be.Uint16(packet[6:])))}
		gotRect.Max = gotRect.Min.Add(image.Pt(int(be.Uint16(packet[8:])), int(be.Uint16(packet[10:]))))
		if gotRect != wantRect {
			t.Fatalf("rectangle %v, want %v", gotRect, wantRect)
		}
		switch wantEncoding {
		case 6:
			if len(packet) < 20 || int(be.Uint32(packet[16:])) != len(packet)-20 {
				t.Fatalf("incorrect zlib length: %x", packet)
			}
			compressed = append(compressed, packet[20:]...)
			expected = append(expected, wantPixels...)
			updates++
		case 0:
			if !bytes.Equal(packet[16:], wantPixels) {
				t.Fatalf("raw pixels %x, want %x", packet[16:], wantPixels)
			}
		}
	}
	update(false, frame.Rect, 6, frame.Pix)
	ch.Reset()
	if err := s.update([]byte{1, 0, 0, 0, 0, 0, 3, 0, 2}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ch.Bytes(), []byte{0, 0, 0, 0}) {
		t.Fatalf("unchanged compressed update: %x", ch.Bytes())
	}
	frame.SetRGBA(2, 1, color.RGBA{R: 7, G: 8, B: 9, A: 255})
	update(true, image.Rect(2, 1, 3, 2), 6, []byte{7, 8, 9, 255})

	// Disabling and re-enabling compression, even across a pixel-format change,
	// must not restart its dictionary. Raw clients are still backwards-compatible.
	negotiate(t, &s, ch, 0, -223)
	update(false, frame.Rect, 0, frame.Pix)
	ch.Reset()
	ch.Write(append([]byte{0, 0, 0}, []byte{32, 24, 1, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0}...))
	if err := s.setPixelFormat(); err != nil {
		t.Fatal(err)
	}
	var bigEndianPixels []byte
	for i := 0; i < len(frame.Pix); i += 4 {
		bigEndianPixels = append(bigEndianPixels, 0, frame.Pix[i], frame.Pix[i+1], frame.Pix[i+2])
	}
	negotiate(t, &s, ch, 6, -223)
	update(true, frame.Rect, 6, bigEndianPixels)
	d.frame = image.NewRGBA(image.Rect(0, 0, 2, 1))
	d.frame.SetRGBA(0, 0, color.RGBA{R: 10, G: 20, B: 30, A: 255})
	update(true, d.frame.Rect, -223, nil)
	update(true, d.frame.Rect, 6, []byte{0, 10, 20, 30, 0, 0, 0, 0})
	if updates != 4 {
		t.Fatalf("compressed updates %d", updates)
	}
	// Finalize only in this test to check the entire standards-compliant stream,
	// including its checksum. Live RFB rectangles terminate at Z_SYNC_FLUSH.
	s.compressed.Reset()
	if err := s.compressor.Close(); err != nil {
		t.Fatal(err)
	}
	compressed = append(compressed, s.compressed.Bytes()...)
	inflater, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	defer inflater.Close()
	decoded, err := io.ReadAll(inflater)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, expected) {
		t.Fatalf("persistent pixels %x, want %x", decoded, expected)
	}
}

func TestPixelRowsHonorStrideRectangleAndChannelLayout(t *testing.T) {
	frame := &image.RGBA{Pix: make([]byte, 44), Stride: 24, Rect: image.Rect(0, 0, 5, 2)}
	for y := 0; y < 2; y++ {
		for x := 0; x < 5; x++ {
			frame.SetRGBA(x, y, color.RGBA{R: byte(10 + x), G: byte(20 + y), B: 30, A: 255})
		}
	}
	rect := image.Rect(1, 0, 4, 2)
	for _, layout := range []struct {
		name    string
		big     byte
		r, g, b byte
	}{
		{"native-little", 0, 0, 8, 16},
		{"native-big", 1, 24, 16, 8},
		{"bgr-little", 0, 16, 8, 0},
		{"rgb-big", 1, 16, 8, 0},
		{"non-byte-shifts", 0, 1, 9, 17},
	} {
		t.Run(layout.name, func(t *testing.T) {
			s := session{format: []byte{32, 24, layout.big, 1, 0, 255, 0, 255, 0, 255, layout.r, layout.g, layout.b, 0, 0, 0}}
			if err := validFormat(s.format); err != nil {
				t.Fatal(err)
			}
			var got bytes.Buffer
			if err := s.writePixelRows(&got, frame, rect); err != nil {
				t.Fatal(err)
			}
			if got.Len() != rect.Dx()*rect.Dy()*4 {
				t.Fatalf("pixel length %d", got.Len())
			}
			i := 0
			for y := rect.Min.Y; y < rect.Max.Y; y++ {
				for x := rect.Min.X; x < rect.Max.X; x++ {
					pixel := got.Bytes()[i : i+4]
					var value uint32
					if layout.big == 1 {
						value = binary.BigEndian.Uint32(pixel)
					} else {
						value = binary.LittleEndian.Uint32(pixel)
					}
					c := frame.RGBAAt(x, y)
					if byte(value>>layout.r) != c.R || byte(value>>layout.g) != c.G || byte(value>>layout.b) != c.B {
						t.Fatalf("pixel (%d,%d) %x not %v", x, y, pixel, c)
					}
					i += 4
				}
			}
		})
	}
}

func TestFrameStorageValidation(t *testing.T) {
	for _, f := range []*image.RGBA{
		nil,
		{Rect: image.Rect(0, 0, 2, 2), Stride: 4, Pix: make([]byte, 16)},
		{Rect: image.Rect(0, 0, 2, 2), Stride: 8, Pix: make([]byte, 15)},
		{Rect: image.Rect(0, 0, 2, 2), Stride: int(^uint(0) >> 1), Pix: make([]byte, 16)},
		{Rect: image.Rect(0, 0, 4097, 1)},
	} {
		if err := validFrame(f); err == nil {
			t.Fatalf("accepted invalid frame %#v", f)
		}
	}
	if err := validFrame(&image.RGBA{Rect: image.Rect(0, 0, 2, 2), Stride: 12, Pix: make([]byte, 20)}); err != nil {
		t.Fatalf("rejected padded valid frame: %v", err)
	}
	if validFormat(nil) == nil {
		t.Fatal("accepted absent pixel format")
	}
}

func TestRequestedSubregionAndDirtyBounds(t *testing.T) {
	frame := image.NewRGBA(image.Rect(0, 0, 6, 4))
	frame.SetRGBA(1, 0, color.RGBA{R: 10})
	frame.SetRGBA(4, 2, color.RGBA{G: 20})
	for _, tc := range []struct {
		name        string
		request     image.Rectangle
		incremental bool
		want        image.Rectangle
	}{
		{"nonzero-origin", image.Rect(2, 1, 5, 4), false, image.Rect(2, 1, 5, 4)},
		{"dirty-within-request", image.Rect(2, 1, 5, 4), true, image.Rect(4, 2, 5, 3)},
		{"full-dirty-bounds", frame.Rect, true, image.Rect(1, 0, 5, 3)},
		{"clip-to-frame", image.Rect(4, 2, 20, 20), false, image.Rect(4, 2, 6, 4)},
		{"outside-frame", image.Rect(7, 5, 8, 6), true, image.Rectangle{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ch := &bufferChannel{}
			s := session{ctx: context.Background(), ch: ch,
				display: &testDisplay{frame, make(chan vmm.Input, 1)},
				width:   6, height: 4, previous: image.NewRGBA(frame.Rect),
				format: []byte{32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0}}
			request := []byte{0}
			if tc.incremental {
				request[0] = 1
			}
			for _, value := range []int{tc.request.Min.X, tc.request.Min.Y, tc.request.Dx(), tc.request.Dy()} {
				request = be.AppendUint16(request, uint16(value))
			}
			if err := s.update(request); err != nil {
				t.Fatal(err)
			}
			packet := ch.Bytes()
			if tc.want.Empty() {
				if !bytes.Equal(packet, []byte{0, 0, 0, 0}) {
					t.Fatalf("out-of-bounds request received pixels: %x", packet)
				}
				return
			}
			if len(packet) != 16+tc.want.Dx()*tc.want.Dy()*4 {
				t.Fatalf("payload length %d, want %d", len(packet), 16+tc.want.Dx()*tc.want.Dy()*4)
			}
			got := image.Rectangle{Min: image.Pt(int(be.Uint16(packet[4:])), int(be.Uint16(packet[6:])))}
			got.Max = got.Min.Add(image.Pt(int(be.Uint16(packet[8:])), int(be.Uint16(packet[10:]))))
			if got != tc.want {
				t.Fatalf("rectangle %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMetaAndSuperWireEventsUsePortableGUIKeys(t *testing.T) {
	ch := &bufferChannel{}
	d := &testDisplay{inputs: make(chan vmm.Input, 4)}
	s := session{ctx: context.Background(), ch: ch, display: d, keys: make(map[string]bool)}
	// Mixing aliases on press/release must release the same physical key. Both
	// sides can be held concurrently, as required by Windows/Command chords.
	for _, step := range []struct {
		symbol uint32
		down   bool
		name   string
		held   int
	}{
		{0xffeb, true, "meta_l", 1},
		{0xffec, true, "meta_r", 2},
		{0xffe7, false, "meta_l", 1},
		{0xffe8, false, "meta_r", 0},
	} {
		packet := make([]byte, 7)
		if step.down {
			packet[0] = 1
		}
		be.PutUint32(packet[3:], step.symbol)
		ch.Write(packet)
		if err := s.keyEvent(); err != nil {
			t.Fatal(err)
		}
		input := <-d.inputs
		if input.Kind != "key" || input.Key != step.name || input.Down != step.down || len(s.keys) != step.held {
			t.Fatalf("keysym %#x: input=%+v held=%v", step.symbol, input, s.keys)
		}
	}
}
