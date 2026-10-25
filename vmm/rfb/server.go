// Package rfb implements an RFB 3.8 display session over a portable byte channel.
// Authentication belongs to the enclosing transport. Raw and zlib-compressed
// true-colour pixels, DesktopSize, ExtendedDesktopSize, keyboard and pointer
// events are supported. Resize requests require an optional vmm.ResizeDisplaySource.
package rfb

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"fmt"
	"image"
	"io"
	"time"

	"github.com/tinyrange/trex/channel"
	"github.com/tinyrange/trex/vmm"
)

var be = binary.BigEndian

// Serve owns and closes ch. Only one controlling session should own a display.
func Serve(ctx context.Context, ch channel.ByteChannel, display vmm.DisplaySource) error {
	defer ch.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			ch.Close()
		case <-done:
		}
	}()
	s := session{ctx: ctx, ch: ch, display: display, keys: make(map[string]bool), format: []byte{32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0}}
	defer func() {
		if s.compressor != nil {
			_ = s.compressor.Close()
		}
	}()
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		for key := range s.keys {
			_ = display.Input(cleanup, vmm.Input{Kind: "key", Key: key})
		}
		input := vmm.Input{Kind: "pointer", Absolute: s.absolute}
		if s.absolute {
			input.X, input.Y = s.absoluteCoordinates(s.px, s.py)
		}
		_ = display.Input(cleanup, input)
	}()
	return s.run()
}

type session struct {
	ctx                                     context.Context
	ch                                      channel.ByteChannel
	display                                 vmm.DisplaySource
	keys                                    map[string]bool
	format                                  []byte
	width, height                           int
	resize                                  bool
	extendedResize, resizeAdvertised        bool
	screenID, screenFlags                   uint32
	previous                                *image.RGBA
	px, py                                  int
	pointer                                 bool
	pointerTypes, pointerTypeSent, absolute bool
	zlibEncoding                            bool
	compressed                              bytes.Buffer
	compressor                              *zlib.Writer
	pixelRow                                []byte
}

func (s *session) read(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(s.ch, b)
	return b, err
}
func (s *session) write(b []byte) error { return channel.WriteAll(s.ch, b) }
func (s *session) handshake() error {
	if err := s.write([]byte("RFB 003.008\n")); err != nil {
		return err
	}
	b, err := s.read(12)
	if err != nil {
		return err
	}
	if string(b) != "RFB 003.008\n" {
		return fmt.Errorf("RFB 3.8 required")
	}
	if err = s.write([]byte{1, 1}); err != nil {
		return err
	}
	b, err = s.read(1)
	if err != nil {
		return err
	}
	if b[0] != 1 {
		return fmt.Errorf("unsupported security type")
	}
	if err = s.write([]byte{0, 0, 0, 0}); err != nil {
		return err
	}
	if _, err = s.read(1); err != nil {
		return err
	}
	f, err := s.display.Capture(s.ctx)
	if err != nil {
		return err
	}
	if err = validFrame(f); err != nil {
		return err
	}
	s.width = f.Rect.Dx()
	s.height = f.Rect.Dy()
	init := make([]byte, 24)
	be.PutUint16(init, uint16(s.width))
	be.PutUint16(init[2:], uint16(s.height))
	copy(init[4:], s.format)
	name := "trex VM"
	be.PutUint32(init[20:], uint32(len(name)))
	if err = s.write(append(init, []byte(name)...)); err != nil {
		return err
	}
	return nil
}

func (s *session) run() error {
	if err := s.handshake(); err != nil {
		return err
	}
	for {
		if err := s.message(); err != nil {
			return err
		}
	}
}

func (s *session) message() error {
	typeByte, err := s.read(1)
	if err != nil {
		return err
	}
	switch typeByte[0] {
	case 0:
		return s.setPixelFormat()
	case 2:
		return s.setEncodings()
	case 3:
		return s.requestUpdate()
	case 4:
		return s.keyEvent()
	case 5:
		return s.pointerEvent()
	case 6:
		return s.discardClipboard()
	case 251:
		return s.setDesktopSize()
	default:
		return fmt.Errorf("unsupported RFB message %d", typeByte[0])
	}
}

func (s *session) setPixelFormat() error {
	b, err := s.read(19)
	if err != nil {
		return err
	}
	p := b[3:]
	if err = validFormat(p); err != nil {
		return err
	}
	s.format = p
	s.previous = nil
	return nil
}

func (s *session) setEncodings() error {
	b, err := s.read(3)
	if err != nil {
		return err
	}
	n := int(be.Uint16(b[1:]))
	if n > 256 {
		return fmt.Errorf("too many encodings")
	}
	b, err = s.read(n * 4)
	if err != nil {
		return err
	}
	s.resize = false
	s.extendedResize = false
	s.pointerTypes = false
	s.zlibEncoding = false
	for i := 0; i < n; i++ {
		if int32(be.Uint32(b[i*4:])) == 6 {
			s.zlibEncoding = true
		}
		if int32(be.Uint32(b[i*4:])) == -223 {
			s.resize = true
		}
		if int32(be.Uint32(b[i*4:])) == -308 {
			s.extendedResize = true
		}
		if int32(be.Uint32(b[i*4:])) == -257 {
			s.pointerTypes = true
		}
	}
	return nil
}

func (s *session) resizeReady() (bool, error) {
	if _, ok := s.display.(vmm.ResizeDisplaySource); !ok {
		return false, nil
	}
	if ready, ok := s.display.(vmm.DisplayResizeReadiness); ok {
		return ready.ResizeReady(s.ctx)
	}
	return true, nil
}

func (s *session) extendedDesktopSize(reason, status uint16) error {
	b := make([]byte, 36)
	b[3] = 1
	be.PutUint16(b[4:], reason)
	be.PutUint16(b[6:], status)
	be.PutUint16(b[8:], uint16(s.width))
	be.PutUint16(b[10:], uint16(s.height))
	be.PutUint32(b[12:], 0xfffffecc) // ExtendedDesktopSize (-308).
	b[16] = 1                        // One screen covering the framebuffer.
	be.PutUint32(b[20:], s.screenID)
	be.PutUint16(b[28:], uint16(s.width))
	be.PutUint16(b[30:], uint16(s.height))
	be.PutUint32(b[32:], s.screenFlags)
	return s.write(b)
}

func (s *session) setDesktopSize() error {
	b, err := s.read(7)
	if err != nil {
		return err
	}
	w, h := int(be.Uint16(b[1:])), int(be.Uint16(b[3:]))
	screens, err := s.read(int(b[5]) * 16)
	if err != nil {
		return err
	}
	if !s.extendedResize || !s.resizeAdvertised {
		return fmt.Errorf("SetDesktopSize before resize capability negotiation")
	}
	status := uint16(0)
	if len(screens) != 16 || w < 1 || h < 1 || w > 4096 || h > 4096 ||
		be.Uint16(screens[4:]) != 0 || be.Uint16(screens[6:]) != 0 ||
		int(be.Uint16(screens[8:])) != w || int(be.Uint16(screens[10:])) != h {
		status = 3 // Invalid layout; all records were consumed above.
	} else if ready, err := s.resizeReady(); err != nil || !ready {
		status = 1
	} else {
		ctx, cancel := context.WithTimeout(s.ctx, 60*time.Second)
		err := s.display.(vmm.ResizeDisplaySource).Resize(ctx, w, h)
		cancel()
		if err != nil {
			status = 3
		} else {
			f, err := s.display.Capture(s.ctx)
			if err != nil {
				return err
			}
			if err := validFrame(f); err != nil {
				return err
			}
			if f.Rect.Dx() != w || f.Rect.Dy() != h {
				status = 3
			} else {
				s.width, s.height = w, h
				s.screenID, s.screenFlags = be.Uint32(screens), be.Uint32(screens[12:])
				s.previous = nil
			}
		}
	}
	return s.extendedDesktopSize(1, status)
}

func (s *session) requestUpdate() error {
	b, err := s.read(9)
	if err != nil {
		return err
	}
	if err = s.update(b); err != nil {
		return err
	}
	return nil
}

func (s *session) keyEvent() error {
	b, err := s.read(7)
	if err != nil {
		return err
	}
	key := keyName(be.Uint32(b[3:]))
	if key != "" {
		down := b[0] != 0
		if err = s.display.Input(s.ctx, vmm.Input{Kind: "key", Key: key, Down: down}); err != nil {
			return err
		}
		if down {
			s.keys[key] = true
		} else {
			delete(s.keys, key)
		}
	}
	return nil
}

func (s *session) pointerEvent() error {
	b, err := s.read(5)
	if err != nil {
		return err
	}
	x, y := int(be.Uint16(b[1:])), int(be.Uint16(b[3:]))
	dx, dy := 0, 0
	if s.pointerTypeSent && !s.absolute {
		dx, dy = x-0x7fff, y-0x7fff
	} else if s.pointer {
		dx = int(int16(uint16(x - s.px)))
		dy = int(int16(uint16(y - s.py)))
	}
	s.px = x
	s.py = y
	s.pointer = true
	buttons := []string{}
	for i, name := range []string{"left", "middle", "right"} {
		if b[0]&(1<<i) != 0 {
			buttons = append(buttons, name)
		}
	}
	input := vmm.Input{Kind: "pointer", X: float64(dx), Y: float64(dy), Buttons: buttons, Absolute: s.absolute}
	if s.absolute {
		input.X, input.Y = s.absoluteCoordinates(x, y)
	}
	if b[0]&8 != 0 {
		input.Wheel++
	}
	if b[0]&16 != 0 {
		input.Wheel--
	}
	if err = s.display.Input(s.ctx, input); err != nil {
		return err
	}
	return nil
}

func (s *session) absoluteCoordinates(x, y int) (float64, float64) {
	return float64(min(max(x, 0), s.width-1)) * 32767 / float64(max(s.width-1, 1)), float64(min(max(y, 0), s.height-1)) * 32767 / float64(max(s.height-1, 1))
}

func (s *session) discardClipboard() error {
	b, err := s.read(7)
	if err != nil {
		return err
	}
	n := be.Uint32(b[3:])
	if n > 1<<20 {
		return fmt.Errorf("clipboard too large")
	}
	if _, err = io.CopyN(io.Discard, s.ch, int64(n)); err != nil {
		return err
	}
	return nil
}

func validFrame(f *image.RGBA) error {
	if f == nil || f.Rect.Min != (image.Point{}) || f.Rect.Dx() < 1 || f.Rect.Dy() < 1 || f.Rect.Dx() > 4096 || f.Rect.Dy() > 4096 {
		return fmt.Errorf("invalid framebuffer")
	}
	// Check storage independently from Rect so a malformed backend frame cannot
	// cause slice panics. This also permits padded rows without requiring a full
	// stride after the final row. Division avoids overflow for hostile strides.
	row := f.Rect.Dx() * 4
	if f.Stride < row || len(f.Pix) < row || f.Rect.Dy()-1 > (len(f.Pix)-row)/f.Stride {
		return fmt.Errorf("invalid framebuffer storage")
	}
	return nil
}
func validFormat(p []byte) error {
	if len(p) != 16 || p[0] != 32 || p[1] != 24 || p[2] > 1 || p[3] != 1 || be.Uint16(p[4:]) != 255 || be.Uint16(p[6:]) != 255 || be.Uint16(p[8:]) != 255 {
		return fmt.Errorf("RFB requires 32-bit RGB888 true colour")
	}
	var used uint32
	for _, shift := range p[10:13] {
		if shift > 24 {
			return fmt.Errorf("invalid pixel shift")
		}
		mask := uint32(255) << shift
		if used&mask != 0 {
			return fmt.Errorf("overlapping pixel channels")
		}
		used |= mask
	}
	return nil
}
func (s *session) update(req []byte) error {
	f, err := s.display.Capture(s.ctx)
	if err != nil {
		return err
	}
	if err = validFrame(f); err != nil {
		return err
	}
	if s.extendedResize {
		ready, err := s.resizeReady()
		if err != nil {
			return err
		}
		if (ready && !s.resizeAdvertised) || (s.resizeAdvertised && (req[0] == 0 || f.Rect.Dx() != s.width || f.Rect.Dy() != s.height)) {
			s.resizeAdvertised = true
			s.width, s.height = f.Rect.Dx(), f.Rect.Dy()
			s.previous = nil
			if err := s.extendedDesktopSize(0, 0); err != nil {
				return err
			}
			if req[0] != 0 {
				return nil
			}
			// The required layout update has no pixel rectangles. Fulfil a
			// full update request with a separate pixel update as well.
		}
	}
	if s.pointerTypes {
		absolute := false
		if source, ok := s.display.(vmm.AbsolutePointerSource); ok {
			absolute, err = source.AbsolutePointer(s.ctx)
			if err != nil {
				return err
			}
		}
		if !s.pointerTypeSent || absolute != s.absolute {
			s.absolute, s.pointerTypeSent, s.pointer = absolute, true, false
			b := make([]byte, 16)
			b[3] = 1
			if absolute {
				b[5] = 1
			}
			be.PutUint16(b[8:], uint16(s.width))
			be.PutUint16(b[10:], uint16(s.height))
			be.PutUint32(b[12:], 0xfffffeff)
			if err := s.write(b); err != nil {
				return err
			}
			if req[0] != 0 {
				return nil
			}
		}
	}
	if f.Rect.Dx() != s.width || f.Rect.Dy() != s.height {
		if !s.resize {
			return fmt.Errorf("client does not support DesktopSize")
		}
		s.width = f.Rect.Dx()
		s.height = f.Rect.Dy()
		s.previous = nil
		b := make([]byte, 16)
		b[3] = 1
		be.PutUint16(b[8:], uint16(s.width))
		be.PutUint16(b[10:], uint16(s.height))
		be.PutUint32(b[12:], 0xffffff21)
		return s.write(b)
	}
	r := image.Rectangle{Min: image.Pt(int(be.Uint16(req[1:])), int(be.Uint16(req[3:])))}
	r.Max = image.Pt(r.Min.X+int(be.Uint16(req[5:])), r.Min.Y+int(be.Uint16(req[7:])))
	r = r.Intersect(f.Rect)
	full := r == f.Rect
	if req[0] != 0 && s.previous != nil {
		dirty := image.Rectangle{}
		for y := r.Min.Y; y < r.Max.Y; y++ {
			a, z := f.PixOffset(r.Min.X, y), s.previous.PixOffset(r.Min.X, y)
			row, old := f.Pix[a:a+r.Dx()*4], s.previous.Pix[z:z+r.Dx()*4]
			if bytes.Equal(row, old) {
				continue
			}
			// Only the first and last differing pixels determine a row's
			// bounding rectangle. Avoid a union and RGBA conversion per pixel
			// when video or scrolling changes most of a scanline.
			left, right := 0, len(row)-1
			for row[left] == old[left] {
				left++
			}
			for row[right] == old[right] {
				right--
			}
			dirty = dirty.Union(image.Rect(r.Min.X+left/4, y, r.Min.X+right/4+1, y+1))
		}
		r = dirty
	}
	if r.Empty() {
		return s.write([]byte{0, 0, 0, 0})
	}
	var b [20]byte
	b[3] = 1
	be.PutUint16(b[4:], uint16(r.Min.X))
	be.PutUint16(b[6:], uint16(r.Min.Y))
	be.PutUint16(b[8:], uint16(r.Dx()))
	be.PutUint16(b[10:], uint16(r.Dy()))
	if full {
		s.previous = f
	} else {
		s.previous = nil
	}
	if s.zlibEncoding {
		// RFB encoding 6 uses one persistent zlib stream across rectangles,
		// with a sync flush per update. Keep the dictionary between frames.
		if s.compressor == nil {
			s.compressor, err = zlib.NewWriterLevel(&s.compressed, zlib.BestSpeed)
			if err != nil {
				return err
			}
		}
		s.compressed.Reset()
		if err = s.writePixelRows(s.compressor, f, r); err != nil {
			return err
		}
		if err = s.compressor.Flush(); err != nil {
			return err
		}
		be.PutUint32(b[12:], 6)
		be.PutUint32(b[16:], uint32(s.compressed.Len()))
		if err = s.write(b[:]); err != nil {
			return err
		}
		return s.write(s.compressed.Bytes())
	}
	// Preserve one complete update per transport write for raw clients.
	// Native clients negotiate zlib and avoid this full-frame buffer.
	var raw bytes.Buffer
	raw.Grow(16 + r.Dx()*r.Dy()*4)
	raw.Write(b[:16])
	if err = s.writePixelRows(&raw, f, r); err != nil {
		return err
	}
	return s.write(raw.Bytes())
}

func (s *session) writePixelRows(out io.Writer, f *image.RGBA, r image.Rectangle) error {
	// In RGBX order Go's RGBA storage is already the negotiated wire format.
	// The fourth byte carries no channel in a 24-bit true-colour pixel. Copying
	// it is valid and avoids repacking every pixel for the Metal client.
	native := s.format[2] == 0 && s.format[10] == 0 && s.format[11] == 8 && s.format[12] == 16 ||
		s.format[2] == 1 && s.format[10] == 24 && s.format[11] == 16 && s.format[12] == 8
	if !native && cap(s.pixelRow) < r.Dx()*4 {
		s.pixelRow = make([]byte, r.Dx()*4)
	}
	for y := r.Min.Y; y < r.Max.Y; y++ {
		start := f.PixOffset(r.Min.X, y)
		row := f.Pix[start : start+r.Dx()*4]
		if !native {
			dst := s.pixelRow[:len(row)]
			for x := 0; x < len(row); x += 4 {
				v := uint32(row[x])<<s.format[10] | uint32(row[x+1])<<s.format[11] | uint32(row[x+2])<<s.format[12]
				if s.format[2] == 1 {
					be.PutUint32(dst[x:], v)
				} else {
					binary.LittleEndian.PutUint32(dst[x:], v)
				}
			}
			row = dst
		}
		if err := channel.WriteAll(out, row); err != nil {
			return err
		}
	}
	return nil
}

var keyNames = map[uint32]string{
	0xff08: "backspace", 0xff09: "tab", 0xff0d: "enter", 0xff1b: "esc", 0xffff: "delete",
	0xff50: "home", 0xff51: "left", 0xff52: "up", 0xff53: "right", 0xff54: "down",
	0xff55: "pgup", 0xff56: "pgdn", 0xff57: "end", 0xff63: "insert",
	0xffe1: "shift", 0xffe2: "shift_r", 0xffe3: "ctrl", 0xffe4: "ctrl_r",
	0xffe9: "alt", 0xffea: "alt_r", 0xffe5: "caps_lock",
	// RFB clients may identify the GUI keys as either Meta or Super. Both
	// map to the same physical Windows/Command key on each side.
	0xffe7: "meta_l", 0xffe8: "meta_r", 0xffeb: "meta_l", 0xffec: "meta_r",
	' ': "space", '-': "minus", '=': "equal", '[': "bracket_left", ']': "bracket_right",
	';': "semicolon", '\'': "apostrophe", '`': "grave_accent", '\\': "backslash",
	',': "comma", '.': "dot", '/': "slash",
}

func keyName(k uint32) string {
	if k >= 'A' && k <= 'Z' {
		k += 32
	}
	if k >= 'a' && k <= 'z' || k >= '0' && k <= '9' {
		return string(rune(k))
	}
	if k >= 0xffbe && k <= 0xffc9 {
		return fmt.Sprintf("f%d", k-0xffbd)
	}
	return keyNames[k]
}
