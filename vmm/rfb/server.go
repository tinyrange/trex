// Package rfb implements an RFB 3.8 display session over a portable byte channel.
// Authentication belongs to the enclosing transport. Raw true-colour pixels,
// DesktopSize, keyboard transitions and pointer events are supported.
package rfb

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"image"
	"io"
	"strings"
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
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		for key := range s.keys {
			_ = display.Input(cleanup, vmm.Input{Kind: "key", Key: key})
		}
		_ = display.Input(cleanup, vmm.Input{Kind: "pointer"})
	}()
	return s.run()
}

type session struct {
	ctx           context.Context
	ch            channel.ByteChannel
	display       vmm.DisplaySource
	keys          map[string]bool
	format        []byte
	width, height int
	resize        bool
	previous      *image.RGBA
	px, py        int
	pointer       bool
}

func (s *session) read(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(s.ch, b)
	return b, err
}
func (s *session) write(b []byte) error { return channel.WriteAll(s.ch, b) }
func (s *session) run() error {
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
	for {
		b, err = s.read(1)
		if err != nil {
			return err
		}
		switch b[0] {
		case 0:
			b, err = s.read(19)
			if err != nil {
				return err
			}
			p := b[3:]
			if err = validFormat(p); err != nil {
				return err
			}
			s.format = p
			s.previous = nil
		case 2:
			b, err = s.read(3)
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
			for i := 0; i < n; i++ {
				if int32(be.Uint32(b[i*4:])) == -223 {
					s.resize = true
				}
			}
		case 3:
			b, err = s.read(9)
			if err != nil {
				return err
			}
			if err = s.update(b); err != nil {
				return err
			}
		case 4:
			b, err = s.read(7)
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
		case 5:
			b, err = s.read(5)
			if err != nil {
				return err
			}
			x, y := int(be.Uint16(b[1:])), int(be.Uint16(b[3:]))
			dx, dy := 0, 0
			if s.pointer {
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
			if err = s.display.Input(s.ctx, vmm.Input{Kind: "pointer", X: float64(dx), Y: float64(dy), Buttons: buttons}); err != nil {
				return err
			}
		case 6:
			b, err = s.read(7)
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
		default:
			return fmt.Errorf("unsupported RFB message %d", b[0])
		}
	}
}
func validFrame(f *image.RGBA) error {
	if f == nil || f.Rect.Min != (image.Point{}) || f.Rect.Dx() < 1 || f.Rect.Dy() < 1 || f.Rect.Dx() > 4096 || f.Rect.Dy() > 4096 {
		return fmt.Errorf("invalid framebuffer")
	}
	return nil
}
func validFormat(p []byte) error {
	if p[0] != 32 || p[1] != 24 || p[2] > 1 || p[3] != 1 || be.Uint16(p[4:]) != 255 || be.Uint16(p[6:]) != 255 || be.Uint16(p[8:]) != 255 {
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
	r := image.Rect(int(be.Uint16(req[1:])), int(be.Uint16(req[3:])), 0, 0)
	r.Max = image.Pt(r.Min.X+int(be.Uint16(req[5:])), r.Min.Y+int(be.Uint16(req[7:])))
	r = r.Intersect(f.Rect)
	full := r == f.Rect
	if req[0] != 0 && s.previous != nil {
		dirty := image.Rectangle{}
		for y := r.Min.Y; y < r.Max.Y; y++ {
			a, z := f.PixOffset(r.Min.X, y), s.previous.PixOffset(r.Min.X, y)
			if bytes.Equal(f.Pix[a:a+r.Dx()*4], s.previous.Pix[z:z+r.Dx()*4]) {
				continue
			}
			for x := r.Min.X; x < r.Max.X; x++ {
				if f.RGBAAt(x, y) != s.previous.RGBAAt(x, y) {
					dirty = dirty.Union(image.Rect(x, y, x+1, y+1))
				}
			}
		}
		r = dirty
	}
	if r.Empty() {
		return s.write([]byte{0, 0, 0, 0})
	}
	b := make([]byte, 16+r.Dx()*r.Dy()*4)
	b[3] = 1
	be.PutUint16(b[4:], uint16(r.Min.X))
	be.PutUint16(b[6:], uint16(r.Min.Y))
	be.PutUint16(b[8:], uint16(r.Dx()))
	be.PutUint16(b[10:], uint16(r.Dy()))
	i := 16
	for y := r.Min.Y; y < r.Max.Y; y++ {
		for x := r.Min.X; x < r.Max.X; x++ {
			c := f.RGBAAt(x, y)
			v := uint32(c.R)<<s.format[10] | uint32(c.G)<<s.format[11] | uint32(c.B)<<s.format[12]
			if s.format[2] == 1 {
				be.PutUint32(b[i:], v)
			} else {
				binary.LittleEndian.PutUint32(b[i:], v)
			}
			i += 4
		}
	}
	if full {
		s.previous = f
	} else {
		s.previous = nil
	}
	return s.write(b)
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
	if name, ok := map[uint32]string{0xff08: "backspace", 0xff09: "tab", 0xff0d: "enter", 0xff1b: "esc", 0xffff: "delete", 0xff50: "home", 0xff51: "left", 0xff52: "up", 0xff53: "right", 0xff54: "down", 0xff55: "pgup", 0xff56: "pgdn", 0xff57: "end", 0xff63: "insert", 0xffe1: "shift", 0xffe2: "shift_r", 0xffe3: "ctrl", 0xffe4: "ctrl_r", 0xffe9: "alt", 0xffea: "alt_r", 0xffe5: "caps_lock", 32: "space"}[k]; ok {
		return name
	}
	plain := "-=[];'`\\,./"
	names := strings.Split("minus equal bracket_left bracket_right semicolon apostrophe grave_accent backslash comma dot slash", " ")
	if i := strings.IndexRune(plain, rune(k)); i >= 0 {
		return names[i]
	}
	return ""
}
