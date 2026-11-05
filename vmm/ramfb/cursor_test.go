package ramfb

import (
	"encoding/binary"
	"image/color"
	"testing"
)

func TestCursorMasksClippingAndOwnership(t *testing.T) {
	m := make([]byte, Pixels+16)
	for i, v := range []uint32{Magic, 1, 4, 1, 16, 1} {
		binary.LittleEndian.PutUint32(m[i*4:], v)
	}
	for x := 0; x < 4; x++ {
		copy(m[Pixels+x*4:], []byte{30, 20, 100, 0})
	}
	c := m[512:]
	binary.LittleEndian.PutUint32(c, CursorMagic)
	binary.LittleEndian.PutUint32(c[4:], 1)
	for offset, value := range map[int]uint16{8: 0, 10: 1, 16: 0, 18: 1, 20: 32, 22: 32, 24: 4, 26: 0x101} {
		binary.LittleEndian.PutUint16(c[offset:], value)
	}
	for i := 0; i < 128; i++ {
		c[28+i] = 255
	}
	c[28], c[156] = 0x3f, 0x50 // black, white, transparent, invert
	frame, err := Capture(m)
	if err != nil {
		t.Fatal(err)
	}
	want := []color.RGBA{{0, 0, 0, 255}, {255, 255, 255, 255}, {100, 20, 30, 255}, {155, 235, 225, 255}}
	for x, p := range want {
		if frame.RGBAAt(x, 0) != p {
			t.Fatalf("x=%d: %v want %v", x, frame.RGBAAt(x, 0), p)
		}
	}
	if m[Pixels] != 30 || m[Pixels+2] != 100 {
		t.Fatal("cursor changed guest pixels")
	}
	binary.LittleEndian.PutUint16(c[16:], 1) // clip one pixel at left edge
	frame, err = Capture(m)
	if err != nil {
		t.Fatal(err)
	}
	if frame.RGBAAt(0, 0) != want[1] || frame.RGBAAt(2, 0) != want[3] || frame.RGBAAt(3, 0) != want[2] {
		t.Fatal("cursor clipping failed")
	}
	for _, offset := range []int{4, 20, 22, 24} {
		value := binary.LittleEndian.Uint16(c[offset:])
		binary.LittleEndian.PutUint16(c[offset:], 0)
		frame, err = Capture(m)
		if err != nil || frame.RGBAAt(0, 0) != want[2] {
			t.Fatalf("invalid/inactive cursor field %d affected frame", offset)
		}
		binary.LittleEndian.PutUint16(c[offset:], value)
	}
}
