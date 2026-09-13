package ramfb

import (
	"encoding/binary"
	"testing"
)

func TestCaptureLayoutAndOwnership(t *testing.T) {
	m := make([]byte, Pixels+32)
	for i, v := range []uint32{Magic, 1, 2, 2, 16, 1} {
		binary.LittleEndian.PutUint32(m[i*4:], v)
	}
	copy(m[Pixels:], []byte{1, 2, 3, 0, 4, 5, 6, 0})
	copy(m[Pixels+16:], []byte{7, 8, 9, 0, 10, 11, 12, 0})
	f, err := Capture(m)
	if err != nil {
		t.Fatal(err)
	}
	if p := f.RGBAAt(1, 1); p.R != 12 || p.G != 11 || p.B != 10 || p.A != 255 {
		t.Fatal(p)
	}
	m[Pixels+16] = 99
	if f.RGBAAt(0, 1).B != 7 {
		t.Fatal("capture aliases guest RAM")
	}
	binary.LittleEndian.PutUint32(m[16:], 7)
	if _, err := Capture(m); err == nil {
		t.Fatal("short stride accepted")
	}
	binary.LittleEndian.PutUint32(m[16:], 0xffffffff)
	if _, err := Capture(m); err == nil {
		t.Fatal("out of bounds layout accepted")
	}
	binary.LittleEndian.PutUint32(m[4:], 0)
	if f, err := Capture(m); err != nil || f != nil {
		t.Fatal("inactive mode did not yield VGA fallback")
	}
}
