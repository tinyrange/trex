package ramfb

import (
	"encoding/binary"
	"image"
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
	if reused, err := CaptureInto(m, f); err != nil || reused != f || f.RGBAAt(0, 1).B != 99 {
		t.Fatalf("capture did not reuse and refresh its destination: %v", err)
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

func BenchmarkCapture1080p(b *testing.B) {
	const width, height = 1920, 1080
	memory := make([]byte, Pixels+width*height*4)
	for i, value := range []uint32{Magic, 1, width, height, width * 4, 1} {
		binary.LittleEndian.PutUint32(memory[i*4:], value)
	}
	b.Run("allocate", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := Capture(memory); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("reuse", func(b *testing.B) {
		frame := image.NewRGBA(image.Rect(0, 0, width, height))
		b.ReportAllocs()
		for b.Loop() {
			if _, err := CaptureInto(memory, frame); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func TestMonochromeCaptureUsesBitOrderWidthAndPaddedRows(t *testing.T) {
	m := make([]byte, Pixels+8)
	for i, v := range []uint32{Magic, 1, 9, 2, 4, 2} {
		binary.LittleEndian.PutUint32(m[i*4:], v)
	}
	copy(m[Pixels:], []byte{0x80, 0xff, 0xff, 0xff, 0x01, 0x00, 0xff, 0xff})
	frame, err := Capture(m)
	if err != nil {
		t.Fatal(err)
	}
	for y := 0; y < 2; y++ {
		for x := 0; x < 9; x++ {
			want := byte(0)
			if y == 0 && (x == 0 || x == 8) || y == 1 && x == 7 {
				want = 255
			}
			p := frame.RGBAAt(x, y)
			if p.R != want || p.G != want || p.B != want || p.A != 255 {
				t.Fatalf("pixel %d,%d=%v", x, y, p)
			}
		}
	}
	binary.LittleEndian.PutUint32(m[16:], 1)
	if _, err := Capture(m); err == nil {
		t.Fatal("short monochrome row accepted")
	}
}
