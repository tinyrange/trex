package cc

import "testing"

func TestCGAMonoBankedMemoryAndModeTransition(t *testing.T) {
	v := newVGA(make([]byte, 32768))
	if err := v.setMode(6); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]uint64{{0xb8000, 0x80}, {0xba000, 0x40}, {0xb8050, 0x20}, {0xbbf3f, 1}} {
		v.write(pair[0], byte(pair[1]))
		if v.read(pair[0]) != byte(pair[1]) {
			t.Fatal("CGA readback")
		}
	}
	img, err := v.screenshot()
	if err != nil {
		t.Fatal(err)
	}
	if img.Bounds().Dx() != 640 || img.Bounds().Dy() != 200 {
		t.Fatal(img.Bounds())
	}
	for _, point := range [][2]int{{0, 0}, {1, 1}, {2, 2}, {639, 199}} {
		if img.RGBAAt(point[0], point[1]).R != 255 {
			t.Fatalf("bank/pixel missing %v", point)
		}
	}
	if img.RGBAAt(1, 0).R != 0 {
		t.Fatal("bit order corrupted")
	}
	if err := v.setMode(0x86); err != nil {
		t.Fatal(err)
	}
	if v.read(0xb8000) != 0x80 {
		t.Fatal("no-clear mode erased bank")
	}
	if err := v.setMode(0x12); err != nil {
		t.Fatal(err)
	}
	img, err = v.screenshot()
	if err != nil || img.Bounds().Dy() != 480 || v.cgaMono {
		t.Fatal("EGA transition", err)
	}
}
