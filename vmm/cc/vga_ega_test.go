package cc

import "testing"

func TestEGAMode10PlanarSurfaceAndNoClear(t *testing.T) {
	v := newVGA(make([]byte, 32768))
	if err := v.setMode(0x10); err != nil {
		t.Fatal(err)
	}
	v.seq[2] = 8
	v.write(0xa0000+349*80+79, 1)
	frame, err := v.screenshot()
	if err != nil {
		t.Fatal(err)
	}
	if frame.Bounds().Dx() != 640 || frame.Bounds().Dy() != 350 {
		t.Fatal(frame.Bounds())
	}
	c := frame.RGBAAt(639, 349)
	if c.R != 87 || c.G != 87 || c.B != 87 || frame.RGBAAt(638, 349).R != 0 {
		t.Fatal("EGA last scanline/plane pixel", c)
	}
	if err := v.setMode(0x90); err != nil {
		t.Fatal(err)
	}
	if v.planes[3][349*80+79] != 1 {
		t.Fatal("no-clear EGA mode discarded VRAM")
	}
	if err := v.setMode(0x12); err != nil {
		t.Fatal(err)
	}
	frame, err = v.screenshot()
	if err != nil || frame.Bounds().Dy() != 480 {
		t.Fatal("VGA transition", err)
	}
}
