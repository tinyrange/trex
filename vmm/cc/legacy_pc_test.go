package cc

import (
	"image/color"
	"j5.nz/cc/hypervisor"
	"testing"
	"time"
)

func TestATRefreshBitAdvancesWithoutGuestReads(t *testing.T) {
	now := time.Unix(0, 0)
	p := &pc{now: func() time.Time { return now }, started: now, ports: map[uint16]byte{}}
	read := func() byte {
		ex := hypervisor.X86Exit{Port: 0x61, Size: 1, Count: 1, Data: []byte{0}}
		if err := p.handleIO(ex); err != nil {
			t.Fatal(err)
		}
		return ex.Data[0] & 16
	}
	if read() != 0 {
		t.Fatal("initial refresh phase")
	}
	now = now.Add(15085 * time.Nanosecond)
	if read() != 16 || read() != 16 {
		t.Fatal("refresh is tied to reads instead of time")
	}
	now = now.Add(15085 * time.Nanosecond)
	if read() != 0 {
		t.Fatal("refresh did not toggle back")
	}
}
func TestBIOSFontIsVisibleAndGuestCanReplaceIt(t *testing.T) {
	text := make([]byte, 32768)
	text[0], text[1] = 'A', 7
	v := newVGA(text)
	v.syncText()
	img, err := v.screenshot()
	if err != nil {
		t.Fatal(err)
	}
	visible := false
	for y := 0; y < 16; y++ {
		for x := 0; x < 8; x++ {
			if img.RGBAAt(x, y) != (color.RGBA{A: 255}) {
				visible = true
			}
		}
	}
	if !visible {
		t.Fatal("POST font rendered no A glyph")
	}
	clear(v.planes[2][int('A')*32 : int('A')*32+32])
	img, err = v.screenshot()
	if err != nil {
		t.Fatal(err)
	}
	for y := 0; y < 16; y++ {
		for x := 0; x < 8; x++ {
			if img.RGBAAt(x, y) != (color.RGBA{A: 255}) {
				t.Fatal("guest font replacement ignored")
			}
		}
	}
	if err = v.setMode(0x10); err != nil {
		t.Fatal(err)
	}
	img, err = v.screenshot()
	if err != nil || img.Bounds().Dx() != 640 || img.Bounds().Dy() != 350 {
		t.Fatal("EGA mode geometry", err)
	}
}
