package cc

import (
	"bytes"
	"testing"
)

func programISADMA(d *isaDMA, ch int, address, count uint16, page, mode byte) {
	base, clear, mask, modePort := uint16(0), uint16(12), uint16(10), uint16(11)
	reg := uint16(ch * 2)
	if ch >= 4 {
		base, clear, mask, modePort = 0xc0, 0xd8, 0xd4, 0xd6
		reg = uint16((ch - 4) * 4)
	}
	d.port(mask, true, byte(ch&3)|4)
	d.port(clear, true, 0)
	d.port(base+reg, true, byte(address))
	d.port(base+reg, true, byte(address>>8))
	// Reprogram count with its actual port, resetting the shared flip-flop.
	d.port(clear, true, 0)
	cp := base + reg + 1
	if ch >= 4 {
		cp = base + reg + 2
	}
	d.port(cp, true, byte(count))
	d.port(cp, true, byte(count>>8))
	pages := []uint16{0x87, 0x83, 0x81, 0x82, 0x8f, 0x8b, 0x89, 0x8a}
	d.port(pages[ch], true, page)
	d.port(modePort, true, mode|byte(ch&3))
	d.port(mask, true, byte(ch&3))
}
func TestISADMAATWrapAndTerminalCount(t *testing.T) {
	d := newISADMA()
	ram := make([]byte, 0x40000)
	ram[0x2fffe], ram[0x2ffff], ram[0x20000] = 1, 2, 3
	programISADMA(d, 1, 0xfffe, 2, 2, 0x48)
	var got []byte
	for i := 0; i < 3; i++ {
		b, ok := d.readUnit(1, ram)
		if !ok {
			t.Fatal("premature stop")
		}
		got = append(got, b...)
	}
	if !bytes.Equal(got, []byte{1, 2, 3}) || d.channels[1].address != 1 {
		t.Fatal(got, d.channels[1])
	}
	if _, ok := d.readUnit(1, ram); ok {
		t.Fatal("TC did not mask single DMA")
	}
	v, _ := d.port(8, false, 0)
	again, _ := d.port(8, false, 0)
	if v != 2 || again != 0 {
		t.Fatal("TC clear-on-read", v, again)
	}
}
func TestISADMAWordAutoInitAndBounds(t *testing.T) {
	d := newISADMA()
	ram := make([]byte, 0x40000)
	copy(ram[0x3fffe:], []byte{1, 2})
	copy(ram[0x20000:], []byte{3, 4})
	programISADMA(d, 5, 0xffff, 1, 3, 0x58)
	a, ok := d.readUnit(5, ram)
	if !ok || !bytes.Equal(a, []byte{1, 2}) {
		t.Fatal(a)
	}
	b, ok := d.readUnit(5, ram)
	if !ok || !bytes.Equal(b, []byte{3, 4}) {
		t.Fatal(b)
	}
	if d.channels[5].address != 0xffff || d.channels[5].count != 1 || d.channels[5].masked {
		t.Fatal("auto-init not restored")
	}
	d.channels[5].page = 0xff
	if _, ok := d.readUnit(5, ram); ok {
		t.Fatal("out-of-RAM DMA accepted")
	}
	d.channels[5].page = 3
	d.channels[5].mode = 0x54
	if _, ok := d.readUnit(5, ram); ok {
		t.Fatal("wrong transfer direction accepted")
	}
}
