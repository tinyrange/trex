package cc

import (
	"j5.nz/cc/hypervisor/x86state"
	"testing"
)

func TestBIOSPaletteTableAndSixBitColors(t *testing.T) {
	cpu := &biosLegacyCPU{}
	cpu.system.Es.Base = 0x20000
	p := &pc{cpu: cpu, ram: make([]byte, 1<<20), vga: newVGA(make([]byte, 32768))}
	for i := 0; i < 16; i++ {
		p.ram[0x20100+i] = byte(0x30 + i)
	}
	p.ram[0x20110] = 0x3f
	r := x86state.Registers{Rax: 0x1002, Rdx: 0x100}
	if cf, err := p.videoBIOS(&r); cf || err != nil {
		t.Fatal(cf, err)
	}
	r = x86state.Registers{Rax: 0x1007, Rbx: 7}
	if cf, err := p.videoBIOS(&r); cf || err != nil || r.Rbx != 0x3707 {
		t.Fatal(cf, err, r)
	}
	r = x86state.Registers{Rax: 0x1009, Rdx: 0x200}
	if cf, err := p.videoBIOS(&r); cf || err != nil {
		t.Fatal(cf, err)
	}
	for i := 0; i < 17; i++ {
		if p.ram[0x20200+i] != p.ram[0x20100+i] {
			t.Fatal("palette ES:DX roundtrip")
		}
	}
	if p.vga.dac[0x3f] != [3]byte{63, 63, 63} || p.vga.dac[0x14] != [3]byte{42, 21, 0} || p.vga.dac[0x38] != [3]byte{21, 21, 21} {
		t.Fatal("EGA primary/secondary intensity levels")
	}
	// BIOS palette entries control real plane-rendered text, including all
	// three color components. This prevents matching a false dark title.
	p.vga.text[0], p.vga.text[1] = 'A', 15
	p.vga.syncText()
	r = x86state.Registers{Rax: 0x1000, Rbx: 0x3f0f}
	p.videoBIOS(&r)
	frame, err := p.vga.screenshot()
	if err != nil {
		t.Fatal(err)
	}
	white := false
	for y := 0; y < 16; y++ {
		for x := 0; x < 8; x++ {
			c := frame.RGBAAt(x, y)
			if c.R == 255 && c.G == 255 && c.B == 255 {
				white = true
			}
		}
	}
	if !white {
		t.Fatal("BIOS palette did not affect glyph pixels")
	}
}
