package cc

import (
	"bytes"
	"j5.nz/cc/hypervisor/x86state"
	"testing"
)

func TestBIOSDACBlockUsesPagedRGBBuffer(t *testing.T) {
	p, c, _ := pagedBIOSFixture(t)
	p.vga = newVGA(make([]byte, 32768))
	// A triple crosses a linear page boundary whose physical pages are
	// discontiguous. Include high bits to verify VGA's six-bit components.
	data := []byte{48, 49, 50, 0xff, 0x80, 42}
	if err := p.biosCopy(0x80fff, data, true, c.system); err != nil {
		t.Fatal(err)
	}
	r := x86state.Registers{Rax: 0x1012, Rbx: 15, Rcx: 2, Rdx: 0xfff}
	if cf, err := p.videoBIOS(&r); cf || err != nil {
		t.Fatal(cf, err)
	}
	if p.vga.dac[15] != [3]byte{48, 49, 50} || p.vga.dac[16] != [3]byte{63, 0, 42} {
		t.Fatal("DAC block was ignored or addressed as physical memory", p.vga.dac[15:17])
	}
	r.Rax = 0x1017
	if cf, err := p.videoBIOS(&r); cf || err != nil {
		t.Fatal(cf, err)
	}
	got, err := p.biosReadContext(0x80fff, 6, c.system)
	if err != nil || !bytes.Equal(got, []byte{48, 49, 50, 63, 0, 42}) {
		t.Fatal(got, err)
	}
	// An invalid range must not partially overwrite the DAC.
	before := p.vga.dac
	r = x86state.Registers{Rax: 0x1012, Rbx: 255, Rcx: 2, Rdx: 0xfff}
	if cf, err := p.videoBIOS(&r); !cf || err != nil || p.vga.dac != before {
		t.Fatal("invalid DAC range accepted", cf, err)
	}
}

func TestBIOSDACSingleEntryAndPlanarColor(t *testing.T) {
	p := &pc{ram: make([]byte, 1<<20), vga: newVGA(make([]byte, 32768))}
	if err := p.vga.setMode(0x12); err != nil {
		t.Fatal(err)
	}
	r := x86state.Registers{Rax: 0x1010, Rbx: 15, Rcx: 0x3132, Rdx: 0x30ab}
	if cf, err := p.videoBIOS(&r); cf || err != nil {
		t.Fatal(cf, err)
	}
	r = x86state.Registers{Rax: 0x1015, Rbx: 15, Rdx: 0x00ab}
	if cf, err := p.videoBIOS(&r); cf || err != nil || r.Rcx != 0x3132 || r.Rdx != 0x30ab {
		t.Fatal(cf, err, r)
	}
	p.vga.attr[1] = 15
	p.vga.planes[0][0] = 0x80
	frame, err := p.vga.screenshot()
	if err != nil {
		t.Fatal(err)
	}
	pixel := frame.RGBAAt(0, 0)
	if pixel.R != 192 || pixel.G != 199 || pixel.B != 200 {
		t.Fatal("DAC update did not reach planar screenshot", pixel)
	}
}
