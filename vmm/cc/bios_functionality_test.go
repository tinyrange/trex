package cc

import (
	"bytes"
	"encoding/binary"
	"j5.nz/cc/hypervisor/x86state"
	"testing"
)

func TestVGAFunctionalityPagedBuffer(t *testing.T) {
	p, c, _ := pagedBIOSFixture(t)
	p.vga = newVGA(make([]byte, 32768))
	p.mode = 3
	p.installVideoFirmware()
	p.ram[0x449] = 3
	p.ram[0x484] = 24
	p.ram[0x485] = 16
	es := uint16(0x8000)
	r := x86state.Registers{Rax: 0x1b00, Rdi: 0xff0}
	if cf, err := p.videoBIOS(&r, &es); cf || err != nil {
		t.Fatal(cf, err)
	}
	b, err := p.biosReadContext(0x80ff0, 64, c.system)
	if err != nil {
		t.Fatal(err)
	}
	if r.Rax != 0x1b1b || r.Rdi != 0xff0 || es != 0x8000 || binary.LittleEndian.Uint32(b) != 0xf0005200 || b[4] != 3 || b[34] != 24 || b[35] != 16 {
		t.Fatalf("bad state %x", b)
	}
	modes := binary.LittleEndian.Uint32(p.ram[0xf5200:])
	for mode := byte(0); mode < 32; mode++ {
		if modes&(1<<mode) != 0 {
			if err := p.vga.setMode(mode); err != nil {
				t.Fatal("advertised unsupported mode", mode)
			}
		}
	}
	if modes&(1<<0x12) == 0 {
		t.Fatal("VGA 640x480 mode not discoverable")
	}
	before := bytes.Clone(b)
	r.Rax = 0x1b00
	r.Rbx = 1
	if cf, err := p.videoBIOS(&r, &es); !cf || err != nil {
		t.Fatal("accepted unsupported query", cf, err)
	}
	b, err = p.biosReadContext(0x80ff0, 64, c.system)
	if err != nil || !bytes.Equal(b, before) {
		t.Fatal("invalid query wrote caller memory")
	}
}
