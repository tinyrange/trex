package cc

import (
	"bytes"
	"encoding/binary"
	"j5.nz/cc/hypervisor"
	"testing"
)

type ideIRQCPU struct {
	hypervisor.X86
	levels map[uint32]bool
}

func (c *ideIRQCPU) SetIRQ(n uint32, v bool) error { c.levels[n] = v; return nil }

func TestICH7RelocatedPIOAndRouting(t *testing.T) {
	p, data := dmaTestPC(t)
	p.pciIDE = newICH7PATA()
	c := &ideIRQCPU{levels: map[uint32]bool{}}
	p.cpu = c
	p.ide.irq = p.setIDEIRQ
	io := func(port uint16, write bool, b []byte) {
		t.Helper()
		if err := p.handleIO(hypervisor.X86Exit{Port: port, Size: 1, Count: uint32(len(b)), Write: write, Data: b}); err != nil {
			t.Fatal(err)
		}
	}
	config := func(offset uint32, b []byte) {
		t.Helper()
		a := make([]byte, 4)
		binary.LittleEndian.PutUint32(a, 0x80000800|offset&^3)
		if err := p.pciIO(hypervisor.X86Exit{Port: 0xcf8, Size: 4, Count: 1, Write: true, Data: a}); err != nil {
			t.Fatal(err)
		}
		if err := p.pciIO(hypervisor.X86Exit{Port: 0xcfc + uint16(offset&3), Size: uint8(len(b)), Count: 1, Write: true, Data: b}); err != nil {
			t.Fatal(err)
		}
	}
	// Firmware's compatibility IRQ must not alias the native PCI route.
	if p.pciIDE.config[0x3c] != 16 || p.pciIDE.primaryIRQ() != 14 {
		t.Fatal("wrong compatibility/native split")
	}
	config(0x10, []byte{1, 0xe0, 0, 0})
	config(0x14, []byte{9, 0xe0, 0, 0})
	config(9, []byte{1})
	if p.pciIDE.commandBase(0) != 0xe000 || p.pciIDE.controlPort(0) != 0xe00a {
		t.Fatal("BAR relocation ignored")
	}
	for n, v := range []byte{0, 1, 2, 0, 0, 0xe0, 0x20} {
		io(0xe001+uint16(n), true, []byte{v})
	}
	if !c.levels[16] || c.levels[14] {
		t.Fatal("native transfer did not assert only INTA")
	}
	sector := make([]byte, 512)
	if err := p.handleIO(hypervisor.X86Exit{Port: 0xe000, Size: 2, Count: 256, Data: sector}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sector, data[1024:1536]) {
		t.Fatal("relocated PIO did not read original disk")
	}
	// Status acknowledges the interrupt; decode and interrupt-disable gates work.
	io(0xe007, false, []byte{0})
	if c.levels[16] {
		t.Fatal("status did not acknowledge native interrupt")
	}
	p.ide.signal(true)
	config(9, []byte{0})
	if c.levels[16] || !c.levels[14] {
		t.Fatal("mode switch left stale native interrupt")
	}
	config(0x41, []byte{0})
	if c.levels[14] {
		t.Fatal("channel decode disable left asserted IRQ")
	}
	disabled := []byte{0}
	io(0x1f7, false, disabled)
	if disabled[0] != 0xff {
		t.Fatal("disabled primary decoded")
	}
	config(0x41, []byte{0x80})
	config(9, []byte{1})
	config(5, []byte{4})
	if c.levels[16] {
		t.Fatal("PCI interrupt-disable ignored in native mode")
	}
	absent := []byte{0}
	io(0x177, false, absent)
	if absent[0] != 0xff {
		t.Fatal("disabled secondary decoded")
	}
	config(0x43, []byte{0x80})
	io(0x177, false, absent)
	if absent[0] != 0 {
		t.Fatal("unimplemented enabled secondary pretended to be a disk")
	}
	for n := 0; n < 40; n++ {
		config(0x48, []byte{byte(n)})
	}
	if len(p.pciIDE.trace) != 32 {
		t.Fatal("configuration trace unbounded")
	}
}

func TestICH7RelocatedDMA(t *testing.T) {
	p, data := dmaTestPC(t)
	p.pciIDE = newICH7PATA()
	p.pciIDE.config[4] = 5
	binary.LittleEndian.PutUint32(p.pciIDE.bm[4:], 0x1000)
	p.pciIDE.write(0x20, 0x01)
	p.pciIDE.write(0x21, 0xe1)
	dmaPRD(p, 0, 0x20000, 512, true)
	dmaCommand(t, p, false, 1)
	if err := p.handleIO(hypervisor.X86Exit{Port: 0xe100, Size: 1, Count: 1, Write: true, Data: []byte{9}}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.ram[0x20000:0x20200], data[1024:1536]) {
		t.Fatal("relocated bus-master DMA failed")
	}
}
