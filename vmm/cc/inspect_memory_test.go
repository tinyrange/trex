package cc

import (
	"bytes"
	"encoding/binary"
	"testing"

	"j5.nz/cc/hypervisor/x86state"
)

func TestInspectionPageTableSelectionIsReadOnly(t *testing.T) {
	c := &darwinTestCPU{sys: x86state.SystemRegisters{Cr0: 1 << 31, Cr3: 0x1007, Efer: 1 << 10}}
	p := &pc{cpu: c, ram: make([]byte, 1<<20)}
	// The current (isolated user) root has no high kernel mapping. Another
	// root maps two adjacent virtual pages onto discontiguous physical pages.
	const address = uint64(0xffffff8000200000)
	put := func(off int, value uint64) { binary.LittleEndian.PutUint64(p.ram[off:], value) }
	put(0x2000+int(address>>39&511)*8, 0x3003)
	put(0x3000+int(address>>30&511)*8, 0x4003)
	put(0x4000+int(address>>21&511)*8, 0x5003)
	put(0x5000, 0x8003)
	put(0x5008, 0xa003)
	copy(p.ram[0x8ff8:], []byte("original"))
	copy(p.ram[0xa000:], []byte(" kernel!"))
	before := bytes.Clone(p.ram)
	system := c.sys
	if _, err := p.readVirtualBytes(address+4088, 16, 0); err == nil {
		t.Fatal("current user root unexpectedly exposes kernel")
	}
	b, err := p.readVirtualBytes(address+4088, 16, 0x2009) // Raw CR3 with PCID bits.
	if err != nil || string(b) != "original kernel!" {
		t.Fatalf("selected root cross-page read: %q %v", b, err)
	}
	if c.sys != system || !bytes.Equal(p.ram, before) {
		t.Fatal("inspection changed guest registers or RAM")
	}
	for _, tc := range []struct {
		address uint64
		size    int
		root    uint64
	}{
		{address, 1, 0xf0000},  // Unmapped root.
		{address, 1, 0x100000}, // Outside physical RAM.
		{address, -1, 0x2000}, {address, 65537, 0x2000},
		{^uint64(0), 2, 0x2000}, {0x0000800000000000, 1, 0x2000},
	} {
		if _, err := p.readVirtualBytes(tc.address, tc.size, tc.root); err == nil {
			t.Fatalf("bad observation accepted: %#v", tc)
		}
	}
	if c.sys != system || !bytes.Equal(p.ram, before) {
		t.Fatal("failed inspection changed guest")
	}
}
