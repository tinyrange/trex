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

func TestInspectionPAEPagesAndRootSelection(t *testing.T) {
	c := &darwinTestCPU{sys: x86state.SystemRegisters{Cr0: 1 << 31, Cr3: 0x1000, Cr4: 1 << 5, Efer: 1 << 11}}
	p := &pc{cpu: c, ram: make([]byte, 4<<20)}
	put := func(off int, value uint64) { binary.LittleEndian.PutUint64(p.ram[off:], value) }
	const address = uint64(0x80400000)
	const nx = uint64(1) << 63
	put(0x1030, 0x2001) // Third PDPTE of the separately aligned root at 0x1020.
	put(0x2010, 0x3003|nx)
	put(0x3000, 0x8003|nx)
	put(0x3008, 0xa003|nx)
	copy(p.ram[0x8ff8:], "original")
	copy(p.ram[0xa000:], " PAE map")
	put(0x2018, 0x200083|nx|1<<12) // 2 MiB leaf with PAT, CR4.PSE remains clear.
	copy(p.ram[0x201234:], "large")
	before, system := bytes.Clone(p.ram), c.sys
	if _, err := p.readVirtualBytes(address, 1, 0); err == nil {
		t.Fatal("wrong PAE root exposed mapping")
	}
	got, err := p.readVirtualBytes(address+4088, 16, 0x1038) // PWT/PCD ignored, root retains bits 5..11.
	if err != nil || string(got) != "original PAE map" {
		t.Fatalf("PAE cross-page read: %q %v", got, err)
	}
	got, err = p.readVirtualBytes(0x80601234, 5, 0x1020)
	if err != nil || string(got) != "large" {
		t.Fatalf("PAE large page: %q %v", got, err)
	}
	for _, address := range []uint64{0, 0x80800000, 0x80402000, 0x100000000} {
		if _, err := p.readVirtualBytes(address, 1, 0x1020); err == nil {
			t.Fatalf("unmapped/out-of-range PAE address accepted: %#x", address)
		}
	}
	if c.sys != system || !bytes.Equal(p.ram, before) {
		t.Fatal("PAE inspection changed guest registers or page-table attributes")
	}
	put(0x3000, 0x100008003|nx)
	physical, err := p.physical(address+123, x86state.SystemRegisters{Cr0: 1 << 31, Cr3: 0x1020, Cr4: 1 << 5})
	if err != nil || physical != 0x10000807b {
		t.Fatalf("PAE physical address lost high bits: %#x %v", physical, err)
	}
}
