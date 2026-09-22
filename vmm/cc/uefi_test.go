package cc

import (
	"encoding/binary"
	"github.com/tinyrange/trex/emulator/cpu"
	"j5.nz/cc/hypervisor/x86state"
	"testing"
)

func TestEFIMemoryWalkAndAtomicCrossPageWrite(t *testing.T) {
	p := &pc{ram: make([]byte, 16<<20)}
	s := &x86state.SystemRegisters{Cr0: 1 << 31, Cr3: 0x1000, Cr4: 1 << 5, Efer: 1 << 10}
	m := efiMemory{p: p, system: s}
	put := func(a, v uint64) { binary.LittleEndian.PutUint64(p.ram[a:], v) }
	put(0x1000, 0x2003)
	put(0x2000, 0x3003)
	put(0x3000, 0x4003)
	put(0x4000, 0x8003)
	if err := m.WriteMemory(4094, []byte{1, 2, 3, 4}); err == nil {
		t.Fatal("accepted unmapped second page")
	}
	if p.ram[0x8ffe] != 0 {
		t.Fatal("partial write before page fault")
	}
	put(0x4008, 0xa003)
	if err := m.WriteMemory(4094, []byte{1, 2, 3, 4}); err != nil {
		t.Fatal(err)
	}
	if p.ram[0x8ffe] != 1 || p.ram[0xa000] != 3 {
		t.Fatal("wrong physical pages")
	}
	var data [4]byte
	if err := m.ReadMemory(4094, data[:], cpu.Read); err != nil || data != [4]byte{1, 2, 3, 4} {
		t.Fatal(data, err)
	}
	if _, err := m.physical(0x800000000000); err == nil {
		t.Fatal("accepted noncanonical address")
	}
	put(0x3008, 0x400083)
	if got, err := m.physical(0x201234); err != nil || got != 0x401234 {
		t.Fatal(got, err)
	}
	put(0x2008, 0x40000083)
	if got, err := m.physical(0x40101234); err != nil || got != 0x40101234 {
		t.Fatal(got, err)
	}
}
