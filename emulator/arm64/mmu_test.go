package arm64

import (
	"encoding/binary"
	"github.com/tinyrange/trex/emulator/cpu"
	"testing"
)

func TestTranslationPermissionsAndCrossPageAtomicity(t *testing.T) {
	m := cpu.NewAddressSpace(0x10000)
	if err := m.Map(0, make([]byte, 0x10000), cpu.Read|cpu.Write|cpu.Execute); err != nil {
		t.Fatal(err)
	}
	put := func(p, v uint64) {
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], v)
		if err := m.WriteMemory(p, b[:]); err != nil {
			t.Fatal(err)
		}
	}
	// Three-level 39-bit tables: VA 0x400000 maps to PA 0x8000.
	put(0x1000, 0x2003)
	put(0x2010, 0x3003)
	put(0x3000, 0x8000|0x703)
	put(0x3008, 0x9000|0x783)
	c := &CPU{currentEL: 4}
	c.SetRegister("sctlr_el1", 1)
	c.SetRegister("ttbr0_el1", 0x1000)
	c.SetRegister("tcr_el1", 25)
	c.SetRegister("mair_el1", 255)
	pa, err := c.Translate(m, 0x400123, cpu.Read)
	if err != nil || pa != 0x8123 {
		t.Fatalf("PA=%x err=%v", pa, err)
	}
	if _, err := c.Translate(m, 0x401000, cpu.Write); err == nil {
		t.Fatal("read-only mapping accepted write")
	}
	vm := c.VirtualMemory(m)
	// The single-page fast path must enforce the same permissions and observe
	// page-table edits immediately, without requiring a cache invalidation.
	if err := vm.WriteMemory(0x400000, []byte{0xa5}); err != nil {
		t.Fatal(err)
	}
	if err := vm.WriteMemory(0x401000, []byte{0xff}); err == nil {
		t.Fatal("single-page write ignored read-only permission")
	}
	put(0x3000, 0x9000|0x703)
	var remapped [1]byte
	if err := vm.ReadMemory(0x400000, remapped[:], cpu.Read); err != nil || remapped[0] != 0 {
		t.Fatalf("stale translation: data=%x err=%v", remapped, err)
	}
	put(0x3000, 0x8000|0x703)
	if err := vm.WriteMemory(0x400fff, []byte{1, 2}); err == nil {
		t.Fatal("expected second-page permission fault")
	}
	var b [1]byte
	m.ReadMemory(0x8fff, b[:], cpu.Read)
	if b[0] != 0 {
		t.Fatal("partial write before second-page fault")
	}
	put(0x3000, 0x8000|0x703|1<<53)
	if _, err := c.Translate(m, 0x400000, cpu.Execute); err == nil {
		t.Fatal("PXN ignored")
	}
	if err := vm.ReadMemory(0x400000, remapped[:], cpu.Execute); err == nil {
		t.Fatal("single-page fetch ignored PXN")
	}
	put(0x3000, 0x8003)
	if _, err := c.Translate(m, 0x400000, cpu.Read); err == nil {
		t.Fatal("access flag ignored")
	}
}

func TestSystemStateCloneAndAddressTranslationInstruction(t *testing.T) {
	m := memory(t)
	c := &CPU{currentEL: 4}
	c.x[0] = 0x12345678
	step(t, c, m, 0xd5087800) // AT S1E1R,X0 with MMU disabled
	par, _ := c.Register("par_el1")
	if par&0x0000fffffffff000 != 0x12345000 || par&1 != 0 {
		t.Fatalf("PAR=%x", par)
	}
	copy := c.Clone()
	c.SetRegister("ttbr0_el1", 0x4000)
	v, _ := copy.Register("ttbr0_el1")
	if v != 0 {
		t.Fatal("system register checkpoint aliases")
	}
	step(t, c, m, 0xd50342df)
	if c.daif != 0x80 {
		t.Fatalf("DAIF=%x", c.daif)
	}
	step(t, c, m, 0xd50342ff)
	if c.daif != 0 {
		t.Fatal(c.daif)
	}
}
