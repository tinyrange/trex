package rfe

import (
	"context"
	"j5.nz/cc/hypervisor/x86state"
	"testing"
)

func TestA20AliasesReadsWritesAndBoundary(t *testing.T) {
	raw, err := newCPU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c := raw.(*cpu)
	defer c.Close()
	ram, err := c.MapRAM(0, 2<<20)
	if err != nil {
		t.Fatal(err)
	}
	ram[0], ram[1<<20], ram[0xfffff] = 0x12, 0x34, 0x56
	c.SetA20(false)
	v, err := c.Read(1<<20, 1, false)
	if err != nil || v != 0x12 {
		t.Fatal(v, err)
	}
	v, err = c.Read(0xfffff, 2, false)
	if err != nil || v != 0x1256 {
		t.Fatal(v, err)
	}
	if err = c.Write(0xfffff, 2, 0x789a); err != nil {
		t.Fatal(err)
	}
	if ram[0] != 0x78 || ram[0xfffff] != 0x9a || ram[1<<20] != 0x34 {
		t.Fatal("A20 write alias")
	}
	c.SetA20(true)
	v, err = c.Read(1<<20, 1, false)
	if err != nil || v != 0x34 {
		t.Fatal(v, err)
	}
}
func TestIRQPulseLatchedWhileMasked(t *testing.T) {
	raw, _ := newCPU(context.Background())
	c := raw.(*cpu)
	defer c.Close()
	c.pics[0].mask = 255
	c.SetIRQ(1, true)
	c.SetIRQ(1, false)
	if err := c.interrupts(); err != nil {
		t.Fatal(err)
	}
	if c.pics[0].irr != 2 {
		t.Fatal("lost IRQ pulse", c.pics[0])
	}
	c.pics[0].mask = 0
	if c.pics[0].pending() != 1 {
		t.Fatal("masked request not retained")
	}
}
func TestCPUIDUsesInstalledOwnedPolicy(t *testing.T) {
	raw, _ := newCPU(context.Background())
	c := raw.(*cpu)
	defer c.Close()
	ram, _ := c.MapRAM(0, 1<<20)
	copy(ram[0x1000:], []byte{0x0f, 0xa2})
	entries := []x86state.CPUIDEntry{{Function: 0, Eax: 7, Ebx: 123}}
	c.SetCPUID(entries)
	entries[0].Eax = 99
	c.core.PC = 0x1000
	if err := c.core.Step(); err != nil {
		t.Fatal(err)
	}
	if c.core.R[0] != 7 || c.core.R[3] != 123 {
		t.Fatal(c.core.R)
	}
}
