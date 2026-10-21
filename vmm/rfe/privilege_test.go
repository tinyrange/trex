package rfe

import (
	"context"
	"errors"
	"j5.nz/cc/hypervisor/x86state"
	"renvo.dev/rfe/x86"
	"testing"
)

func TestFirmwareRegisterSynchronizationPreservesVM86Privilege(t *testing.T) {
	raw, err := newCPU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c := raw.(*cpu)
	defer c.Close()
	s, _ := c.SystemRegisters()
	s.Cr0 |= 1
	s.Cs.Selector = 0xf000
	if err = c.SetSystemRegisters(s); err != nil {
		t.Fatal(err)
	}
	c.SetRegisters(x86state.Registers{Rflags: 0x20202})
	// BIOS CS has RPL0 but VM86 CLI at IOPL0 still faults at CPL3.
	c.SetSystemRegisters(s)
	err = c.core.Execute(x86.Instruction{PC: 0, Next: 1, Op: "cli"})
	var ex *x86.Exception
	if !errors.As(err, &ex) || ex.Vector != 13 {
		t.Fatalf("firmware sync gained privilege: CPL%d err%v", c.system.CPL, err)
	}
	c.SetRegisters(x86state.Registers{Rflags: 0x23202})
	if err = c.core.Execute(x86.Instruction{PC: 0, Next: 1, Op: "cli"}); err != nil {
		t.Fatal("VM86 IOPL3 CLI", err)
	}
	s.Cr0 &^= 1
	s.Cs.Selector = 0x1233
	c.SetSystemRegisters(s)
	c.SetRegisters(x86state.Registers{Rflags: 0x202})
	if c.system.CPL != 0 {
		t.Fatal("real mode used selector low bits as privilege")
	}
}
func TestCPUIDIgnoresECXExceptSignificantSubleafEntries(t *testing.T) {
	raw, err := newCPU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c := raw.(*cpu)
	defer c.Close()
	c.SetCPUID([]x86state.CPUIDEntry{{Function: 1, Eax: 0x663, Edx: 16}, {Function: 7, Index: 1, Flags: 1, Eax: 0x1234}})
	a, _, _, d := c.system.CPUID(1, 0xdeadbeef)
	if a != 0x663 || d != 16 {
		t.Fatal("legacy CPUID incorrectly required ECX0")
	}
	a, _, _, _ = c.system.CPUID(7, 0)
	if a != 0 {
		t.Fatal("significant subleaf ignored")
	}
	a, _, _, _ = c.system.CPUID(7, 1)
	if a != 0x1234 {
		t.Fatal("significant subleaf missing")
	}
}
