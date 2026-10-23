package cc

import (
	"encoding/binary"
	"j5.nz/cc/hypervisor"
	"j5.nz/cc/hypervisor/x86state"
	"testing"
	"time"
)

type clockBIOSCPU struct {
	hypervisor.X86
	r x86state.Registers
	s x86state.SystemRegisters
}

func (c *clockBIOSCPU) CompleteIO() error                                   { return nil }
func (c *clockBIOSCPU) Registers() (x86state.Registers, error)              { return c.r, nil }
func (c *clockBIOSCPU) SystemRegisters() (x86state.SystemRegisters, error)  { return c.s, nil }
func (c *clockBIOSCPU) SetRegisters(r x86state.Registers) error             { c.r = r; return nil }
func (c *clockBIOSCPU) SetSystemRegisters(s x86state.SystemRegisters) error { c.s = s; return nil }
func TestBIOSSetAndReadTicksUseSameGuestClock(t *testing.T) {
	now := time.Unix(1000000000, 0)
	cpu := &clockBIOSCPU{r: x86state.Registers{Rip: 0x106a, Rsp: 0x8000, Rflags: 2}, s: x86state.SystemRegisters{Cs: x86state.Segment{Base: 0xf0000}}}
	p := &pc{cpu: cpu, ram: make([]byte, 1<<20), now: func() time.Time { return now }, started: now}
	cpu.r.Rax = 0x100
	cpu.r.Rcx = 0xaabb0012
	cpu.r.Rdx = 0xccdd3456
	p.ram[0x470] = 3
	binary.LittleEndian.PutUint16(p.ram[0x8004:], 1)
	if err := p.bios(); err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(p.ram[0x46c:]) != 0x123456 || p.ram[0x470] != 0 || binary.LittleEndian.Uint16(p.ram[0x8004:])&1 != 0 {
		t.Fatal("set ticks failed or left carry set")
	}
	now = now.Add(48 * time.Hour)
	binary.LittleEndian.PutUint32(p.ram[0x46c:], 0x12345a)
	p.ram[0x470] = 1
	cpu.r.Rax = 0
	if err := p.bios(); err != nil {
		t.Fatal(err)
	}
	if cpu.r.Rcx != 0xaabb0012 || cpu.r.Rdx != 0xccdd345a || cpu.r.Rax != 1 || p.ram[0x470] != 0 {
		t.Fatalf("read ignored guest counter or damaged high registers: %+v", cpu.r)
	}
	cpu.r.Rax = 0
	if err := p.bios(); err != nil {
		t.Fatal(err)
	}
	if cpu.r.Rax != 0 {
		t.Fatal("midnight flag was not consumed")
	}
}
