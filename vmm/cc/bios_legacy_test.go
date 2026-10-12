package cc

import (
	"encoding/binary"
	"testing"

	"j5.nz/cc/hypervisor"
	"j5.nz/cc/hypervisor/x86state"
)

type biosLegacyCPU struct {
	hypervisor.X86
	regs   x86state.Registers
	system x86state.SystemRegisters
}

func (c *biosLegacyCPU) CompleteIO() error                                  { return nil }
func (c *biosLegacyCPU) Registers() (x86state.Registers, error)             { return c.regs, nil }
func (c *biosLegacyCPU) SetRegisters(r x86state.Registers) error            { c.regs = r; return nil }
func (c *biosLegacyCPU) SystemRegisters() (x86state.SystemRegisters, error) { return c.system, nil }
func (c *biosLegacyCPU) SetSystemRegisters(r x86state.SystemRegisters) error {
	c.system = r
	return nil
}

func TestBIOSAbsentLegacyPortProbesReturnToGuest(t *testing.T) {
	for _, vector := range []uint64{0x14, 0x17} {
		for _, ax := range []uint64{0x00a3, 0x0102, 0x0200, 0x0300, 0x7f55} {
			c := &biosLegacyCPU{regs: x86state.Registers{Rip: 0x1000 + vector*4 + 2, Rsp: 0x8000, Rax: ax, Rbx: 0x1234, Rdx: 3}, system: x86state.SystemRegisters{}}
			c.system.Cs.Base = 0xf0000
			p := &pc{cpu: c, ram: make([]byte, 1<<20)}
			binary.LittleEndian.PutUint16(p.ram[0x8004:], 0x0240)
			if err := p.bios(); err != nil {
				t.Fatalf("INT%x stopped native guest: %v", vector, err)
			}
			flags := binary.LittleEndian.Uint16(p.ram[0x8004:])
			if flags != 0x0241 || c.regs.Rax != (ax&0xff)|0x8600 || c.regs.Rbx != 0x1234 || c.regs.Rdx != 3 {
				t.Fatalf("INT%x absent-device return corrupts registers/flags: regs=%+v flags=%x", vector, c.regs, flags)
			}
			if binary.LittleEndian.Uint16(p.ram[0x410:]) != 0 {
				t.Fatal("probe advertised a nonexistent device")
			}
		}
	}
}
