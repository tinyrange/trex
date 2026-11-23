package cc

import (
	"fmt"
	"io"

	"github.com/tinyrange/trex/vmm"
	"j5.nz/cc/hypervisor/x86state"
)

func (p *pc) installAMD64(boot *vmm.AMD64Boot) error {
	size := boot.RAM.Size()
	if _, err := io.ReadFull(io.NewSectionReader(boot.RAM, 0, size), p.ram[:size]); err != nil {
		return fmt.Errorf("load AMD64 physical RAM: %w", err)
	}
	s, err := p.cpu.SystemRegisters()
	if err != nil {
		return err
	}
	code := x86state.Segment{Selector: 0x10, Type: 11, Present: 1, S: 1, L: 1, G: 1, Limit: 0xffffffff}
	data := x86state.Segment{Selector: 0x18, Type: 3, Present: 1, S: 1, Db: 1, G: 1, Limit: 0xffffffff}
	if boot.User {
		code.Selector, code.Dpl = 0x33, 3
		data.Selector, data.Dpl = 0x2b, 3
	}
	s.Cs, s.Ss, s.Ds, s.Es, s.Fs, s.Gs = code, data, data, data, data, data
	s.Fs.Base, s.Gs.Base = boot.FSBase, boot.GSBase
	s.Gdt, s.Idt = boot.GDT, boot.IDT
	s.Cr0 = 0x80010033                                       // PG, WP, NE, ET, MP, PE.
	s.Cr2, s.Cr3, s.Cr4, s.Cr8 = 0, boot.PageTable, 0x620, 0 // PAE, OSFXSR, OSXMMEXCPT.
	s.Efer = 0xd00                                           // LME, LMA, NXE.
	s.InterruptBitmap = [4]uint64{}
	if err := p.cpu.SetSystemRegisters(s); err != nil {
		return fmt.Errorf("set AMD64 system registers: %w", err)
	}
	regs := boot.Registers
	regs.Rflags |= 2
	return p.cpu.SetRegisters(regs)
}
