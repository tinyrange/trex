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
	if boot.TSSLimit != 0 {
		s.Tr = x86state.Segment{Selector: 0x40, Base: boot.TSSBase, Limit: boot.TSSLimit, Type: 11, Present: 1}
	}
	s.Cr0 = 0x80010033                                       // PG, WP, NE, ET, MP, PE.
	s.Cr2, s.Cr3, s.Cr4, s.Cr8 = 0, boot.PageTable, 0x620, 0 // PAE, OSFXSR, OSXMMEXCPT.
	s.Efer = 0xd00                                           // LME, LMA, NXE.
	if boot.SyscallEntry != 0 {
		setter, ok := p.cpu.(interface {
			SetSyscallRegisters(x86state.SyscallRegisters) error
		})
		if !ok {
			return fmt.Errorf("cc backend cannot initialize AMD64 syscall registers")
		}
		// STAR selects __KERNEL_CS on SYSCALL and __USER32_CS as the
		// base selector on SYSRET, which adds 16 for 64-bit user code.
		if err := setter.SetSyscallRegisters(x86state.SyscallRegisters{
			STAR: 0x0023001000000000, LSTAR: boot.SyscallEntry,
			SFMASK: uint64(boot.SyscallMask), KernelGSBase: boot.KernelGSBase,
		}); err != nil {
			return err
		}
		s.Efer |= 1 // SCE.
	}
	s.InterruptBitmap = [4]uint64{}
	if err := p.cpu.SetSystemRegisters(s); err != nil {
		return fmt.Errorf("set AMD64 system registers: %w", err)
	}
	regs := boot.Registers
	regs.Rflags |= 2
	return p.cpu.SetRegisters(regs)
}
