package vmm

import (
	"fmt"

	"github.com/tinyrange/trex/memory"
	"github.com/tinyrange/trex/storage"
	"j5.nz/cc/hypervisor/x86state"
)

// AMD64Boot is an explicit initial x86-64 long-mode handoff. RAM represents
// physical addresses starting at zero. The caller builds the page tables and
// descriptor tables and chooses whether the first instruction runs at CPL3.
type AMD64Boot struct {
	RAM            storage.Reader
	Registers      x86state.Registers
	PageTable      uint64
	GDT, IDT       x86state.DescriptorTable
	TSSBase        uint64
	TSSLimit       uint32
	FSBase, GSBase uint64
	SyscallEntry   uint64
	SyscallMask    uint32
	KernelGSBase   uint64
	User           bool
}

func (b *AMD64Boot) Validate(ramSize int64) error {
	if b == nil || b.RAM == nil {
		return fmt.Errorf("AMD64 handoff requires a physical memory file")
	}
	size := b.RAM.Size()
	if size <= 0 || size > ramSize || ramSize > 3<<30 || ramSize%4096 != 0 {
		return fmt.Errorf("AMD64 handoff requires page-aligned RAM up to 3 GiB")
	}
	if b.PageTable == 0 || b.PageTable%4096 != 0 || b.PageTable > uint64(size) || 4096 > uint64(size)-b.PageTable || b.GDT.Limit < 55 {
		return fmt.Errorf("AMD64 handoff requires a complete page-table root and GDT")
	}
	entry, err := memory.TranslateAMD64(b.RAM, b.PageTable, b.Registers.Rip)
	if err != nil || !entry.Execute || (b.User && !entry.User) || entry.Physical >= uint64(size) {
		return fmt.Errorf("AMD64 handoff entry is unavailable at the requested privilege")
	}
	if b.SyscallEntry != 0 {
		entry, err := memory.TranslateAMD64(b.RAM, b.PageTable, b.SyscallEntry)
		if err != nil || !entry.Execute || entry.User || entry.Physical >= uint64(size) {
			return fmt.Errorf("AMD64 syscall entry must map executable supervisor code in RAM")
		}
	} else if b.SyscallMask != 0 || b.KernelGSBase != 0 {
		return fmt.Errorf("AMD64 syscall mask and kernel GS base require a syscall entry")
	}
	if err := b.validateMemoryRange("GDT", b.GDT.Base, uint64(b.GDT.Limit)); err != nil {
		return err
	}
	if b.IDT.Base != 0 || b.IDT.Limit != 0 {
		if err := b.validateMemoryRange("IDT", b.IDT.Base, uint64(b.IDT.Limit)); err != nil {
			return err
		}
	}
	if b.TSSBase != 0 || b.TSSLimit != 0 {
		if b.GDT.Limit < 79 || b.TSSLimit < 103 || b.TSSLimit > 0xfffff {
			return fmt.Errorf("AMD64 handoff TSS requires a complete 64-bit descriptor at GDT selector 0x40")
		}
		if err := b.validateMemoryRange("TSS", b.TSSBase, uint64(b.TSSLimit)); err != nil {
			return err
		}
	}
	return nil
}

func (b *AMD64Boot) validateMemoryRange(name string, base, limit uint64) error {
	if limit > ^uint64(0)-base {
		return fmt.Errorf("AMD64 handoff %s range overflows", name)
	}
	size := uint64(b.RAM.Size())
	for address, remaining := base, limit+1; remaining != 0; {
		entry, err := memory.TranslateAMD64(b.RAM, b.PageTable, address)
		count := min(remaining, 4096-address%4096)
		if err != nil || entry.Physical >= size || count > size-entry.Physical {
			return fmt.Errorf("AMD64 handoff %s is not mapped in the supplied RAM", name)
		}
		address += count
		remaining -= count
	}
	return nil
}
