package cc

import (
	"fmt"

	"j5.nz/cc/hypervisor"
)

// Debugger stepping and ordinary execution must use the same device bus.
func (p *pc) handleMMIO(ex hypervisor.X86Exit) error {
	if ex.Size == 0 || ex.Size > 8 || uint64(ex.Size) > ^uint64(0)-ex.Address {
		return fmt.Errorf("invalid MMIO range address=%#x size=%d", ex.Address, ex.Size)
	}
	ex.Address = p.cpuAddress(ex.Address)
	if p.legacyDisplay && ex.Address >= legacyDisplayAddress && ex.Address+uint64(ex.Size) <= legacyDisplayAddress+legacyDisplaySize {
		var value uint64
		for index := uint8(0); index < ex.Size; index++ {
			if ex.Write {
				p.ram[ex.Address+uint64(index)] = ex.Data[index]
			} else {
				value |= uint64(p.ram[ex.Address+uint64(index)]) << (index * 8)
			}
		}
		if !ex.Write {
			p.cpu.CompleteMMIORead(value, uint32(ex.Size))
		}
		return nil
	}
	if p.pciNIC != nil && p.pciNIC.contains(ex.Address, ex.Size) {
		return p.pciNIC.mmio(ex, p.cpu)
	}
	if p.nvme != nil && p.nvme.contains(ex.Address, ex.Size) {
		return p.nvme.mmio(ex, p.cpu)
	}
	if p.hpet != nil && ex.Address >= hpetAddress && ex.Address < hpetAddress+0x400 {
		return p.hpet.mmio(ex, p.cpu, p.now())
	}
	if ex.Address >= inputAddress && ex.Address < inputAddress+0x1000 {
		return p.input.mmio(ex, p.cpu)
	}
	// Conventional physical space above installed low RAM is an unassigned
	// bus range, not VGA. Win9x probes one page beyond reported RAM while
	// checking memory aliases. Like the QEMU control, reads return zero and
	// writes have no storage. Keep PCI/device apertures outside this range
	// strict so an unsupported device cannot silently look functional.
	lowEnd := min(uint64(len(p.ram)), uint64(pciMemoryBase))
	if ex.Size > 0 && ex.Size <= 8 && ex.Address >= lowEnd && ex.Address < uint64(pciMemoryBase) && uint64(ex.Size) <= uint64(pciMemoryBase)-ex.Address {
		if !ex.Write {
			p.cpu.CompleteMMIORead(0, uint32(ex.Size))
		}
		return nil
	}
	return p.vga.mmio(ex, p.cpu)
}
