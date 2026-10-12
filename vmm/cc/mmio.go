package cc

import "j5.nz/cc/hypervisor"

// Debugger stepping and ordinary execution must use the same device bus.
func (p *pc) handleMMIO(ex hypervisor.X86Exit) error {
	ex.Address = p.cpuAddress(ex.Address)
	if p.hpet != nil && ex.Address >= hpetAddress && ex.Address < hpetAddress+0x400 {
		return p.hpet.mmio(ex, p.cpu, p.now())
	}
	if ex.Address >= inputAddress && ex.Address < inputAddress+0x1000 {
		return p.input.mmio(ex, p.cpu)
	}
	return p.vga.mmio(ex, p.cpu)
}
