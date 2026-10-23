package cc

import (
	"fmt"
	"j5.nz/cc/hypervisor/x86state"
)

// BIOS arguments are guest linear addresses, including in paged virtual-8086
// calls. Never lend the caller a physical slice and then silently write a
// different buffer. Walk every page: adjacent linear pages need not share
// adjacent RAM backing. Disk DMA continues using physical memory separately.
func (p *pc) biosCopy(address uint64, data []byte, write bool, s x86state.SystemRegisters) error {
	buffer, commit, err := p.guestMemory(address, uint64(len(data)), s, write)
	if err != nil {
		return err
	}
	if write {
		copy(buffer, data)
		commit()
	} else {
		copy(data, buffer)
	}
	return nil
}
func (p *pc) biosReadContext(address, size uint64, s x86state.SystemRegisters) ([]byte, error) {
	if size > 128<<10 {
		return nil, fmt.Errorf("BIOS buffer exceeds transfer bound")
	}
	data := make([]byte, int(size))
	if err := p.biosCopy(address, data, false, s); err != nil {
		return nil, err
	}
	return data, nil
}
func (p *pc) biosAccessSystem() (x86state.SystemRegisters, error) {
	// Pure block-device firmware helpers also support a nonpaged RAM fixture.
	if p.cpu == nil {
		return x86state.SystemRegisters{}, nil
	}
	return p.cpu.SystemRegisters()
}
func (p *pc) biosRead(address, size uint64) ([]byte, error) {
	s, err := p.biosAccessSystem()
	if err != nil {
		return nil, err
	}
	return p.biosReadContext(address, size, s)
}
func (p *pc) biosWrite(address uint64, data []byte) error {
	s, err := p.biosAccessSystem()
	if err != nil {
		return err
	}
	return p.biosCopy(address, data, true, s)
}
