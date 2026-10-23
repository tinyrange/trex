package cc

// beforeRAMWrite revokes software code/native mapping proofs before firmware
// or DMA changes borrowed physical RAM. Pure translation/inspection users may
// conservatively notify too: the memory helper exposes a mutable capability.
func (p *pc) beforeRAMWrite(address, size uint64) {
	if cpu, ok := p.cpu.(interface{ BeforeRAMWrite(uint64, uint64) }); ok {
		cpu.BeforeRAMWrite(address, size)
	}
}
