package cc

import "j5.nz/cc/hypervisor/x86state"

// AH=87 uses a six-descriptor protected-mode transition table. The source and
// destination descriptors name physical memory; the table itself is addressed
// by the caller's ES:SI (which may be paged in a v8086 monitor).
func (p *pc) moveExtendedMemory(table uint64, words uint16, s x86state.SystemRegisters) byte {
	descriptors, _, err := p.guestMemory(table+16, 16, s, false)
	if err != nil {
		return 0x80
	}
	base := func(d []byte) uint64 { return uint64(d[2]) | uint64(d[3])<<8 | uint64(d[4])<<16 | uint64(d[7])<<24 }
	n := uint64(words) * 2
	source, err := p.memory(base(descriptors), n)
	if err != nil {
		return 0x80
	}
	dest, err := p.memory(base(descriptors[8:]), n)
	if err != nil {
		return 0x80
	}
	copy(dest, source)
	return 0
}
