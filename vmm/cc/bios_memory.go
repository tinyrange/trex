package cc

import (
	"encoding/binary"

	"j5.nz/cc/hypervisor/x86state"
)

// extendedMemory implements the E801 size query and the E820 system address
// map. AH=88 alone cannot describe the RAM above 64 MiB. ROM remains
// reserved even though firmware bytes have RAM backing in the backend.
func (p *pc) extendedMemory(r *x86state.Registers, s x86state.SystemRegisters) bool {
	if uint16(r.Rax) == 0xe801 {
		low := uint16((min(len(p.ram), 16<<20) - (1 << 20)) >> 10)
		high := uint16(max(len(p.ram)-(16<<20), 0) >> 16)
		setLow(&r.Rax, low)
		setLow(&r.Rbx, high)
		setLow(&r.Rcx, low)
		setLow(&r.Rdx, high)
		return true
	}
	switch uint32(r.Rax) {
	case 0xe820:
		regions := [...]struct {
			base, size uint64
			kind       uint32
		}{
			{0, 0xa0000, 1},
			// The VGA aperture is device address space, not firmware-owned
			// memory. Claiming it here conflicts with NT 3.51 video resources.
			{0xc0000, 0x40000, 2},
			{0x100000, uint64(len(p.ram)) - 0x100000, 1},
		}
		index := uint32(r.Rbx)
		if uint32(r.Rdx) != 0x534d4150 || uint32(r.Rcx) < 20 || index >= uint32(len(regions)) {
			return false
		}
		size := uint64(20)
		if uint32(r.Rcx) >= 24 {
			size = 24
		}
		buffer, err := p.memory(s.Es.Base+uint64(uint16(r.Rdi)), size)
		if err != nil {
			return false
		}
		region := regions[index]
		binary.LittleEndian.PutUint64(buffer, region.base)
		binary.LittleEndian.PutUint64(buffer[8:], region.size)
		binary.LittleEndian.PutUint32(buffer[16:], region.kind)
		if size == 24 {
			binary.LittleEndian.PutUint32(buffer[20:], 1) // Enabled range.
		}
		r.Rax = 0x534d4150
		r.Rcx = size
		r.Rbx = uint64(index + 1)
		if index+1 == uint32(len(regions)) {
			r.Rbx = 0
		}
		return true
	}
	return false
}
