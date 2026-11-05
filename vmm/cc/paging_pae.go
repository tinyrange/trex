package cc

import (
	"encoding/binary"
	"fmt"
)

// Legacy PAE has four PDPTEs at a 32-byte aligned CR3, then two 512-entry
// levels. Unlike long mode, its linear addresses remain 32 bits. NX and other
// attributes are excluded from the physical address; inspection does not set
// Accessed/Dirty. The returned PDE/PTE spans let BIOS accesses account for those
// bits through the existing guestMemory path. PAE PDPTEs have no Accessed bit.
func (p *pc) physicalPAEPage(address, cr3 uint64) (uint64, []byte, []byte, error) {
	if address > 0xffffffff {
		return 0, nil, nil, fmt.Errorf("PAE linear address exceeds 32 bits: %#x", address)
	}
	const frame = uint64(0x000ffffffffff000)
	root, err := p.memory((cr3&0xffffffe0)+(address>>30)*8, 8)
	if err != nil {
		return 0, nil, nil, err
	}
	pdpte := binary.LittleEndian.Uint64(root)
	if pdpte&1 == 0 {
		return 0, nil, nil, fmt.Errorf("unmapped PAE PDPTE for %#x", address)
	}
	dir, err := p.memory((pdpte&frame)+(address>>21&511)*8, 8)
	if err != nil {
		return 0, nil, nil, err
	}
	pde := binary.LittleEndian.Uint64(dir)
	if pde&1 == 0 {
		return 0, nil, nil, fmt.Errorf("unmapped PAE PDE for %#x", address)
	}
	if pde&128 != 0 {
		// PAE 2 MiB mappings do not depend on CR4.PSE. Bit 12 is PAT.
		return pde&frame&^uint64(0x1fffff) | address&0x1fffff, dir, dir, nil
	}
	table, err := p.memory((pde&frame)+(address>>12&511)*8, 8)
	if err != nil {
		return 0, nil, nil, err
	}
	pte := binary.LittleEndian.Uint64(table)
	if pte&1 == 0 {
		return 0, nil, nil, fmt.Errorf("unmapped PAE PTE for %#x", address)
	}
	return pte&frame | address&4095, dir, table, nil
}
