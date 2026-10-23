package cc

import (
	"encoding/binary"
	"fmt"
	"j5.nz/cc/hypervisor/x86state"
)

// guestMemory resolves BIOS segment:offset addresses through the active guest
// page tables. Firmware reads must set Accessed, and writes must also set Dirty,
// just as the equivalent guest ROM instructions would. In particular a v8086
// monitor may use Dirty to distinguish disk-loaded code from discardable pages.
// Validate the entire (possibly noncontiguous) span before exposing a buffer.
// The caller commits after changing a writable buffer; read-only buffers must
// not be modified. Inspection uses physical instead and has no paging effects.
func (p *pc) guestMemory(address, size uint64, s x86state.SystemRegisters, write bool) ([]byte, func(), error) {
	if size > 1<<20 || address+size < address {
		return nil, nil, fmt.Errorf("invalid BIOS memory span")
	}
	if s.Cr0&(1<<31) == 0 && !p.a20Disabled {
		b, err := p.memory(address, size)
		return b, func() {}, err
	}
	var chunks, accessed, dirty [][]byte
	for at := uint64(0); at < size; {
		physical, dir, leaf, err := p.physicalPage(address+at, s)
		if err != nil {
			return nil, nil, err
		}
		n := min(size-at, 4096-((address+at)&4095))
		b, err := p.memory(p.cpuAddress(physical), n)
		if err != nil {
			return nil, nil, err
		}
		chunks = append(chunks, b)
		accessed = append(accessed, dir, leaf)
		dirty = append(dirty, leaf)
		at += n
	}
	mark := func(entries [][]byte, bits uint32) {
		for _, entry := range entries {
			if len(entry) == 0 {
				continue
			}
			binary.LittleEndian.PutUint32(entry, binary.LittleEndian.Uint32(entry)|bits)
		}
	}
	mark(accessed, 1<<5)
	var data []byte
	if len(chunks) == 1 {
		data = chunks[0]
	} else {
		data = make([]byte, size)
		at := 0
		for _, b := range chunks {
			at += copy(data[at:], b)
		}
	}
	return data, func() {
		if !write {
			return
		}
		if len(chunks) != 1 {
			at := 0
			for _, b := range chunks {
				at += copy(b, data[at:])
			}
		}
		mark(dirty, 1<<6)
	}, nil
}
