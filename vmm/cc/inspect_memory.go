package cc

import (
	"fmt"

	"github.com/tinyrange/trex/emulator/cpu"
)

// readVirtualBytes selects a caller-observed page-table root for inspection.
// Zero retains current CR3. In particular, kernel observations must not depend
// on whether a KPTI guest happened to stop in userspace. The register copy is
// local: neither CR3 nor guest memory is changed, and no fallback root is guessed.
func (p *pc) readVirtualBytes(address uint64, size int, pageTable uint64) ([]byte, error) {
	if size < 0 || size > 65536 || uint64(size) > ^uint64(0)-address {
		return nil, fmt.Errorf("cc: virtual inspection requires nonwrapping size 0..65536")
	}
	s, err := p.cpu.SystemRegisters()
	if err != nil {
		return nil, err
	}
	if pageTable != 0 {
		s.Cr3 = pageTable
	}
	b := make([]byte, size)
	if err := (efiMemory{p: p, system: &s}).ReadMemory(address, b, cpu.Read); err != nil {
		return nil, err
	}
	return b, nil
}
