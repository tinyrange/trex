package cc

import (
	"encoding/binary"
	"fmt"

	"github.com/tinyrange/trex/vmm/ramfb"
	"j5.nz/cc/hypervisor"
)

// The optional real-mode aperture replaces the VGA/option-ROM window while
// enabled. Its 4 KiB TRF1 header and 256 KiB pixel plane fit below the system
// BIOS at F0000. Ordinary guests retain the original VGA memory routing.
const (
	legacyDisplayPort    = 0x514
	legacyDisplayAddress = 0xa0000
	legacyDisplaySize    = ramfb.Pixels + (256 << 10)
)

func (p *pc) displayMemory() []byte {
	if p.legacyDisplay {
		return p.ram[legacyDisplayAddress : legacyDisplayAddress+legacyDisplaySize]
	}
	return p.framebuffer
}

func (p *pc) legacyDisplayIO(ex hypervisor.X86Exit) error {
	if !ex.Write || ex.Size != 4 || ex.Count != 1 || len(ex.Data) != 4 {
		return fmt.Errorf("legacy display control requires one DWORD write")
	}
	value := binary.LittleEndian.Uint32(ex.Data)
	if value == 0 {
		p.legacyDisplay = false
		return nil
	}
	if value != ramfb.Magic || len(p.ram) < legacyDisplayAddress+legacyDisplaySize {
		return fmt.Errorf("invalid legacy display activation")
	}
	if !p.legacyDisplay {
		clear(p.ram[legacyDisplayAddress : legacyDisplayAddress+legacyDisplaySize])
		p.legacyDisplay = true
		binary.LittleEndian.PutUint32(p.displayMemory(), ramfb.Magic)
	}
	return nil
}
