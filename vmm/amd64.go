package vmm

import (
	"fmt"

	"github.com/tinyrange/trex/memory"
	"github.com/tinyrange/trex/storage"
	"j5.nz/cc/hypervisor/x86state"
)

// AMD64Boot is an explicit initial x86-64 long-mode handoff. RAM represents
// physical addresses starting at zero. The caller builds the page tables and
// descriptor tables and chooses whether the first instruction runs at CPL3.
type AMD64Boot struct {
	RAM            storage.Reader
	Registers      x86state.Registers
	PageTable      uint64
	GDT, IDT       x86state.DescriptorTable
	FSBase, GSBase uint64
	User           bool
}

func (b *AMD64Boot) Validate(ramSize int64) error {
	if b == nil || b.RAM == nil {
		return fmt.Errorf("AMD64 handoff requires a physical memory file")
	}
	size := b.RAM.Size()
	if size <= 0 || size > ramSize || ramSize > 3<<30 || ramSize%4096 != 0 {
		return fmt.Errorf("AMD64 handoff requires page-aligned RAM up to 3 GiB")
	}
	if b.PageTable == 0 || b.PageTable%4096 != 0 || b.PageTable > uint64(size) || 4096 > uint64(size)-b.PageTable || b.GDT.Limit < 55 || uint64(b.GDT.Limit) > ^uint64(0)-b.GDT.Base {
		return fmt.Errorf("AMD64 handoff requires a complete page-table root and GDT")
	}
	entry, err := memory.TranslateAMD64(b.RAM, b.PageTable, b.Registers.Rip)
	if err != nil || !entry.Execute || (b.User && !entry.User) || entry.Physical >= uint64(size) {
		return fmt.Errorf("AMD64 handoff entry is unavailable at the requested privilege")
	}
	for address := b.GDT.Base; ; {
		entry, err := memory.TranslateAMD64(b.RAM, b.PageTable, address)
		remaining := b.GDT.Base + uint64(b.GDT.Limit) - address + 1
		count := min(remaining, 4096-address%4096)
		if err != nil || entry.Physical >= uint64(size) || count > uint64(size)-entry.Physical {
			return fmt.Errorf("AMD64 handoff GDT is not mapped in the supplied RAM")
		}
		if count == remaining {
			break
		}
		address += count
	}
	return nil
}
