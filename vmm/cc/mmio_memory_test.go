package cc

import (
	"testing"

	"j5.nz/cc/hypervisor"
)

type memoryProbeCPU struct {
	hypervisor.X86
	value uint64
	size  uint32
	reads int
}

func (c *memoryProbeCPU) CompleteMMIORead(value uint64, size uint32) {
	c.value, c.size = value, size
	c.reads++
}

func TestUnassignedLowMemoryProbeHasNoBacking(t *testing.T) {
	c := &memoryProbeCPU{}
	p := &pc{cpu: c, ram: make([]byte, 16<<20), vga: newVGA(make([]byte, 32768))}
	ex := hypervisor.X86Exit{Address: 16 << 20, Size: 4, Write: true}
	if err := p.handleMMIO(ex); err != nil {
		t.Fatal(err)
	}
	ex.Write = false
	if err := p.handleMMIO(ex); err != nil {
		t.Fatal(err)
	}
	if c.reads != 1 || c.value != 0 || c.size != 4 {
		t.Fatal("absent RAM acquired backing", c)
	}
	// The last complete access in the gap is valid, but crossing into PCI
	// space, probing a real RAM address or wrapping the bus stays an error.
	ex.Address = uint64(pciMemoryBase) - 4
	if err := p.handleMMIO(ex); err != nil {
		t.Fatal(err)
	}
	for _, address := range []uint64{(16 << 20) - 4, uint64(pciMemoryBase) - 3, uint64(pciMemoryBase), ^uint64(0) - 1} {
		ex.Address = address
		if err := p.handleMMIO(ex); err == nil {
			t.Fatalf("unassigned bus hid unsupported access at %x", address)
		}
	}
	// Real VGA memory still routes to the planar device, not the bus gap.
	ex = hypervisor.X86Exit{Address: 0xa0000, Size: 1}
	if err := p.handleMMIO(ex); err != nil {
		t.Fatal(err)
	}
}
