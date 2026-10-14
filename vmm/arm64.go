package vmm

import (
	"fmt"

	"github.com/tinyrange/trex/storage"
)

// ARM64Boot enters caller-supplied AArch64 firmware with the MMU disabled.
// Addresses are guest physical addresses; no host file or firmware policy is implied.
type ARM64Boot struct {
	Image                      storage.Reader
	Loads                      []ARM64Load
	Address, Entry, MemoryBase uint64
	// MemorySize is nonzero when an encoded handoff requires this RAM size.
	MemorySize uint64
	X          [31]uint64
	System     map[uint16]uint64
}

// ARM64Load places a separate input directly in guest RAM without concatenating
// large boot payloads into the executable image.
type ARM64Load struct {
	Image   storage.Reader
	Address uint64
}

func (b *ARM64Boot) Validate(memory int64) error {
	if b == nil {
		return nil
	}
	if memory <= 0 || uint64(memory) > ^uint64(0)-b.MemoryBase {
		return fmt.Errorf("arm64_boot: invalid RAM range")
	}
	if b.MemorySize != 0 && b.MemorySize != uint64(memory) {
		return fmt.Errorf("arm64_boot: RAM size differs from encoded handoff")
	}
	if b.Image == nil || b.Image.Size() < 4 || b.Image.Size() > 256<<20 {
		return fmt.Errorf("arm64_boot: image size outside bounds")
	}
	end := b.MemoryBase + uint64(memory)
	if b.Address < b.MemoryBase || b.Address > end || uint64(b.Image.Size()) > end-b.Address || b.Address&3 != 0 || b.Entry&3 != 0 || b.Entry < b.Address || b.Entry-b.Address >= uint64(b.Image.Size()) {
		return fmt.Errorf("arm64_boot: image and entry must fit RAM")
	}
	if len(b.Loads) > 32 {
		return fmt.Errorf("arm64_boot: too many payloads")
	}
	ranges := []ARM64Load{{Image: b.Image, Address: b.Address}}
	for _, l := range b.Loads {
		if l.Image == nil || l.Image.Size() <= 0 || l.Address < b.MemoryBase || l.Address > end || uint64(l.Image.Size()) > end-l.Address {
			return fmt.Errorf("arm64_boot: invalid payload range")
		}
		for _, r := range ranges {
			if l.Address < r.Address+uint64(r.Image.Size()) && r.Address < l.Address+uint64(l.Image.Size()) {
				return fmt.Errorf("arm64_boot: overlapping payloads")
			}
		}
		ranges = append(ranges, l)
	}
	return nil
}
