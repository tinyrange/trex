package vmm

import (
	"encoding/binary"
	"fmt"
)

// ARM64Translation describes an EL1 stage-one translation at a stopped CPU.
// ReadPhysical supplies exactly the requested bytes from guest physical memory.
// The walker supports 4/16/64 KiB granules and up to 48-bit addresses, without
// mutating access flags or interpreting an invalid descriptor as mapped memory.
type ARM64Translation struct {
	TCR, TTBR0, TTBR1 uint64
	ReadPhysical      func(address uint64, size int) ([]byte, error)
}

func (t ARM64Translation) Translate(address uint64) (physical, span uint64, err error) {
	if t.ReadPhysical == nil {
		return 0, 0, fmt.Errorf("ARM64: missing physical reader")
	}
	upper := address>>63 != 0
	if t.TCR&(1<<37|1<<38) != 0 {
		upper = address&(1<<55) != 0
	}
	ts, tg, ttbr := t.TCR&63, (t.TCR>>14)&3, t.TTBR0
	var pageBits uint64
	if upper {
		ts, tg, ttbr = (t.TCR>>16)&63, (t.TCR>>30)&3, t.TTBR1
		switch tg {
		case 2:
			pageBits = 12
		case 1:
			pageBits = 14
		case 3:
			pageBits = 16
		}
	} else {
		switch tg {
		case 0:
			pageBits = 12
		case 2:
			pageBits = 14
		case 1:
			pageBits = 16
		}
	}
	if ts < 16 || ts > 39 || pageBits == 0 || t.TCR&(1<<59) != 0 || (t.TCR>>32)&7 > 5 {
		return 0, 0, fmt.Errorf("ARM64: unsupported translation configuration %#x", t.TCR)
	}
	epd := uint64(7)
	if upper {
		epd = 23
	}
	if t.TCR&(1<<epd) != 0 {
		return 0, 0, fmt.Errorf("ARM64: translation table disabled")
	}
	bits := 64 - ts
	mask := uint64(1)<<bits - 1
	canonical := address
	tbi := uint64(37)
	if upper {
		tbi++
	}
	if t.TCR&(1<<tbi) != 0 {
		if upper {
			canonical |= 0xff << 56
		} else {
			canonical &= 0x00ffffffffffffff
		}
	}
	if !upper && canonical & ^mask != 0 || upper && canonical|mask != ^uint64(0) {
		return 0, 0, fmt.Errorf("ARM64: noncanonical virtual address %#x", address)
	}
	address &= mask
	indexBits := pageBits - 3
	levels := (bits - pageBits + indexBits - 1) / indexBits
	if levels == 0 || levels > 4 || pageBits == 16 && levels > 3 {
		return 0, 0, fmt.Errorf("ARM64: invalid translation levels")
	}
	const physicalMask = uint64(1)<<48 - 1
	rootBits := bits - pageBits - (levels-1)*indexBits
	// A partial initial table need only align to its own byte size. Later
	// table descriptors always refer to a full translation granule.
	table := ttbr & physicalMask & ^(uint64(1)<<(rootBits+3) - 1)
	for level := uint64(4) - levels; level < 4; level++ {
		shift := pageBits + (3-level)*indexBits
		index := (address >> shift) & (uint64(1)<<indexBits - 1)
		data, err := t.ReadPhysical(table+index*8, 8)
		if err != nil {
			return 0, 0, err
		}
		if len(data) != 8 {
			return 0, 0, fmt.Errorf("ARM64: short page table read")
		}
		desc := binary.LittleEndian.Uint64(data)
		if desc&1 == 0 {
			return 0, 0, fmt.Errorf("ARM64: unmapped virtual address at level %d", level)
		}
		if level < 3 && desc&2 != 0 {
			table = desc & physicalMask & ^(uint64(1)<<pageBits - 1)
			continue
		}
		if level == 0 || level == 3 && desc&2 == 0 {
			return 0, 0, fmt.Errorf("ARM64: invalid page descriptor at level %d", level)
		}
		offsetMask := uint64(1)<<shift - 1
		return desc&physicalMask & ^offsetMask | address&offsetMask, (offsetMask + 1) - (address & offsetMask), nil
	}
	return 0, 0, fmt.Errorf("ARM64: translation did not terminate")
}

func (t ARM64Translation) Read(address uint64, size int) ([]byte, error) {
	if size < 0 || size > 65536 || uint64(size) > ^uint64(0)-address {
		return nil, fmt.Errorf("ARM64: read size must be 0..65536 without overflow")
	}
	result := make([]byte, 0, size)
	for len(result) < size {
		physical, span, err := t.Translate(address + uint64(len(result)))
		if err != nil {
			return nil, err
		}
		n := min(size-len(result), int(span))
		data, err := t.ReadPhysical(physical, n)
		if err != nil {
			return nil, err
		}
		if len(data) != n {
			return nil, fmt.Errorf("ARM64: short physical read")
		}
		result = append(result, data...)
	}
	return result, nil
}
