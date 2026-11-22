// Package rpa reads the observed absolute-address RPA block-list format.
package rpa

import (
	"encoding/binary"
	"fmt"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
)

type Extent struct{ Address, Real, Size uint64 }
type BlockList struct {
	Entries  []Extent
	Capacity uint64
}

func absolute(source storage.Reader, address, size uint64) (uint64, error) {
	real := address & ((1 << 60) - 1)
	if address>>60 != 8 || real > uint64(source.Size()) || size > uint64(source.Size())-real {
		return 0, fmt.Errorf("RPA block list: absolute range %x+%x", address, size)
	}
	return real, nil
}

// ReadBlockList validates the complete chain before returning any DMA targets.
// The observed header is 0101/u16 context0/u32 used bytes/u64 next.
// The context's meaning is not established; other values remain unsupported.
// Its used bytes include the16-byte header and up to255 address/length pairs.
// source is a portable view of real-addressed memory; no memory is modified.
func ReadBlockList(source storage.Reader, address uint64, maximumCapacity uint64) (*BlockList, error) {
	if source == nil || source.Size() < 0 || maximumCapacity == 0 || maximumCapacity > 64<<20 {
		return nil, fmt.Errorf("RPA block list: invalid source or capacity budget")
	}
	result := &BlockList{}
	seen := map[uint64]bool{}
	var headers []Extent
	for address != 0 {
		if len(seen) >= 64 || seen[address] {
			return nil, fmt.Errorf("RPA block list: cyclic or excessive chain")
		}
		seen[address] = true
		real, err := absolute(source, address, 16)
		if err != nil {
			return nil, err
		}
		var header [16]byte
		if _, err := starfile.ReadFullAt(source, header[:], int64(real)); err != nil {
			return nil, err
		}
		size := uint64(binary.BigEndian.Uint32(header[4:]))
		if binary.BigEndian.Uint16(header[:]) != 0x0101 || binary.BigEndian.Uint16(header[2:]) != 0 || size < 16 || size > 4096 || size%16 != 0 {
			return nil, fmt.Errorf("RPA block list: unsupported header")
		}
		if _, err := absolute(source, address, size); err != nil {
			return nil, err
		}
		headers = append(headers, Extent{address, real, size})
		for offset := uint64(16); offset < size; offset += 16 {
			if len(result.Entries) >= 4096 {
				return nil, fmt.Errorf("RPA block list: entry budget")
			}
			var entry [16]byte
			if _, err := starfile.ReadFullAt(source, entry[:], int64(real+offset)); err != nil {
				return nil, err
			}
			target, length := binary.BigEndian.Uint64(entry[:]), binary.BigEndian.Uint64(entry[8:])
			if length == 0 || length > maximumCapacity-result.Capacity {
				return nil, fmt.Errorf("RPA block list: capacity budget")
			}
			output, err := absolute(source, target, length)
			if err != nil {
				return nil, err
			}
			result.Entries = append(result.Entries, Extent{target, output, length})
			result.Capacity += length
		}
		address = binary.BigEndian.Uint64(header[8:])
	}
	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("RPA block list: empty chain")
	}
	for _, entry := range result.Entries {
		for _, header := range headers {
			if entry.Real < header.Real+header.Size && header.Real < entry.Real+entry.Size {
				return nil, fmt.Errorf("RPA block list: target overlaps list metadata")
			}
		}
	}
	return result, nil
}
