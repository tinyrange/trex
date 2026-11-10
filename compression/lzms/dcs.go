package lzms

import (
	"encoding/binary"
	"fmt"
)

// IsDCS reports the CBS compressed component-store signature.
func IsDCS(data []byte) bool { return len(data) >= 4 && string(data[:4]) == "DCS\x01" }

// DecompressDCS expands a DCS version 1 component-store container. Its header
// holds a block count and total size, followed by independent raw LZMS blocks.
// A block's stored length includes its decoded-length word but not its own
// length word. Validate all framing and the caller's bound before allocating.
func DecompressDCS(data []byte, maximumSize uint64) ([]byte, error) {
	if len(data) < 12 || !IsDCS(data) {
		return nil, fmt.Errorf("dcs: invalid header")
	}
	count := uint64(binary.LittleEndian.Uint32(data[4:]))
	total := uint64(binary.LittleEndian.Uint32(data[8:]))
	if count == 0 || count > uint64(len(data)-12)/8 || total == 0 || total > maximumSize || total > uint64(maximumOutputSize) {
		return nil, fmt.Errorf("dcs: invalid or excessive count/size")
	}
	offset, expanded := uint64(12), uint64(0)
	for i := uint64(0); i < count; i++ {
		if offset > uint64(len(data))-8 {
			return nil, fmt.Errorf("dcs: truncated block %d", i)
		}
		stored := uint64(binary.LittleEndian.Uint32(data[offset:]))
		size := uint64(binary.LittleEndian.Uint32(data[offset+4:]))
		if stored < 8 || stored > uint64(len(data))-offset-4 || size == 0 || size > total-expanded {
			return nil, fmt.Errorf("dcs: invalid block %d", i)
		}
		expanded += size
		offset += stored + 4
	}
	if offset != uint64(len(data)) || expanded != total {
		return nil, fmt.Errorf("dcs: inconsistent container size")
	}
	out := make([]byte, int(total))
	position := 0
	offset = 12
	for i := uint64(0); i < count; i++ {
		stored := uint64(binary.LittleEndian.Uint32(data[offset:]))
		size := int(binary.LittleEndian.Uint32(data[offset+4:]))
		end := position + size
		if err := decompressInto(data[offset+8:offset+4+stored], out[position:end:end]); err != nil {
			return nil, fmt.Errorf("dcs: block %d: %w", i, err)
		}
		position = end
		offset += stored + 4
	}
	return out, nil
}
