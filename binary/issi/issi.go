// Package issi implements the 8x520 to 9x512 (ISSI) sector framing. The original
// eight sector headers and displaced data words are carried in a ninth sector.
// Control words are stamps, not checksums. This layer preserves them for the
// caller's integrity policy rather than inventing authentication.
package issi

import (
	"encoding/binary"
	"fmt"
)

const PageBytes = 4096
const SectorBytes = 512
const HeaderBytes = 64

// PointerTags returns one bit per 16-byte quadword in ascending address order,
// most significant bit first. An unmarked sector stores address bits in the
// same header positions and contributes no pointer tags.
func PointerTags(headers *[HeaderBytes]byte) (tags [32]byte) {
	for sector := 0; sector < 8; sector++ {
		h := headers[sector*8 : (sector+1)*8]
		if h[7]&8 != 0 {
			copy(tags[sector*4:], h[3:7])
		}
	}
	return tags
}

func valid(sidecar, headers, page []byte) error {
	if len(sidecar) != SectorBytes || len(headers) != HeaderBytes || len(page) != PageBytes {
		return fmt.Errorf("issi: expected 512/64/4096 bytes")
	}
	return nil
}

// Save copies original headers and each sector's trailing data word into the
// sidecar before Stamp overwrites those words. Other sidecar bytes survive.
func Save(sidecar, headers, page []byte) error {
	if err := valid(sidecar, headers, page); err != nil {
		return err
	}
	copy(sidecar[8:72], headers)
	for i := 0; i < 8; i++ {
		copy(sidecar[72+i*8:80+i*8], page[i*512+504:(i+1)*512])
	}
	return nil
}

// Stamp writes the same nonzero caller stamp to the nine sector control words
// and the extra control word at the beginning of the sidecar.
func Stamp(sidecar, page []byte, stamp uint64) error {
	if len(sidecar) != SectorBytes || len(page) != PageBytes || stamp == 0 {
		return fmt.Errorf("issi: invalid stamp or buffers")
	}
	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint64(page[i*512+504:], stamp)
	}
	binary.BigEndian.PutUint64(sidecar, stamp)
	binary.BigEndian.PutUint64(sidecar[504:], stamp)
	return nil
}

// Restore returns original headers and displaced words. preserveControls
// saves the eight observed data-sector controls at sidecar+136 before restoring
// data, including mismatches: the consumer decides whether they are valid.
func Restore(sidecar, headers, page []byte, preserveControls bool) error {
	if err := valid(sidecar, headers, page); err != nil {
		return err
	}
	for i := 0; i < 8; i++ {
		if preserveControls {
			copy(sidecar[136+i*8:144+i*8], page[i*512+504:(i+1)*512])
		}
		copy(page[i*512+504:(i+1)*512], sidecar[72+i*8:80+i*8])
	}
	copy(headers, sidecar[8:72])
	return nil
}
