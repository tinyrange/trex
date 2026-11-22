package power

import (
	"encoding/binary"
	"fmt"

	"github.com/tinyrange/trex/binary/issi"
)

// EncodeISSI applies the ISSI framing (binary/issi) in guest memory. Flag
// bits: 1 saves headers and tails, 2 includes hidden pointer tags in those
// headers, 4 stamps sectors. Addresses are partition real addresses.
func (c *CPU) EncodeISSI(sidecar, headers, page, stamp uint64, flags uint32) error {
	if flags&^7 != 0 || flags&4 != 0 && stamp == 0 {
		return fmt.Errorf("power: invalid ISSI encoder flags/stamp")
	}
	if err := c.issiRanges(sidecar, headers, page); err != nil {
		return err
	}
	m := c.m
	if flags&1 != 0 {
		if flags&2 != 0 {
			if err := c.CapturePageTags(headers, page); err != nil {
				return err
			}
		}
		_ = issi.Save(m.Mem[sidecar:sidecar+512], m.Mem[headers:headers+64], m.Mem[page:page+4096])
		m.stored(c, sidecar+8, 128)
	}
	if flags&4 != 0 {
		_ = issi.Stamp(m.Mem[sidecar:sidecar+512], m.Mem[page:page+4096], stamp)
		for i := uint64(0); i < 8; i++ {
			m.stored(c, page+i*512+504, 8)
		}
		m.stored(c, sidecar, 8)
		m.stored(c, sidecar+504, 8)
	}
	return nil
}

// CapturePageTags updates eight native sector headers with actual hidden AS
// pointer tags. A zero bitmap leaves its
// existing header unchanged. Data and source tags are read without mutation.
func (c *CPU) CapturePageTags(headers, page uint64) error {
	m := c.m
	end := uint64(len(m.Mem))
	if headers&7 != 0 || page&4095 != 0 || headers > end || 64 > end-headers || page > end || 4096 > end-page || headers < page+4096 && page < headers+64 {
		return fmt.Errorf("power: invalid page-tag buffers")
	}
	for sector := uint64(0); sector < 8; sector++ {
		var tags uint32
		for q := uint64(0); q < 32; q++ {
			if m.Tag(page + sector*512 + q*16) {
				tags |= uint32(1) << (31 - q)
			}
		}
		if tags != 0 {
			at := headers + sector*8
			binary.BigEndian.PutUint32(m.Mem[at+3:], tags)
			m.Mem[at+7] |= 8
			m.stored(c, at+3, 5)
		}
	}
	return nil
}

func (c *CPU) issiRanges(sidecar, headers, page uint64) error {
	end := uint64(len(c.m.Mem))
	for _, r := range [][2]uint64{{sidecar, 512}, {headers, 64}, {page, 4096}} {
		if r[0]&7 != 0 || r[0] > end || r[1] > end-r[0] {
			return fmt.Errorf("power: invalid ISSI buffer %x/%x", r[0], r[1])
		}
	}
	// Native callers use distinct buffers. Reject aliases before mutation.
	ranges := [][2]uint64{{sidecar, sidecar + 512}, {headers, headers + 64}, {page, page + 4096}}
	for i := 0; i < len(ranges); i++ {
		for j := i + 1; j < len(ranges); j++ {
			if ranges[i][0] < ranges[j][1] && ranges[j][0] < ranges[i][1] {
				return fmt.Errorf("power: overlapping ISSI buffers")
			}
		}
	}
	if page&4095 != 0 {
		return fmt.Errorf("power: unaligned ISSI data page")
	}
	return nil
}

// DecodeISSI restores sector tails and headers. Flag bit 2 retains received
// controls and bit 1 restores marked pointer tags. It does not check control
// agreement; those exact words are returned to the caller.
func (c *CPU) DecodeISSI(sidecar, headers, page uint64, flags uint32) error {
	if flags&^3 != 0 {
		return fmt.Errorf("power: invalid ISSI decoder flags")
	}
	if err := c.issiRanges(sidecar, headers, page); err != nil {
		return err
	}
	m := c.m
	var tags [32]byte
	if flags&1 != 0 {
		tags = issi.PointerTags((*[issi.HeaderBytes]byte)(m.Mem[sidecar+8 : sidecar+72]))
		if m.tags == nil && tags != [32]byte{} {
			return fmt.Errorf("power: ISSI pointer tags require AS extension")
		}
	}
	_ = issi.Restore(m.Mem[sidecar:sidecar+512], m.Mem[headers:headers+64], m.Mem[page:page+4096], flags&2 != 0)
	for i := uint64(0); i < 8; i++ {
		m.stored(c, page+i*512+504, 8)
	}
	m.stored(c, headers, 64)
	if flags&2 != 0 {
		m.stored(c, sidecar+136, 64)
	}
	if flags&1 != 0 {
		for i := uint64(0); i < 8; i++ {
			c.restoreSectorTags(page+i*512, binary.BigEndian.Uint32(tags[i*4:]))
		}
	}
	return nil
}
