package ckd

import (
	"encoding/binary"
	"fmt"
)

// ControlInterval is a decoded, non-spanned VSAM data control interval.
// Records borrow the input. This does not interpret index CIs, RRDS slots,
// catalog relationships, or high-used RBA; callers must supply data CIs only.
type ControlInterval struct {
	FreeOffset, FreeLength uint16
	// EOF is the VSAM software end marker, not evidence that arbitrary zero
	// allocation belongs to a VSAM data component.
	EOF     bool
	Records [][]byte
	Slots   []VSAMSlot
	Segment *VSAMSegment
}

// ParseControlInterval validates the CIDF and backwards RDF stream, including
// repeated equal-length records. Unsupported flags fail closed, rather than
// presenting record segments or vacant slots as complete logical records.
func ParseControlInterval(b []byte) (*ControlInterval, error) {
	if len(b) < 512 || len(b) > 32768 || len(b)%512 != 0 {
		return nil, fmt.Errorf("vsam CI: invalid size %d", len(b))
	}
	end := len(b) - 4
	c := &ControlInterval{FreeOffset: binary.BigEndian.Uint16(b[end:]), FreeLength: binary.BigEndian.Uint16(b[end+2:])}
	// IBM DFSMS Using Data Sets defines an all-zero CIDF as software EOF.
	if c.FreeOffset == 0 && c.FreeLength == 0 {
		c.EOF = true
		return c, nil
	}
	stop := int(c.FreeOffset) + int(c.FreeLength)
	if stop > end || (end-stop)%3 != 0 {
		return nil, fmt.Errorf("vsam CI: invalid free-space boundary")
	}
	pos, off := end, 0
	for pos > stop {
		pos -= 3
		flag, size := b[pos], int(binary.BigEndian.Uint16(b[pos+1:]))
		count := 1
		switch flag {
		case 0:
		case 0x40:
			if pos-stop < 3 {
				return nil, fmt.Errorf("vsam CI: missing repeat count")
			}
			pos -= 3
			if b[pos] != 8 {
				return nil, fmt.Errorf("vsam CI: invalid repeat-count flag")
			}
			count = int(binary.BigEndian.Uint16(b[pos+1:]))
			if count < 2 {
				return nil, fmt.Errorf("vsam CI: invalid repeat count")
			}
		default:
			return nil, fmt.Errorf("vsam CI: unsupported RDF flags %#02x", flag)
		}
		if size == 0 || count > (int(c.FreeOffset)-off)/size {
			return nil, fmt.Errorf("vsam CI: record exceeds data area")
		}
		for i := 0; i < count; i++ {
			c.Records = append(c.Records, b[off:off+size])
			off += size
		}
	}
	if off != int(c.FreeOffset) {
		return nil, fmt.Errorf("vsam CI: record lengths do not cover data area")
	}
	return c, nil
}
