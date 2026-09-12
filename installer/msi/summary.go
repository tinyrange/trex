package msi

import (
	"encoding/binary"
	"fmt"
)

// summaryWordCount reads PID_WORDCOUNT from the OLE property set, without
// interpreting unrelated metadata or materializing any installer payload.
func (d *Database) summaryWordCount() (uint32, error) {
	if d.streams["\x05SummaryInformation"] == nil {
		return 0, nil
	}
	b, err := d.read("\x05SummaryInformation")
	if err != nil {
		return 0, err
	}
	bad := fmt.Errorf("msi: malformed summary property set")
	if len(b) < 48 || binary.LittleEndian.Uint16(b) != 0xfffe {
		return 0, bad
	}
	n := uint64(binary.LittleEndian.Uint32(b[24:]))
	if n == 0 || n > 2 || 28+20*n > uint64(len(b)) {
		return 0, bad
	}
	// The SummaryInformation stream contains the SummaryInformation section.
	start := uint64(binary.LittleEndian.Uint32(b[44:]))
	if start+8 > uint64(len(b)) {
		return 0, bad
	}
	size := uint64(binary.LittleEndian.Uint32(b[start:]))
	count := uint64(binary.LittleEndian.Uint32(b[start+4:]))
	if size < 8 || start+size > uint64(len(b)) || 8+8*count > size {
		return 0, bad
	}
	for i := uint64(0); i < count; i++ {
		entry := start + 8 + 8*i
		if binary.LittleEndian.Uint32(b[entry:]) != 15 {
			continue
		}
		offset := uint64(binary.LittleEndian.Uint32(b[entry+4:]))
		if offset < 8+8*count || offset+8 > size || binary.LittleEndian.Uint32(b[start+offset:]) != 3 {
			return 0, bad
		}
		return binary.LittleEndian.Uint32(b[start+offset+4:]), nil
	}
	return 0, nil
}
