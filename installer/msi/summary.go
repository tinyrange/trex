package msi

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// summaryProperty returns the bounded typed value for one property identifier.
// It never reads outside the property's section or into its next sibling.
func summaryProperty(b []byte, id uint32) ([]byte, error) {
	bad := fmt.Errorf("msi: malformed summary property set")
	if len(b) < 48 || binary.LittleEndian.Uint16(b) != 0xfffe {
		return nil, bad
	}
	n := uint64(binary.LittleEndian.Uint32(b[24:]))
	if n == 0 || n > 2 || 28+20*n > uint64(len(b)) {
		return nil, bad
	}
	start := uint64(binary.LittleEndian.Uint32(b[44:]))
	if start < 28+20*n || start+8 > uint64(len(b)) {
		return nil, bad
	}
	size := uint64(binary.LittleEndian.Uint32(b[start:]))
	count := uint64(binary.LittleEndian.Uint32(b[start+4:]))
	if size < 8 || start+size > uint64(len(b)) || 8+8*count > size {
		return nil, bad
	}
	var selected uint64
	offsets := make([]uint64, 0, count)
	seen := map[uint32]bool{}
	seenOffsets := map[uint64]bool{}
	for i := uint64(0); i < count; i++ {
		entry := start + 8 + 8*i
		key := binary.LittleEndian.Uint32(b[entry:])
		off := uint64(binary.LittleEndian.Uint32(b[entry+4:]))
		if seen[key] || off < 8+8*count || off+4 > size {
			return nil, bad
		}
		seen[key] = true
		if seenOffsets[off] {
			return nil, bad
		}
		seenOffsets[off] = true
		offsets = append(offsets, off)
		if key == id {
			selected = off
		}
	}
	if selected == 0 {
		return nil, nil
	}
	end := size
	for _, off := range offsets {
		if off > selected && off < end {
			end = off
		}
	}
	return b[start+selected : start+end], nil
}

func (d *Database) summaryValue(id uint32) ([]byte, error) {
	if d.streams["\x05SummaryInformation"] == nil {
		return nil, nil
	}
	b, err := d.read("\x05SummaryInformation")
	if err != nil {
		return nil, err
	}
	return summaryProperty(b, id)
}

func (d *Database) summaryWordCount() (uint32, error) {
	v, err := d.summaryValue(15)
	if err != nil || v == nil {
		return 0, err
	}
	if len(v) < 8 || binary.LittleEndian.Uint32(v) != 3 {
		return 0, fmt.Errorf("msi: invalid summary word count")
	}
	return binary.LittleEndian.Uint32(v[4:]), nil
}

// PackageCode is PID_REVNUMBER, distinct from the Property table ProductCode.
// MSI package codes are ASCII GUIDs even when the summary uses another codepage.
func (d *Database) PackageCode() (string, error) {
	v, err := d.summaryValue(9)
	if err != nil || v == nil {
		return "", err
	}
	return summaryPackageCode(v)
}

func summaryPackageCode(v []byte) (string, error) {
	bad := fmt.Errorf("msi: invalid package code in summary information")
	if len(v) < 8 || binary.LittleEndian.Uint32(v) != 30 {
		return "", bad
	}
	n := uint64(binary.LittleEndian.Uint32(v[4:]))
	if n != 39 || 8+n > uint64(len(v)) || v[8+n-1] != 0 {
		return "", bad
	}
	s := string(v[8 : 8+n-1])
	for i, c := range s {
		switch i {
		case 0:
			if c != '{' {
				return "", bad
			}
		case 37:
			if c != '}' {
				return "", bad
			}
		case 9, 14, 19, 24:
			if c != '-' {
				return "", bad
			}
		default:
			if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
				return "", bad
			}
		}
	}
	return strings.ToUpper(s), nil
}
