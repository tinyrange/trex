// Package vmsbackup decodes VMS BACKUP save-set structures.
package vmsbackup

import (
	"encoding/binary"
	"fmt"
)

type Attribute struct {
	Kind uint16
	Data []byte
}

// ParseAttributes reads the version-1 attribute stream within one summary or
// file record. TLVs are byte-packed, even when the preceding value has odd
// length. Duplicate and unknown types are preserved, not interpreted away.
// This is metadata framing only; it does not validate the enclosing save-set
// block checksums or claim that the record is semantically complete.
func ParseAttributes(data []byte, maximumAttributes int) ([]Attribute, error) {
	if maximumAttributes < 1 {
		return nil, fmt.Errorf("vms backup: invalid attribute limit")
	}
	if len(data) < 2 || data[0] != 1 || data[1] != 1 {
		return nil, fmt.Errorf("vms backup: unsupported attribute version")
	}
	result := []Attribute{}
	for p := 2; p < len(data); {
		zero := true
		for _, v := range data[p:] {
			if v != 0 {
				zero = false
				break
			}
		}
		if zero {
			return result, nil
		}
		if len(result) >= maximumAttributes {
			return nil, fmt.Errorf("vms backup: attribute limit")
		}
		if len(data)-p < 4 {
			return nil, fmt.Errorf("vms backup: truncated attribute header")
		}
		size := int(binary.LittleEndian.Uint16(data[p:]))
		kind := binary.LittleEndian.Uint16(data[p+2:])
		p += 4
		if size > len(data)-p {
			return nil, fmt.Errorf("vms backup: truncated attribute value")
		}
		result = append(result, Attribute{Kind: kind, Data: append([]byte(nil), data[p:p+size]...)})
		p += size
	}
	return result, nil
}
