package ckd

import "fmt"

func (p *Pages) recordData(r Record) ([]byte, error) {
	if len(r.Key) != 0 || uint32(len(r.Data)) != p.PageSize+p.suffixBytes {
		return nil, fmt.Errorf("ckd pages: record %d has key/data lengths %d/%d, want 0/%d", r.Number, len(r.Key), len(r.Data), p.PageSize+p.suffixBytes)
	}
	if p.suffixBytes != 0 {
		s := r.Data[p.PageSize:]
		// Preserve only the observed uncompressed suffix profiles. Unknown
		// compression/checksum/striping fields must not be ignored as padding.
		if len(s) != 32 || (s[0] != 0 && s[0] != 0x20) || (s[10] != 0x10 && s[10] != 0x20) || s[29] != 0x5a || s[30] != 0x5a || s[31] != 0xa5 {
			return nil, fmt.Errorf("VSAM: unsupported extended-format suffix")
		}
		for i, b := range s[:29] {
			if i != 0 && i != 10 && b != 0 {
				return nil, fmt.Errorf("VSAM: unsupported extended-format suffix fields")
			}
		}
	}
	return r.Data[:p.PageSize], nil
}
