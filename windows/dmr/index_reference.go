package dmr

import "fmt"

// EncodeIndexResourceReference encodes an MRM resource index. The caller must
// obtain the index from the applicable PRI resource map; it is not a name hash.
func EncodeIndexResourceReference(index uint32) ([]byte, error) {
	if index > 0x7fffffff {
		return nil, fmt.Errorf("dmr: resource index exceeds signed 32-bit range")
	}
	out := make([]byte, 12)
	le.PutUint16(out, 0x400)
	le.PutUint16(out[2:], 12)
	le.PutUint16(out[6:], 4)
	le.PutUint32(out[8:], index)
	return out, nil
}

// ParseIndexResourceReference accepts the canonical internal index form, not
// literal strings or other MRM reference variants.
func ParseIndexResourceReference(data []byte) (uint32, error) {
	if len(data) != 12 || le.Uint16(data) != 0x400 ||
		le.Uint16(data[2:]) != 12 || le.Uint16(data[4:]) != 0 ||
		le.Uint16(data[6:]) != 4 || le.Uint32(data[8:]) > 0x7fffffff {
		return 0, fmt.Errorf("dmr: invalid index resource reference")
	}
	return le.Uint32(data[8:]), nil
}
