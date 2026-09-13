package dmr

import "fmt"

const (
	AlternatePathTag       uint32 = 0x50544c41 // ALTP
	AlternateFamilyPathTag uint32 = 0x46544c41 // ALTF
	maxAlternatePathBytes         = 131072
)

// EncodeAlternatePath encodes an ALTP or ALTF section. The payload is one
// UTF-16 string, which may contain the native semicolon-separated search path.
// This codec does not split, normalize, deduplicate, or choose guest paths.
// firstPackageFamily selects ALTF, whose reserved field is written as zero.
func EncodeAlternatePath(value string, firstPackageFamily bool) ([]byte, error) {
	payload, err := terminatedString(value, maxAlternatePathBytes)
	if err != nil {
		return nil, err
	}
	header, tag := 8, AlternatePathTag
	if firstPackageFamily {
		header, tag = 16, AlternateFamilyPathTag
	}
	size := header + len(payload)
	out := make([]byte, align4(size))
	le.PutUint32(out, tag)
	le.PutUint32(out[4:], uint32(size))
	if firstPackageFamily {
		le.PutUint32(out[12:], uint32(len(payload)))
	}
	copy(out[header:], payload)
	return out, nil
}

// ParseAlternatePath validates either native alternate-path record, including
// exact payload size and zero alignment padding. It returns the original path
// string and whether the record is for the first package family.
func ParseAlternatePath(data []byte) (value string, firstPackageFamily bool, err error) {
	if len(data) < 8 {
		return "", false, fmt.Errorf("dmr: short alternate path")
	}
	header := 8
	switch le.Uint32(data) {
	case AlternatePathTag:
	case AlternateFamilyPathTag:
		header, firstPackageFamily = 16, true
	default:
		return "", false, fmt.Errorf("dmr: invalid alternate path tag")
	}
	size := uint64(le.Uint32(data[4:]))
	if size < uint64(header) || size > uint64(header+maxAlternatePathBytes) ||
		size%2 != 0 || uint64(len(data)) != (size+3)&^uint64(3) {
		return "", false, fmt.Errorf("dmr: invalid alternate path extent")
	}
	if !zeroBytes(data[int(size):]) {
		return "", false, fmt.Errorf("dmr: nonzero alternate path padding")
	}
	if firstPackageFamily && (le.Uint32(data[8:]) != 0 || uint64(le.Uint32(data[12:])) != size-16) {
		return "", false, fmt.Errorf("dmr: invalid ALTF reserved field/payload length")
	}
	value, err = parseIdentityString(data[header:int(size)])
	return value, firstPackageFamily, err
}
