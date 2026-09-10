package dmr

import "fmt"

const MutablePathsTag uint32 = 0x504d4b50 // PKMP

// EncodeMutablePaths serializes the ordered mutable-path entries associated
// with graph nodes. Empty paths occupy a four-byte entry and must not be dropped:
// the consumer walks this list in parallel with the dependency graph.
func EncodeMutablePaths(paths []string) ([]byte, error) {
	if len(paths) == 0 || len(paths) > maxNodes {
		return nil, fmt.Errorf("dmr: mutable paths require 1..%d entries", maxNodes)
	}
	out := make([]byte, 16)
	le.PutUint32(out, MutablePathsTag)
	le.PutUint32(out[12:], uint32(len(paths)))
	for i, path := range paths {
		payload, err := terminatedString(path, maxSize-len(out)-4)
		if err != nil {
			return nil, fmt.Errorf("dmr: mutable path %d: %w", i, err)
		}
		size := 4 + len(payload)
		aligned := align4(size)
		if aligned > maxSize-len(out) {
			return nil, fmt.Errorf("dmr: mutable paths exceed size limit")
		}
		offset := len(out)
		out = append(out, make([]byte, aligned)...)
		le.PutUint32(out[offset:], uint32(size))
		copy(out[offset+4:], payload)
	}
	le.PutUint32(out[4:], uint32(len(out)))
	return out, nil
}

// ParseMutablePaths validates PKMP and all variable-sized path records, keeping
// empty entries and repeated paths in their original positions.
func ParseMutablePaths(data []byte) ([]string, error) {
	if len(data) < 16 || len(data) > maxSize || len(data)%4 != 0 || le.Uint32(data) != MutablePathsTag ||
		uint64(le.Uint32(data[4:])) != uint64(len(data)) || le.Uint32(data[8:]) != 0 {
		return nil, fmt.Errorf("dmr: invalid PKMP header")
	}
	count := le.Uint32(data[12:])
	if count == 0 || count > maxNodes {
		return nil, fmt.Errorf("dmr: invalid mutable path count")
	}
	paths := make([]string, 0, int(count))
	offset := 16
	for i := uint32(0); i < count; i++ {
		if len(data)-offset < 4 {
			return nil, fmt.Errorf("dmr: missing mutable path %d", i)
		}
		size := uint64(le.Uint32(data[offset:]))
		aligned := (size + 3) &^ uint64(3)
		if size < 4 || size%2 != 0 || aligned > uint64(len(data)-offset) {
			return nil, fmt.Errorf("dmr: invalid mutable path %d extent", i)
		}
		if !zeroBytes(data[offset+int(size) : offset+int(aligned)]) {
			return nil, fmt.Errorf("dmr: nonzero mutable path padding")
		}
		path, err := parseIdentityString(data[offset+4 : offset+int(size)])
		if err != nil {
			return nil, fmt.Errorf("dmr: mutable path %d: %w", i, err)
		}
		paths = append(paths, path)
		offset += int(aligned)
	}
	if offset != len(data) {
		return nil, fmt.Errorf("dmr: trailing mutable path bytes")
	}
	return paths, nil
}
