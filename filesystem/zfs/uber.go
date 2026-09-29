package zfs

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
)

// Uberblocks have a location-salted SHA-256 trailer. Accepting an arbitrary
// magic/txg without that checksum could select corrupted transaction metadata.
func validUber(b []byte, offset uint64, o binary.ByteOrder) bool {
	if len(b) < 1024 || o.Uint64(b[len(b)-40:]) != 0x210da7ab10c7a11 {
		return false
	}
	input := bytes.Clone(b)
	sum := input[len(input)-32:]
	for i := range sum {
		sum[i] = 0
	}
	o.PutUint64(sum, offset)
	h := sha256.Sum256(input)
	for i := 0; i < 4; i++ {
		if be.Uint64(h[i*8:]) != o.Uint64(b[len(b)-32+i*8:]) {
			return false
		}
	}
	return true
}
