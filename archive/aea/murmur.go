package aea

import (
	"encoding/binary"
	"math/bits"
)

// murmur64 is the low half of MurmurHash3 x64-128, with a 64-bit initial seed.
func murmur64(data []byte, seed uint64) uint64 {
	const c1, c2 uint64 = 0x87c37b91114253d5, 0x4cf5ad432745937f
	h1, h2 := seed, seed
	size := len(data)
	for len(data) >= 16 {
		k1, k2 := binary.LittleEndian.Uint64(data), binary.LittleEndian.Uint64(data[8:])
		h1 ^= bits.RotateLeft64(k1*c1, 31) * c2
		h1 = (bits.RotateLeft64(h1, 27)+h2)*5 + 0x52dce729
		h2 ^= bits.RotateLeft64(k2*c2, 33) * c1
		h2 = (bits.RotateLeft64(h2, 31)+h1)*5 + 0x38495ab5
		data = data[16:]
	}
	var k1, k2 uint64
	for i, v := range data {
		if i < 8 {
			k1 |= uint64(v) << uint(i*8)
		} else {
			k2 |= uint64(v) << uint((i-8)*8)
		}
	}
	h1 ^= bits.RotateLeft64(k1*c1, 31) * c2
	h2 ^= bits.RotateLeft64(k2*c2, 33) * c1
	h1 ^= uint64(size)
	h2 ^= uint64(size)
	h1 += h2
	h2 += h1
	fmix := func(h uint64) uint64 {
		h ^= h >> 33
		h *= 0xff51afd7ed558ccd
		h ^= h >> 33
		h *= 0xc4ceb9fe1a85ec53
		return h ^ (h >> 33)
	}
	return fmix(h1) + fmix(h2)
}
