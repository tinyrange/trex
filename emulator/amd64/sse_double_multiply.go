package amd64

import (
	"fmt"
	"math/bits"
)

// multiplyDouble supports normal binary64 operands and signed zeros with a
// normal result. Exceptional ranges remain explicit stops, as with the existing
// scalar binary32 arithmetic. The 106-bit significand product is exact; using
// host multiplication to detect precision would lose the discarded bits.
func (c *CPU) multiplyDouble(a, b uint64) (uint64, error) {
	const fractionMask = uint64(1<<52 - 1)
	normal := func(v uint64) bool { e := v >> 52 & 2047; return e != 0 && e != 2047 }
	if (!normal(a) && a<<1 != 0) || (!normal(b) && b<<1 != 0) {
		return 0, fmt.Errorf("unsupported scalar double multiply operands %#x, %#x", a, b)
	}
	sign := (a ^ b) & (uint64(1) << 63)
	if a<<1 == 0 || b<<1 == 0 {
		return sign, nil
	}
	hi, lo := bits.Mul64(a&fractionMask|1<<52, b&fractionMask|1<<52)
	shift := uint(bits.Len64(hi) + 64 - 53)
	significand := hi<<(64-shift) | lo>>shift
	remainder := lo & (uint64(1)<<shift - 1)
	exponent := int(a>>52&2047) + int(b>>52&2047) - 1023 + int(shift) - 52
	if exponent <= 0 || exponent >= 2047 {
		return 0, fmt.Errorf("unsupported scalar double multiply result %#x, %#x", a, b)
	}
	if remainder != 0 {
		control := c.readMXCSR()
		if err := c.setMXCSR(control | 1<<5); err != nil {
			return 0, err
		}
		if control&(1<<12) == 0 {
			return 0, fmt.Errorf("unmasked SIMD precision exception")
		}
		increment := false
		switch control >> 13 & 3 {
		case 0:
			half := uint64(1) << (shift - 1)
			increment = remainder > half || remainder == half && significand&1 != 0
		case 1:
			increment = sign != 0
		case 2:
			increment = sign == 0
		}
		if increment {
			significand++
		}
		if significand == 1<<53 {
			significand >>= 1
			exponent++
			if exponent >= 2047 {
				return 0, fmt.Errorf("unsupported rounded double multiply overflow")
			}
		}
	}
	return sign | uint64(exponent)<<52 | significand&fractionMask, nil
}
