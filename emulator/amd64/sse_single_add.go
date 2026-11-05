package amd64

import "fmt"

// addSingle covers finite normal operands and signed zeros, with normal or
// zero results. Like scalar multiply/divide, exceptional ranges fail closed.
// Three guard/round/sticky bits retain precision even when the exponent gap
// exceeds binary64 precision; using host addition would lose directed rounding.
func (c *CPU) addSingle(a, b uint32) (uint32, error) {
	normal := func(v uint32) bool { e := v >> 23 & 255; return e != 0 && e != 255 }
	if (!normal(a) && a&0x7fffffff != 0) || (!normal(b) && b&0x7fffffff != 0) {
		return 0, fmt.Errorf("unsupported scalar add operands %#x, %#x", a, b)
	}
	control := c.readMXCSR()
	mode := control >> 13 & 3
	if a&0x7fffffff == 0 && b&0x7fffffff == 0 {
		if (a^b)&0x80000000 == 0 {
			return a, nil
		}
		if mode == 1 {
			return 0x80000000, nil
		}
		return 0, nil
	}
	if a&0x7fffffff == 0 {
		return b, nil
	}
	if b&0x7fffffff == 0 {
		return a, nil
	}
	jam := func(value uint64, shift uint) uint64 {
		if shift == 0 {
			return value
		}
		if shift >= 64 {
			if value != 0 {
				return 1
			}
			return 0
		}
		lost := value & (uint64(1)<<shift - 1)
		result := value >> shift
		if lost != 0 {
			result |= 1
		}
		return result
	}
	ea, eb := int(a>>23&255), int(b>>23&255)
	sa, sb := uint64(a&0x7fffff|1<<23)<<3, uint64(b&0x7fffff|1<<23)<<3
	exponent := ea
	if ea > eb {
		sb = jam(sb, uint(ea-eb))
	} else {
		sa = jam(sa, uint(eb-ea))
		exponent = eb
	}
	left, right := int64(sa), int64(sb)
	if a&0x80000000 != 0 {
		left = -left
	}
	if b&0x80000000 != 0 {
		right = -right
	}
	sum := left + right
	if sum == 0 {
		if mode == 1 {
			return 0x80000000, nil
		}
		return 0, nil
	}
	sign := uint32(0)
	if sum < 0 {
		sign = 0x80000000
		sum = -sum
	}
	magnitude := uint64(sum)
	if magnitude >= 1<<27 {
		magnitude = jam(magnitude, 1)
		exponent++
	}
	for magnitude < 1<<26 {
		magnitude <<= 1
		exponent--
	}
	if exponent <= 0 {
		return 0, fmt.Errorf("unsupported scalar add subnormal result")
	}
	significand, remainder := magnitude>>3, magnitude&7
	increment := false
	if remainder != 0 {
		switch mode {
		case 0:
			increment = remainder > 4 || remainder == 4 && significand&1 != 0
		case 1:
			increment = sign != 0
		case 2:
			increment = sign == 0
		}
	}
	if increment {
		significand++
	}
	if significand == 1<<24 {
		significand >>= 1
		exponent++
	}
	if exponent >= 255 {
		return 0, fmt.Errorf("unsupported scalar add overflow")
	}
	if remainder != 0 {
		if err := c.setMXCSR(control | 1<<5); err != nil {
			return 0, err
		}
		if control&(1<<12) == 0 {
			return 0, fmt.Errorf("unmasked SIMD precision exception")
		}
	}
	return sign | uint32(exponent)<<23 | uint32(significand)&0x7fffff, nil
}
