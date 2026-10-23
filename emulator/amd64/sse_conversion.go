package amd64

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/bits"
)

// CVTPS2PD is exact for finite values. Intel SDM Vol.2 lists only Invalid
// (signaling NaN) and Denormal exceptions; MXCSR.DAZ suppresses the latter.
func (c *CPU) packedSinglesToDoubles(value uint64) ([16]byte, error) {
	var result [16]byte
	control := c.readMXCSR()
	var exceptions uint64
	for lane := 0; lane < 2; lane++ {
		input := uint32(value >> (lane * 32))
		sign := uint64(input>>31) << 63
		exponent, fraction := (input>>23)&255, input&0x7fffff
		var output uint64
		switch {
		case exponent == 255:
			output = sign | 0x7ff0000000000000 | uint64(fraction)<<29
			if fraction != 0 {
				if fraction&0x400000 == 0 {
					exceptions |= 1
				}
				output |= 1 << 51 // Quiet NaN, preserving sign and payload.
			}
		case exponent == 0 && fraction != 0:
			if control&(1<<6) != 0 {
				output = sign
			} else {
				exceptions |= 2
				output = math.Float64bits(float64(math.Float32frombits(input)))
			}
		default:
			output = math.Float64bits(float64(math.Float32frombits(input)))
		}
		binary.LittleEndian.PutUint64(result[lane*8:], output)
	}
	if exceptions != 0 {
		if err := c.setMXCSR(control | exceptions); err != nil {
			return result, err
		}
		if exceptions & ^(control>>7) != 0 {
			return result, fmt.Errorf("unmasked SIMD conversion exception %#x", exceptions)
		}
	}
	return result, nil
}

// signedIntegerToSingle performs one rounding directly from the integer, avoiding
// double rounding through binary64 for 64-bit operands.
func (c *CPU) signedIntegerToSingle(value int64) (uint32, error) {
	if value == 0 {
		return 0, nil
	}
	magnitude := uint64(value)
	var sign uint32
	if value < 0 {
		sign = 1 << 31
		magnitude = -magnitude
	}
	exponent := bits.Len64(magnitude) - 1
	significand := magnitude
	if exponent <= 23 {
		significand <<= uint(23 - exponent)
	} else {
		shift := uint(exponent - 23)
		significand = magnitude >> shift
		remainder := magnitude & ((uint64(1) << shift) - 1)
		if remainder != 0 {
			control := c.readMXCSR()
			if err := c.setMXCSR(control | 1<<5); err != nil {
				return 0, err
			}
			if control&(1<<12) == 0 {
				return 0, fmt.Errorf("unmasked SIMD precision exception")
			}
			increment := false
			switch (control >> 13) & 3 {
			case 0:
				half := uint64(1) << (shift - 1)
				increment = remainder > half || (remainder == half && significand&1 != 0)
			case 1:
				increment = value < 0
			case 2:
				increment = value > 0
			}
			if increment {
				significand++
			}
			if significand == 1<<24 {
				significand >>= 1
				exponent++
			}
		}
	}
	return sign | uint32(exponent+127)<<23 | uint32(significand)&0x7fffff, nil
}

func (c *CPU) truncateSingleToInteger(input uint32, width int) (uint64, error) {
	control := c.readMXCSR()
	if control&(1<<6) != 0 && input&0x7f800000 == 0 {
		input &= 0x80000000
	}
	value := float64(math.Float32frombits(input))
	truncated := math.Trunc(value)
	limit := math.Ldexp(1, width*8-1)
	var exceptions, result uint64
	if math.IsNaN(value) || truncated < -limit || truncated >= limit {
		exceptions = 1
		result = uint64(1) << (width*8 - 1)
	} else {
		result = uint64(int64(truncated)) & mask(width)
		if truncated != value {
			exceptions = 1 << 5
		}
	}
	if exceptions != 0 {
		if err := c.setMXCSR(control | exceptions); err != nil {
			return 0, err
		}
		if exceptions & ^(control>>7) != 0 {
			return 0, fmt.Errorf("unmasked SIMD integer conversion exception %#x", exceptions)
		}
	}
	return result, nil
}
