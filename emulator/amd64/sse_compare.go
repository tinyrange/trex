package amd64

import (
	"fmt"
	"math"
)

func (c *CPU) compareSingles(a, b uint32) error {
	return c.compareScalars(uint64(a), uint64(b), 4)
}

func (c *CPU) compareDoubles(a, b uint64) error {
	return c.compareScalars(a, b, 8)
}

func (c *CPU) compareScalars(a, b uint64, width int) error {
	exponentMask, fractionMask, signMask := uint64(0x7ff0000000000000), uint64(0xfffffffffffff), uint64(1)<<63
	if width == 4 {
		exponentMask, fractionMask, signMask = 0x7f800000, 0x7fffff, 0x80000000
	}
	control := c.readMXCSR()
	var exceptions uint64
	nan := func(v uint64) bool { return v & ^signMask > exponentMask }
	unordered := nan(a) || nan(b)
	if unordered {
		exceptions = 1
	} else {
		for _, p := range []*uint64{&a, &b} {
			if *p&exponentMask == 0 && *p&fractionMask != 0 {
				if control&(1<<6) != 0 {
					*p &= signMask
				} else {
					exceptions |= 2
				}
			}
		}
	}
	if exceptions != 0 {
		if err := c.setMXCSR(control | exceptions); err != nil {
			return err
		}
		if exceptions & ^(control>>7) != 0 {
			return fmt.Errorf("unmasked SIMD comparison exception %#x", exceptions)
		}
	}
	c.flags &^= flagZero | flagParity | flagCarry | flagOverflow | flagSign | uint64(1<<4)
	if unordered {
		c.flags |= flagZero | flagParity | flagCarry
	} else {
		x, y := math.Float64frombits(a), math.Float64frombits(b)
		if width == 4 {
			x, y = float64(math.Float32frombits(uint32(a))), float64(math.Float32frombits(uint32(b)))
		}
		if x == y {
			c.flags |= flagZero
		} else if x < y {
			c.flags |= flagCarry
		}
	}
	return nil
}
