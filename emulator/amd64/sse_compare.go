package amd64

import (
	"fmt"
	"math"
)

func (c *CPU) compareSingles(a, b uint32) error {
	control := c.readMXCSR()
	var exceptions uint64
	nan := func(v uint32) bool { return v&0x7fffffff > 0x7f800000 }
	unordered := nan(a) || nan(b)
	if unordered {
		exceptions = 1
	} else {
		for _, p := range []*uint32{&a, &b} {
			if *p&0x7f800000 == 0 && *p&0x7fffff != 0 {
				if control&(1<<6) != 0 {
					*p &= 0x80000000
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
		x, y := math.Float32frombits(a), math.Float32frombits(b)
		if x == y {
			c.flags |= flagZero
		} else if x < y {
			c.flags |= flagCarry
		}
	}
	return nil
}
