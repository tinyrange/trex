package amd64

import (
	"fmt"
	"math"
)

// arithmeticSingle supports finite normal operands (and signed zeros) with
// a finite normal result. Exceptional ranges are explicit stops,
// not host-dependent floating-point results or fabricated successful execution.
func (c *CPU) arithmeticSingle(a, b uint32, multiply bool) (uint32, error) {
	normal := func(v uint32) bool { e := (v >> 23) & 255; return e != 0 && e != 255 }
	if (!normal(a) && a&0x7fffffff != 0) || (!normal(b) && !(multiply && b&0x7fffffff == 0)) {
		return 0, fmt.Errorf("unsupported scalar arithmetic operands %#x, %#x", a, b)
	}
	if a&0x7fffffff == 0 || (multiply && b&0x7fffffff == 0) {
		return (a ^ b) & 0x80000000, nil
	}
	x, y := float64(math.Float32frombits(a)), float64(math.Float32frombits(b))
	quotient := x / y
	if multiply {
		quotient = x * y
	}
	result := float32(quotient)
	if !normal(math.Float32bits(result)) {
		return 0, fmt.Errorf("unsupported scalar arithmetic result %#x, %#x", a, b)
	}
	// A ratio of two binary32 significands cannot lie closer to a binary32
	// midpoint than binary64 can distinguish. The product below is exact (at
	// most 48 significant bits), so it also detects precision loss exactly.
	product := float64(result) * y
	if multiply {
		product = float64(result)
		x = quotient
		y = 1
	}
	if product == x {
		return math.Float32bits(result), nil
	}
	control := c.readMXCSR()
	if err := c.setMXCSR(control | 1<<5); err != nil {
		return 0, err
	}
	if control&(1<<12) == 0 {
		return 0, fmt.Errorf("unmasked SIMD precision exception")
	}
	above := product > x
	if y < 0 {
		above = product < x
	}
	switch (control >> 13) & 3 {
	case 1:
		if above {
			result = math.Nextafter32(result, float32(math.Inf(-1)))
		}
	case 2:
		if !above {
			result = math.Nextafter32(result, float32(math.Inf(1)))
		}
	case 3:
		if quotient > 0 && above {
			result = math.Nextafter32(result, 0)
		}
		if quotient < 0 && !above {
			result = math.Nextafter32(result, 0)
		}
	}
	return math.Float32bits(result), nil
}
