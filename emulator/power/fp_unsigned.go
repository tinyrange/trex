package power

import (
	"math"
	"math/bits"
)

const (
	fpsFX     = uint64(1) << 31
	fpsFEX    = uint64(1) << 30
	fpsVX     = uint64(1) << 29
	fpsOX     = uint64(1) << 28
	fpsUX     = uint64(1) << 27
	fpsXX     = uint64(1) << 25
	fpsVXSNAN = uint64(1) << 24
	fpsFR     = uint64(1) << 18
	fpsFI     = uint64(1) << 17
	fpsFPRF   = uint64(31) << 12
	fpsVXCVI  = uint64(1) << 8
	fpsVE     = uint64(1) << 7
	fpsOE     = uint64(1) << 6
	fpsUE     = uint64(1) << 5
	fpsXE     = uint64(1) << 3
)

// FPSCR's VX and FEX are derived summaries, rather than independent sticky bits.
func (c *CPU) fpSummaries() {
	c.FPSCR &^= fpsVX | fpsFEX
	if c.FPSCR&0x01f80700 != 0 {
		c.FPSCR |= fpsVX
	}
	if c.FPSCR&fpsVX != 0 && c.FPSCR&fpsVE != 0 ||
		c.FPSCR&fpsOX != 0 && c.FPSCR&fpsOE != 0 ||
		c.FPSCR&fpsUX != 0 && c.FPSCR&fpsUE != 0 ||
		c.FPSCR&(1<<26) != 0 && c.FPSCR&(1<<4) != 0 ||
		c.FPSCR&fpsXX != 0 && c.FPSCR&fpsXE != 0 {
		c.FPSCR |= fpsFEX
	}
}

func (c *CPU) fpException(flags uint64) {
	if flags&^c.FPSCR != 0 {
		c.FPSCR |= fpsFX
	}
	c.FPSCR |= flags
	c.fpSummaries()
}

func (c *CPU) fpRecord(w uint32) {
	if w&1 != 0 {
		c.SetCRField(1, uint32(c.FPSCR>>28)&15)
	}
}

func (c *CPU) fpCheckEnabled(w uint32, enabled bool) {
	c.fpRecord(w)
	// FE0/FE1 control delivery; FPSCR enable bits still control results.
	if enabled && c.MSR&(MSRFE0|MSRFE1) != 0 {
		c.program(ProgFP)
	}
}

// fcfidu rounds an unsigned64-bit integer directly to binary64 without a
// signed intermediate or dependence on the host's floating-point rounding mode.
func (c *CPU) convertFromUnsigned(w uint32) {
	t, b := (w>>21)&31, (w>>11)&31
	v := c.FPR[b]
	c.FPSCR &^= fpsFR | fpsFI | fpsFPRF
	if v == 0 {
		c.FPR[t] = 0
		c.FPSCR |= 2 << 12 // positive zero
		c.fpCheckEnabled(w, false)
		return
	}
	exponent := bits.Len64(v) - 1
	var significand, lost uint64
	var increment bool
	if exponent <= 52 {
		significand = v << uint(52-exponent)
	} else {
		shift := uint(exponent - 52)
		significand = v >> shift
		lost = v & ((uint64(1) << shift) - 1)
		switch c.FPSCR & 3 {
		case 0:
			half := uint64(1) << (shift - 1)
			increment = lost > half || lost == half && significand&1 != 0
		case 2:
			increment = lost != 0
		}
		if increment {
			significand++
			if significand == 1<<53 {
				significand >>= 1
				exponent++
			}
			c.FPSCR |= fpsFR
		}
	}
	c.FPR[t] = uint64(exponent+1023)<<52 | significand&((1<<52)-1)
	c.FPSCR |= 4 << 12 // positive normal
	if lost != 0 {
		c.FPSCR |= fpsFI
		c.fpException(fpsXX)
	}
	c.fpCheckEnabled(w, lost != 0 && c.FPSCR&fpsXE != 0)
}

// fctiduz/fctiwuz truncate toward zero; fctiwu uses FPSCR.RN. Invalid values
// saturate only when VE is disabled; an enabled invalid leaves FRT unchanged.
func (c *CPU) convertToUnsigned(w uint32) {
	t, b := (w>>21)&31, (w>>11)&31
	encoded := c.FPR[b]
	src := math.Float64frombits(encoded)
	rounded := math.Trunc(src)
	xo := (w >> 1) & 0x3ff
	if xo == 142 {
		switch c.FPSCR & 3 {
		case 0:
			rounded = math.RoundToEven(src)
		case 2:
			rounded = math.Ceil(src)
		case 3:
			rounded = math.Floor(src)
		}
	}
	limit, maximum := 0x1p64, ^uint64(0)
	if xo == 143 || xo == 142 {
		limit, maximum = 0x1p32, 0xffffffff
	}
	c.FPSCR &^= fpsFR | fpsFI
	invalid := math.IsNaN(src) || rounded < 0 || rounded >= limit
	var result uint64
	if invalid {
		if !math.IsNaN(src) && rounded > 0 {
			result = maximum
		}
		flags := fpsVXCVI
		if math.IsNaN(src) && encoded&(1<<51) == 0 {
			flags |= fpsVXSNAN
		}
		c.fpException(flags)
		if c.FPSCR&fpsVE == 0 {
			c.FPR[t] = result
		}
	} else {
		c.FPR[t] = uint64(rounded)
		if src != rounded {
			c.FPSCR |= fpsFI
			if math.Abs(rounded) > math.Abs(src) {
				c.FPSCR |= fpsFR
			}
			c.fpException(fpsXX)
		}
	}
	c.fpCheckEnabled(w, invalid && c.FPSCR&fpsVE != 0 || !invalid && src != rounded && c.FPSCR&fpsXE != 0)
}
