package power

import "bytes"

// The DPD encoding of three digits in the range 8..9 ignores the two
// high bits. Power ISA Book I requires the preferred encoding in results.
func preferredDeclet(d uint64) uint64 {
	if d&0x06e == 0x06e {
		return d & 0xff
	}
	return d
}

// dctdp widens the low 32 bits of FRB exactly. Short is a storage
// format, so even a signaling NaN retains its class without raising VX.
// See Power ISA Book I, DFP data-format conversion.
func (c *CPU) decimalShortToLong(w uint32) {
	src := uint64(uint32(c.FPR[(w>>11)&31]))
	sign := src >> 31
	comb := src >> 26 & 31
	result := sign<<63 | preferredDeclet(src>>10&0x3ff)<<10 | preferredDeclet(src&0x3ff)
	var class uint64
	switch comb {
	case 30: // Infinity also retains the source trailing digits on widening.
		result |= comb << 58
		class = 5
		if sign != 0 {
			class = 9
		}
	case 31:
		result |= comb<<58 | (src&(1<<25))<<32
		class = 0x11
		if src&(1<<25) != 0 {
			class = 1
		}
	default:
		expHigh, leading := comb>>3, comb&7
		if comb >= 24 {
			expHigh, leading = (comb>>1)&3, 8|(comb&1)
		}
		// The additional leading digits in the long significand are zero.
		exp := (expHigh<<6 | (src>>20)&63) + (398 - 101)
		result |= (exp>>8)<<61 | (exp&255)<<50 | leading<<20
		class = 4
		if sign != 0 {
			class = 8
		}
		if leading == 0 && src&0xfffff == 0 {
			class = 2 | sign<<4
		}
	}
	c.FPR[(w>>21)&31] = result
	c.FPSCR = c.FPSCR&^(fpsFR|fpsFI|fpsFPRF) | class<<12
	c.fpRecord(w)
}

// decodeDeclet expands a ten-bit DPD group into three decimal digits.
// The low bit of each digit stays in place across all eight encodings.
func decodeDeclet(code uint16) (uint8, uint8, uint8) {
	a, b, c := uint8(code>>7&7), uint8(code>>4&7), uint8(code&7)
	if code&8 == 0 {
		return a, b, c
	}
	switch c >> 1 {
	case 0:
		return a, b, 8 | c&1
	case 1:
		return a, 8 | b&1, b&6 | c&1
	case 2:
		return 8 | a&1, b, a&6 | c&1
	default:
		switch b >> 1 {
		case 0:
			return 8 | a&1, 8 | b&1, a&6 | c&1
		case 1:
			return 8 | a&1, a&6 | b&1, 8 | c&1
		case 2:
			return a, 8 | b&1, 8 | c&1
		default:
			return 8 | a&1, 8 | b&1, 8 | c&1
		}
	}
}

type decimalOperand struct {
	negative  bool
	infinite  bool
	nan       bool
	signaling bool
	exponent  int
	// Digits in most-significant-first order. Finite nonzero operands
	// omit leading zeros. NaNs and infinities retain their payload digits.
	digits []uint8
}

func (c *CPU) readDecimal(reg uint32, quad bool) decimalOperand {
	hi, lo := c.FPR[reg], c.FPR[reg]
	expBits, bias, groups := 8, 398, 5
	if quad {
		lo = c.FPR[reg+1]
		expBits, bias, groups = 12, 6176, 11
	}
	comb := hi >> 58 & 31
	d := decimalOperand{
		negative:  hi>>63 != 0,
		infinite:  comb == 30,
		nan:       comb == 31,
		signaling: comb == 31 && hi&(1<<57) != 0,
	}
	leading, expHigh := comb&7, comb>>3
	if comb >= 24 {
		leading, expHigh = 8|comb&1, (comb>>1)&3
	}
	expLow := hi >> (58 - expBits) & ((1 << expBits) - 1)
	d.exponent = int(expHigh<<expBits|expLow) - bias
	d.digits = make([]uint8, 1+3*groups)
	if !d.nan && !d.infinite {
		d.digits[0] = uint8(leading)
	}
	for i := groups - 1; i >= 0; i-- {
		a, b, c := decodeDeclet(uint16(lo & 1023))
		copy(d.digits[i*3+1:], []uint8{a, b, c})
		lo, hi = lo>>10|hi<<54, hi>>10
	}
	for len(d.digits) > 0 && d.digits[0] == 0 {
		d.digits = d.digits[1:]
	}
	return d
}

func compareDecimalMagnitude(a, b decimalOperand) int {
	if a.infinite || b.infinite {
		if a.infinite == b.infinite {
			return 0
		}
		if a.infinite {
			return 1
		}
		return -1
	}
	if len(a.digits) == 0 || len(b.digits) == 0 {
		return len(a.digits) - len(b.digits)
	}
	if order := len(a.digits) + a.exponent - len(b.digits) - b.exponent; order != 0 {
		return order
	}
	// Equal adjusted exponents align the leading digits. Omitted trailing
	// zeros have no weight in a numeric comparison.
	return bytes.Compare(bytes.TrimRight(a.digits, "\x00"), bytes.TrimRight(b.digits, "\x00"))
}

func (c *CPU) compareDecimalUnordered(w uint32, quad bool) {
	ra, rb := w>>16&31, w>>11&31
	if quad && (ra|rb)&1 != 0 {
		c.illegal(w)
		return
	}
	a, b := c.readDecimal(ra, quad), c.readDecimal(rb, quad)
	result := uint32(1)
	if !a.nan && !b.nan {
		order := compareDecimalMagnitude(a, b)
		// Both signed zeros compare equal, including different quanta.
		if a.negative != b.negative && (a.infinite || b.infinite || len(a.digits) != 0 || len(b.digits) != 0) {
			order = 1
		}
		if a.negative {
			order = -order
		}
		switch {
		case order < 0:
			result = 8
		case order > 0:
			result = 4
		default:
			result = 2
		}
	}
	// Comparisons write FPCC and BF even for an enabled sNaN exception.
	c.SetCRField(uint(w>>23&7), result)
	c.FPSCR = c.FPSCR&^(15<<12) | uint64(result)<<12
	if a.signaling || b.signaling {
		c.fpException(fpsVXSNAN)
		c.fpCheckEnabled(w&^1, c.FPSCR&fpsVE != 0)
	}
}

// Each triplet has exactly one preferred encoding.
var encodeDeclet = func() [1000]uint16 {
	var table [1000]uint16
	for code := uint16(0); code < 1024; code++ {
		if uint16(preferredDeclet(uint64(code))) == code {
			a, b, c := decodeDeclet(code)
			table[100*int(a)+10*int(b)+int(c)] = code
		}
	}
	return table
}()

// Pack a decimal interchange result; precision is 7, 16 or 34.
func (d decimalOperand) pack(precision int) (uint64, uint64) {
	expBits, bias := 8, 398
	switch precision {
	case 7:
		expBits, bias = 6, 101
	case 34:
		expBits, bias = 12, 6176
	}
	var digits [34]byte
	copy(digits[precision-len(d.digits):precision], d.digits)
	exp := uint64(d.exponent + bias)
	leading := uint64(digits[0])
	comb := (exp>>expBits)<<3 | leading
	switch {
	case d.nan:
		comb, exp = 31, 0
		if d.signaling {
			exp = 1 << (expBits - 1)
		}
	case d.infinite:
		comb, exp = 30, 0
	case leading >= 8:
		comb = 24 | (exp>>expBits)<<1 | leading&1
	}
	if d.negative {
		comb |= 32
	}
	hi, lo := uint64(0), comb<<expBits|exp&((1<<expBits)-1)
	for i := 1; i < precision; i += 3 {
		n := int(digits[i])*100 + int(digits[i+1])*10 + int(digits[i+2])
		hi, lo = hi<<10|lo>>54, lo<<10|uint64(encodeDeclet[n])
	}
	return hi, lo
}

func (d decimalOperand) resultClass(minNormal int) uint64 {
	switch {
	case d.signaling:
		return 1
	case d.nan:
		return 0x11
	case d.infinite:
		if d.negative {
			return 9
		}
		return 5
	case len(d.digits) == 0:
		if d.negative {
			return 0x12
		}
		return 2
	}
	class := uint64(4)
	if d.negative {
		class = 8
	}
	if len(d.digits)-1+d.exponent < minNormal {
		class |= 16
	}
	return class
}

// Drop low digits in one rounding operation, including implied leading
// zeros when the target quantum is larger than the entire magnitude.
func (d *decimalOperand) roundDigits(drop, mode int) (inexact, increment bool) {
	keep := len(d.digits) - drop
	tail := d.digits[max(keep, 0):]
	inexact = len(bytes.TrimRight(tail, "\x00")) > 0
	first, last := byte(0), byte(0)
	sticky := inexact
	if keep >= 0 && len(tail) > 0 {
		first = tail[0]
		sticky = len(bytes.TrimRight(tail[1:], "\x00")) > 0
	}
	d.digits = d.digits[:max(keep, 0)]
	if keep > 0 {
		last = d.digits[keep-1]
	}
	if !inexact {
		return false, false
	}
	switch mode {
	case 0:
		increment = first > 5 || first == 5 && (sticky || last&1 != 0)
	case 1: // toward zero
	case 2:
		increment = !d.negative
	case 3:
		increment = d.negative
	case 4:
		increment = first >= 5
	case 5:
		increment = first > 5 || first == 5 && sticky
	case 6:
		increment = true
	case 7:
		increment = last == 0 || last == 5
	}
	if increment {
		for i := len(d.digits) - 1; i >= 0; i-- {
			if d.digits[i] < 9 {
				d.digits[i]++
				return true, true
			}
			d.digits[i] = 0
		}
		d.digits = append([]byte{1}, d.digits...)
	}
	return inexact, increment
}

func (c *CPU) quantizeDecimal(w uint32, quad bool) {
	rt, ra, rb := w>>21&31, w>>16&31, w>>11&31
	if quad && (rt|ra|rb)&1 != 0 {
		c.illegal(w)
		return
	}
	a, b := c.readDecimal(ra, quad), c.readDecimal(rb, quad)
	precision, minNormal := 16, -383
	if quad {
		precision, minNormal = 34, -6143
	}
	result := b
	invalid := uint64(0)
	var inexact, rounded bool
	switch {
	case a.nan || b.nan:
		// A signaling NaN takes priority, with FRA first within a class.
		if a.signaling || a.nan && !b.signaling {
			result = a
		}
		if result.signaling {
			invalid = fpsVXSNAN
		}
		result.signaling = false
	case a.infinite != b.infinite:
		invalid = fpsVXCVI
		result = decimalOperand{nan: true}
	case b.infinite:
		result.digits = nil
	default:
		result.exponent = a.exponent
		drop := a.exponent - b.exponent
		if len(b.digits) != 0 {
			switch {
			case drop > 0:
				mode := int(w >> 9 & 3)
				if mode == 2 {
					mode = 4
				} else if mode == 3 {
					mode = int(c.FPSCR >> 32 & 7)
				}
				inexact, rounded = result.roundDigits(drop, mode)
			case len(b.digits)-drop > precision:
				result = decimalOperand{nan: true}
				invalid = fpsVXCVI
			case drop < 0:
				result.digits = append(result.digits, make([]byte, -drop)...)
			}
		}
	}
	c.FPSCR &^= fpsFI | fpsFR
	if invalid != 0 {
		c.fpException(invalid)
		if c.FPSCR&fpsVE != 0 {
			c.fpCheckEnabled(w, true)
			return
		}
	}
	hi, lo := result.pack(precision)
	c.FPR[rt] = lo
	if quad {
		c.FPR[rt], c.FPR[rt+1] = hi, lo
	}
	c.FPSCR = c.FPSCR&^fpsFPRF | result.resultClass(minNormal)<<12
	if rounded {
		c.FPSCR |= fpsFR
	}
	if inexact {
		c.FPSCR |= fpsFI
		c.fpException(fpsXX)
	}
	c.fpCheckEnabled(w, inexact && c.FPSCR&fpsXE != 0)
}

// drsp returns a zero-extended decimal32. Enabled exponent exceptions
// deliver a decimal64 with a wrapped exponent and seven-digit precision.
func (c *CPU) roundDecimalToShort(w uint32) {
	d := c.readDecimal(w>>11&31, false)
	mode := int(c.FPSCR >> 32 & 7)
	precision, minNormal := 7, -95
	var flags uint64
	var inexact, rounded bool
	switch {
	case d.nan || d.infinite:
		d.digits = d.digits[max(0, len(d.digits)-6):]
	case len(d.digits) == 0:
		d.exponent = min(90, max(-101, d.exponent))
	default:
		tiny := len(d.digits)-1+d.exponent < minNormal
		drop := max(len(d.digits)-precision, 0)
		if tiny && c.FPSCR&fpsUE != 0 {
			d.exponent += 192
			precision, minNormal = 16, -383
			flags |= fpsUX
		} else {
			drop = max(drop, -101-d.exponent)
		}
		if drop > 0 {
			inexact, rounded = d.roundDigits(drop, mode)
			d.exponent += drop
			if len(d.digits) > 7 { // carry out of the most significant digit
				d.digits = d.digits[:7]
				d.exponent++
			}
		}
		if tiny && inexact {
			flags |= fpsUX
		}
		switch {
		case precision == 16:
			// Already wrapped an enabled underflow.
		case len(d.digits)-1+d.exponent > 96:
			flags |= fpsOX
			if c.FPSCR&fpsOE != 0 {
				d.exponent -= 192
				precision, minNormal = 16, -383
			} else {
				inexact = true
				rounded = !(mode == 1 || mode == 7 || mode == 2 && d.negative || mode == 3 && !d.negative)
				if rounded {
					d.infinite, d.digits = true, nil
				} else {
					d.digits, d.exponent = []byte{9, 9, 9, 9, 9, 9, 9}, 90
				}
			}
		case d.exponent > 90:
			d.digits = append(d.digits, make([]byte, d.exponent-90)...)
			d.exponent = 90
		}
	}
	_, c.FPR[w>>21&31] = d.pack(precision)
	c.FPSCR = c.FPSCR&^(fpsFI|fpsFR|fpsFPRF) | d.resultClass(minNormal)<<12
	if rounded {
		c.FPSCR |= fpsFR
	}
	if inexact {
		c.FPSCR |= fpsFI
		flags |= fpsXX
	}
	if flags != 0 {
		c.fpException(flags)
	}
	c.fpCheckEnabled(w, flags&fpsOX != 0 && c.FPSCR&fpsOE != 0 ||
		flags&fpsUX != 0 && c.FPSCR&fpsUE != 0 ||
		inexact && c.FPSCR&fpsXE != 0)
}
