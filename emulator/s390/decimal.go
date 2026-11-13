package s390

import "math/big"

func cvd(x int32) uint64 {
	v := int64(x)
	neg := v < 0
	if neg {
		v = -v
	}
	var r uint64 = 0xc
	if neg {
		r = 0xd
	}
	for i := uint(1); i < 16; i++ {
		r |= uint64(v%10) << (4 * i)
		v /= 10
	}
	return r
}

func (c *CPU) cvb(x uint64) uint32 {
	sign := x & 0xf
	if sign < 0xa {
		c.program(pgmData)
	}
	var v int64
	for i := 15; i >= 1; i-- {
		d := (x >> (4 * uint(i))) & 0xf
		if d > 9 {
			c.program(pgmData)
		}
		v = v*10 + int64(d)
	}
	if sign == 0xb || sign == 0xd {
		v = -v
	}
	if v > 0x7fffffff || v < -0x80000000 {
		c.GR[c.op[1]>>4] = uint32(v)
		c.program(pgmFixedDivide)
	}
	return uint32(int32(v))
}

// packed reads a packed-decimal operand and returns its value.
func (c *CPU) packed(a uint32, b int, l uint32) *big.Int {
	v := new(big.Int)
	ten := big.NewInt(10)
	var sign byte
	for i := uint32(0); i < l; i++ {
		x := c.fetchByte(a+i, b)
		hi, lo := x>>4, x&0xf
		if hi > 9 {
			c.program(pgmData)
		}
		v.Mul(v, ten)
		v.Add(v, big.NewInt(int64(hi)))
		if i == l-1 {
			sign = lo
		} else {
			if lo > 9 {
				c.program(pgmData)
			}
			v.Mul(v, ten)
			v.Add(v, big.NewInt(int64(lo)))
		}
	}
	if sign < 0xa {
		c.program(pgmData)
	}
	if sign == 0xb || sign == 0xd {
		v.Neg(v)
	}
	return v
}

// storePacked stores v into an l-byte packed field; it reports overflow.
func (c *CPU) storePacked(a uint32, b int, l uint32, v *big.Int) bool {
	neg := v.Sign() < 0
	m := new(big.Int).Abs(v)
	digits := m.String()
	cap := int(l*2 - 1)
	over := len(digits) > cap
	if over {
		digits = digits[len(digits)-cap:]
	}
	buf := make([]byte, l)
	sign := byte(0xc)
	if neg && !allZero(digits) {
		sign = 0xd
	}
	buf[l-1] = sign
	pos := len(digits) - 1
	for i := int(l*2 - 2); i >= 0 && pos >= 0; i-- {
		d := digits[pos] - '0'
		pos--
		if i%2 == 0 {
			buf[i/2] |= d << 4
		} else {
			buf[i/2] |= d
		}
	}
	for i := uint32(0); i < l; i++ {
		c.storeByte(a+i, b, buf[i])
	}
	return over
}

func allZero(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '0' {
			return false
		}
	}
	return true
}

func (c *CPU) decimalCC(v *big.Int, over bool) {
	if over {
		c.PSW.CC = 3
		if c.PSW.ProgMask&4 != 0 {
			c.program(pgmDecimalOverflow)
		}
		return
	}
	c.PSW.CC = byte(ccSigned(int32(v.Sign())))
}

// ssDecimal handles two-length SS decimal instructions.
func (c *CPU) ssDecimal() {
	op := c.op[:]
	l1 := uint32(op[1]>>4) + 1
	l2 := uint32(op[1]&0xf) + 1
	a1 := c.eaBD(op[2], op[3])
	a2 := c.eaBD(op[4], op[5])
	b1, b2 := int(op[2]>>4), int(op[4]>>4)
	switch op[0] {
	case 0xf0: // SRP
		l1 = uint32(op[1]>>4) + 1
		round := op[1] & 0xf
		if round > 9 {
			c.program(pgmData)
		}
		v := c.packed(a1, b1, l1)
		sh := int(int8(byte(a2<<2)) >> 2) // six-bit signed shift
		ten := big.NewInt(10)
		neg := v.Sign() < 0
		m := new(big.Int).Abs(v)
		if sh > 0 {
			m.Mul(m, new(big.Int).Exp(ten, big.NewInt(int64(sh)), nil))
		} else if sh < 0 {
			d := new(big.Int).Exp(ten, big.NewInt(int64(-sh-1)), nil)
			m.Quo(m, d)
			m.Add(m, big.NewInt(int64(round)))
			m.Quo(m, ten)
		}
		if neg {
			m.Neg(m)
		}
		over := c.storePacked(a1, b1, l1, m)
		c.decimalCC(m, over)
	case 0xf1: // MVO
		c.checkStore(a1, l1, b1)
		src := make([]byte, l2)
		for i := uint32(0); i < l2; i++ {
			src[i] = c.fetchByte(a2+i, b2)
		}
		last := c.fetchByte(a1+l1-1, b1) & 0xf
		// Build nibble string: source digits then the preserved sign.
		var nib []byte
		for _, x := range src {
			nib = append(nib, x>>4, x&0xf)
		}
		nib = append(nib, last)
		out := make([]byte, l1)
		pos := len(nib) - 1
		for i := int(l1*2 - 1); i >= 0; i-- {
			var d byte
			if pos >= 0 {
				d = nib[pos]
				pos--
			}
			if i%2 == 0 {
				out[i/2] |= d << 4
			} else {
				out[i/2] |= d
			}
		}
		for i := uint32(0); i < l1; i++ {
			c.storeByte(a1+i, b1, out[i])
		}
	case 0xf2: // PACK
		c.checkStore(a1, l1, b1)
		src := make([]byte, l2)
		for i := uint32(0); i < l2; i++ {
			src[i] = c.fetchByte(a2+i, b2)
		}
		out := make([]byte, l1)
		// rightmost byte: swap nibbles
		out[l1-1] = src[l2-1]<<4 | src[l2-1]>>4
		si := int(l2) - 2
		for i := int(l1) - 2; i >= 0; i-- {
			var lo, hi byte
			if si >= 0 {
				lo = src[si] & 0xf
				si--
			}
			if si >= 0 {
				hi = src[si] & 0xf
				si--
			}
			out[i] = hi<<4 | lo
		}
		for i := uint32(0); i < l1; i++ {
			c.storeByte(a1+i, b1, out[i])
		}
	case 0xf3: // UNPK
		c.checkStore(a1, l1, b1)
		src := make([]byte, l2)
		for i := uint32(0); i < l2; i++ {
			src[i] = c.fetchByte(a2+i, b2)
		}
		out := make([]byte, l1)
		out[l1-1] = src[l2-1]<<4 | src[l2-1]>>4
		var nib []byte
		for i := 0; i < int(l2)-1; i++ {
			nib = append(nib, src[i]>>4, src[i]&0xf)
		}
		nib = append(nib, src[l2-1]>>4)
		nib = nib[:len(nib)-1]
		pos := len(nib) - 1
		for i := int(l1) - 2; i >= 0; i-- {
			var d byte
			if pos >= 0 {
				d = nib[pos]
				pos--
			}
			out[i] = 0xf0 | d
		}
		for i := uint32(0); i < l1; i++ {
			c.storeByte(a1+i, b1, out[i])
		}
	case 0xf8: // ZAP
		v := c.packed(a2, b2, l2)
		over := c.storePacked(a1, b1, l1, v)
		c.decimalCC(v, over)
	case 0xf9: // CP
		x := c.packed(a1, b1, l1)
		y := c.packed(a2, b2, l2)
		c.PSW.CC = byte(ccSigned(int32(x.Cmp(y))))
	case 0xfa, 0xfb: // AP, SP
		x := c.packed(a1, b1, l1)
		y := c.packed(a2, b2, l2)
		if op[0] == 0xfa {
			x.Add(x, y)
		} else {
			x.Sub(x, y)
		}
		over := c.storePacked(a1, b1, l1, x)
		c.decimalCC(x, over)
	case 0xfc: // MP
		if l2 > 8 || l2 >= l1 {
			c.program(pgmSpecification)
		}
		x := c.packed(a1, b1, l1)
		y := c.packed(a2, b2, l2)
		// The multiplicand must have at least l2 bytes of leading zeros.
		lim := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64((l1-l2)*2-1)), nil)
		if new(big.Int).Abs(x).Cmp(lim) >= 0 {
			c.program(pgmData)
		}
		x.Mul(x, y)
		c.storePacked(a1, b1, l1, x)
	case 0xfd: // DP
		if l2 > 8 || l2 >= l1 {
			c.program(pgmSpecification)
		}
		x := c.packed(a1, b1, l1)
		y := c.packed(a2, b2, l2)
		if y.Sign() == 0 {
			c.program(pgmDecimalDivide)
		}
		q, r := new(big.Int), new(big.Int)
		q.QuoRem(x, y, r)
		ql := l1 - l2
		lim := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(ql*2-1)), nil)
		if new(big.Int).Abs(q).Cmp(lim) >= 0 {
			c.program(pgmDecimalDivide)
		}
		c.storePacked(a1, b1, ql, q)
		// remainder carries the dividend's sign
		if r.Sign() == 0 && x.Sign() < 0 {
			c.storePacked(a1+ql, b1, l2, r)
			c.storeByte(a1+l1-1, b1, c.fetchByte(a1+l1-1, b1)&0xf0|0xd)
		} else {
			c.storePacked(a1+ql, b1, l2, r)
		}
	}
}
