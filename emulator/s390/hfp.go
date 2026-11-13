package s390

import "math/big"

// Hexadecimal floating point. Values are held as sign, characteristic and an
// n-digit hexadecimal fraction (6 short, 14 long, 28 extended).

type hfp struct {
	neg  bool
	exp  int // characteristic (excess 64); may be out of range before checks
	frac *big.Int
	n    int // fraction digits
}

func (c *CPU) fprCheck(r int) {
	if c.CR[0]&0x00040000 != 0 {
		return
	}
	if r&9 != 0 {
		// Additional floating-point registers with the AFP-register
		// control off: data exception, DXC 1.
		c.dxc = 1
		c.program(pgmData)
	}
}

func (c *CPU) fprCheckExt(r int) {
	if r&2 != 0 || r > 13 {
		c.program(pgmSpecification)
	}
	c.fprCheck(r)
}

func hfpShort(x uint32) hfp {
	return hfp{neg: x>>31 != 0, exp: int(x>>24) & 0x7f, frac: new(big.Int).SetUint64(uint64(x & 0xffffff)), n: 6}
}
func hfpLong(x uint64) hfp {
	return hfp{neg: x>>63 != 0, exp: int(x>>56) & 0x7f, frac: new(big.Int).SetUint64(x & 0x00ffffffffffffff), n: 14}
}
func hfpExt(hi, lo uint64) hfp {
	f := new(big.Int).SetUint64(hi & 0x00ffffffffffffff)
	f.Lsh(f, 56)
	f.Or(f, new(big.Int).SetUint64(lo&0x00ffffffffffffff))
	return hfp{neg: hi>>63 != 0, exp: int(hi>>56) & 0x7f, frac: f, n: 28}
}

func (h hfp) short() uint32 {
	r := uint32(h.exp&0x7f)<<24 | uint32(h.frac.Uint64()&0xffffff)
	if h.neg {
		r |= 1 << 31
	}
	return r
}
func (h hfp) long() uint64 {
	r := uint64(h.exp&0x7f)<<56 | h.frac.Uint64()&0x00ffffffffffffff
	if h.neg {
		r |= 1 << 63
	}
	return r
}
func (h hfp) ext() (uint64, uint64) {
	lo := new(big.Int).And(h.frac, new(big.Int).SetUint64(0x00ffffffffffffff)).Uint64()
	hi := new(big.Int).Rsh(h.frac, 56).Uint64() & 0x00ffffffffffffff
	hi |= uint64(h.exp&0x7f) << 56
	if h.neg {
		hi |= 1 << 63
	}
	le := (h.exp - 14) & 0x7f
	if h.frac.Sign() == 0 {
		le = 0
	} else {
		lo |= uint64(le) << 56
	}
	if h.neg {
		lo |= 1 << 63
	}
	return hi, lo
}

func (h hfp) zero() bool { return h.frac.Sign() == 0 }

func pow16(n int) *big.Int { return new(big.Int).Lsh(big.NewInt(1), uint(4*n)) }

// convert changes the number of fraction digits, truncating.
func (h hfp) convert(n int) hfp {
	f := new(big.Int).Set(h.frac)
	if n > h.n {
		f.Lsh(f, uint(4*(n-h.n)))
	} else {
		f.Rsh(f, uint(4*(h.n-n)))
	}
	return hfp{neg: h.neg, exp: h.exp, frac: f, n: n}
}

// normalize shifts leading zero digits out.
func (h *hfp) normalize() {
	if h.frac.Sign() == 0 {
		return
	}
	lim := pow16(h.n - 1)
	for h.frac.Cmp(lim) < 0 {
		h.frac.Lsh(h.frac, 4)
		h.exp--
	}
}

// finish applies exponent overflow/underflow and significance rules.
// It returns the value to store; exceptions are raised after storing by
// the caller through the returned code (0 when none).
func (c *CPU) hfpFinish(h hfp, sigCheck bool) (hfp, uint16) {
	if h.frac.Sign() == 0 {
		if sigCheck && c.PSW.ProgMask&1 != 0 {
			return hfp{neg: h.neg, exp: h.exp & 0x7f, frac: new(big.Int), n: h.n}, pgmHFPSignificance
		}
		return hfp{frac: new(big.Int), n: h.n}, 0
	}
	if h.exp > 127 {
		h.exp -= 128
		return h, pgmHFPOverflow
	}
	if h.exp < 0 {
		if c.PSW.ProgMask&2 != 0 {
			h.exp += 128
			return h, pgmHFPUnderflow
		}
		return hfp{frac: new(big.Int), n: h.n}, 0
	}
	return h, 0
}

// hfpAdd adds b to a (b negated for subtraction).
func hfpAdd(a, b hfp, normalize bool) hfp {
	n := a.n
	fa := new(big.Int).Lsh(a.frac, 4)
	fb := new(big.Int).Lsh(b.convert(n).frac, 4)
	ea, eb := a.exp, b.exp
	if ea < eb {
		fa, fb = fb, fa
		ea, eb = eb, ea
		a, b = b, a
	}
	d := ea - eb
	if d > n+1 {
		fb.SetInt64(0)
	} else {
		fb.Rsh(fb, uint(4*d))
	}
	if a.neg {
		fa.Neg(fa)
	}
	if b.neg {
		fb.Neg(fb)
	}
	s := fa.Add(fa, fb)
	neg := s.Sign() < 0
	s.Abs(s)
	exp := ea
	if s.Cmp(pow16(n+1)) >= 0 {
		s.Rsh(s, 4)
		exp++
	}
	r := hfp{neg: neg, exp: exp, frac: s, n: n + 1}
	if normalize {
		r.normalize()
	}
	r.frac.Rsh(r.frac, 4)
	r.n = n
	if r.frac.Sign() == 0 {
		r.neg = false
		if !normalize {
			// unnormalized zero keeps the characteristic
		}
	}
	return r
}

func hfpMul(a, b hfp, n int) hfp {
	a = a.convert(n)
	b = b.convert(n)
	a.normalize()
	b.normalize()
	p := new(big.Int).Mul(a.frac, b.frac)
	r := hfp{neg: a.neg != b.neg, exp: a.exp + b.exp - 64, frac: p, n: 2 * n}
	r.normalize()
	return r.convert(n)
}

func hfpDiv(a, b hfp, n int) hfp {
	a = a.convert(n)
	b = b.convert(n)
	a.normalize()
	b.normalize()
	num := new(big.Int).Lsh(a.frac, uint(4*(n+1)))
	q := num.Quo(num, b.frac)
	r := hfp{neg: a.neg != b.neg, exp: a.exp - b.exp + 64, frac: q, n: n + 1}
	if r.frac.Cmp(pow16(n+1)) >= 0 {
		r.frac.Rsh(r.frac, 4)
		r.exp++
	}
	r.normalize()
	return r.convert(n)
}

func hfpCompare(a, b hfp) byte {
	b.neg = !b.neg
	d := hfpAdd(a.convert(max(a.n, b.n)), b.convert(max(a.n, b.n)), false)
	if d.zero() {
		return 0
	}
	if d.neg {
		return 1
	}
	return 2
}

func hfpCC(h hfp) byte {
	switch {
	case h.zero():
		return 0
	case h.neg:
		return 1
	}
	return 2
}

func (c *CPU) getShort(r int) hfp    { return hfpShort(uint32(c.FPR[r] >> 32)) }
func (c *CPU) setShort(r int, h hfp) { c.FPR[r] = c.FPR[r]&0xffffffff | uint64(h.short())<<32 }
func (c *CPU) getLong(r int) hfp     { return hfpLong(c.FPR[r]) }
func (c *CPU) setLong(r int, h hfp)  { c.FPR[r] = h.long() }
func (c *CPU) getExt(r int) hfp      { return hfpExt(c.FPR[r], c.FPR[r+2]) }
func (c *CPU) setExt(r int, h hfp) {
	hi, lo := h.ext()
	c.FPR[r], c.FPR[r+2] = hi, lo
}

func (c *CPU) raise(code uint16) {
	if code != 0 {
		c.program(code)
	}
}

// hfpRR handles opcodes 20-3F.
func (c *CPU) hfpRR(op byte, r1, r2 int) {
	ext := op == 0x25 || op == 0x26 || op == 0x27 || op == 0x35 || op == 0x36 || op == 0x37
	if !ext {
		c.fprCheck(r1)
		c.fprCheck(r2)
	}
	long := op < 0x30
	get := func(r int) hfp {
		if long {
			return c.getLong(r)
		}
		return c.getShort(r)
	}
	set := func(r int, h hfp) {
		if long {
			c.setLong(r, h)
		} else {
			c.setShort(r, h)
		}
	}
	switch op & 0x0f {
	case 0x0, 0x1, 0x2, 0x3: // LP, LN, LT, LC
		if ext && (op == 0x25 || op == 0x26 || op == 0x27) {
			break
		}
		h := get(r2)
		switch op & 0xf {
		case 0:
			h.neg = false
		case 1:
			h.neg = true
		case 3:
			h.neg = !h.neg
		}
		set(r1, h)
		c.PSW.CC = hfpCC(h)
		return
	case 0x4: // HDR/HER
		h := get(r2)
		n := h.n
		h.frac.Lsh(h.frac, 4)
		h.n++
		h.frac.Rsh(h.frac, 1)
		h.normalize()
		h.frac.Rsh(h.frac, 4)
		h.n = n
		r, code := c.hfpFinish(h, false)
		set(r1, r)
		c.raise(code)
		return
	case 0x8: // LDR/LER
		if long {
			c.FPR[r1] = c.FPR[r2]
		} else {
			c.FPR[r1] = c.FPR[r1]&0xffffffff | c.FPR[r2]&0xffffffff00000000
		}
		return
	case 0x9: // CDR/CER
		c.PSW.CC = hfpCompare(get(r1), get(r2))
		return
	case 0xa, 0xb, 0xe, 0xf: // AD/SD/AW/SW
		b := get(r2)
		if op&0xf == 0xb || op&0xf == 0xf {
			b.neg = !b.neg
		}
		h := hfpAdd(get(r1), b, op&0xf <= 0xb)
		r, code := c.hfpFinish(h, true)
		set(r1, r)
		c.PSW.CC = hfpCC(r)
		c.raise(code)
		return
	case 0xc: // MDR / MDER(MER: short x short -> long)
		var h hfp
		if long {
			h = hfpMul(c.getLong(r1), c.getLong(r2), 14)
			r, code := c.hfpFinish(h, false)
			c.setLong(r1, r)
			c.raise(code)
		} else {
			h = hfpMul(c.getShort(r1).convert(14), c.getShort(r2).convert(14), 14)
			r, code := c.hfpFinish(h, false)
			c.setLong(r1, r)
			c.raise(code)
		}
		return
	case 0xd: // DDR/DER
		b := get(r2)
		if b.zero() {
			c.program(pgmHFPDivide)
		}
		n := 14
		if !long {
			n = 6
		}
		h := hfpDiv(get(r1), b, n)
		r, code := c.hfpFinish(h, false)
		set(r1, r)
		c.raise(code)
		return
	}
	// Extended and rounding operations.
	switch op {
	case 0x25: // LRDR / LDXR: round extended to long
		c.fprCheck(r1)
		c.fprCheckExt(r2)
		h := c.getExt(r2)
		h = hfpRound(h, 14)
		r, code := c.hfpFinish(h, false)
		c.setLong(r1, r)
		c.raise(code)
	case 0x26: // MXR
		c.fprCheckExt(r1)
		c.fprCheckExt(r2)
		h := hfpMul(c.getExt(r1), c.getExt(r2), 28)
		r, code := c.hfpFinish(h, false)
		c.setExt(r1, r)
		c.raise(code)
	case 0x27: // MXDR
		c.fprCheckExt(r1)
		c.fprCheck(r2)
		h := hfpMul(c.getLong(r1).convert(28), c.getLong(r2).convert(28), 28)
		r, code := c.hfpFinish(h, false)
		c.setExt(r1, r)
		c.raise(code)
	case 0x35: // LRER / LEDR: round long to short
		c.fprCheck(r1)
		c.fprCheck(r2)
		h := hfpRound(c.getLong(r2), 6)
		r, code := c.hfpFinish(h, false)
		c.setShort(r1, r)
		c.raise(code)
	case 0x36, 0x37: // AXR, SXR
		c.fprCheckExt(r1)
		c.fprCheckExt(r2)
		b := c.getExt(r2)
		if op == 0x37 {
			b.neg = !b.neg
		}
		h := hfpAdd(c.getExt(r1), b, true)
		r, code := c.hfpFinish(h, true)
		c.setExt(r1, r)
		c.PSW.CC = hfpCC(r)
		c.raise(code)
	default:
		c.unknown()
	}
}

// hfpRound rounds to n digits (adding one in the first dropped digit's high bit).
func hfpRound(h hfp, n int) hfp {
	if h.n <= n {
		return h.convert(n)
	}
	f := new(big.Int).Set(h.frac)
	drop := uint(4 * (h.n - n))
	f.Add(f, new(big.Int).Lsh(big.NewInt(8), drop-4))
	f.Rsh(f, drop)
	r := hfp{neg: h.neg, exp: h.exp, frac: f, n: n}
	if f.Cmp(pow16(n)) >= 0 {
		r.frac.Rsh(r.frac, 4)
		r.exp++
	}
	return r
}

// hfpRX handles RX-format floating-point instructions.
func (c *CPU) hfpRX(op byte, r1 int, a uint32, b int) {
	c.fprCheck(r1)
	long := op < 0x70
	fetch := func() hfp {
		if long {
			return hfpLong(c.fetchDouble(a, b))
		}
		return hfpShort(c.fetchWord(a, b))
	}
	get := func(r int) hfp {
		if long {
			return c.getLong(r)
		}
		return c.getShort(r)
	}
	set := func(r int, h hfp) {
		if long {
			c.setLong(r, h)
		} else {
			c.setShort(r, h)
		}
	}
	switch op {
	case 0x60:
		c.storeDouble(a, b, c.FPR[r1])
		return
	case 0x70:
		c.storeWord(a, b, uint32(c.FPR[r1]>>32))
		return
	case 0x68:
		c.FPR[r1] = c.fetchDouble(a, b)
		return
	case 0x78:
		c.FPR[r1] = c.FPR[r1]&0xffffffff | uint64(c.fetchWord(a, b))<<32
		return
	case 0x67: // MXD
		c.fprCheckExt(r1)
		h := hfpMul(c.getLong(r1).convert(28), hfpLong(c.fetchDouble(a, b)).convert(28), 28)
		r, code := c.hfpFinish(h, false)
		c.setExt(r1, r)
		c.raise(code)
		return
	}
	switch op & 0xf {
	case 0x9:
		c.PSW.CC = hfpCompare(get(r1), fetch())
	case 0xa, 0xb, 0xe, 0xf:
		y := fetch()
		if op&0xf == 0xb || op&0xf == 0xf {
			y.neg = !y.neg
		}
		h := hfpAdd(get(r1), y, op&0xf <= 0xb)
		r, code := c.hfpFinish(h, true)
		set(r1, r)
		c.PSW.CC = hfpCC(r)
		c.raise(code)
	case 0xc:
		var h hfp
		if long {
			h = hfpMul(c.getLong(r1), fetch(), 14)
		} else {
			h = hfpMul(c.getShort(r1).convert(14), fetch().convert(14), 14)
		}
		r, code := c.hfpFinish(h, false)
		c.setLong(r1, r)
		c.raise(code)
	case 0xd:
		y := fetch()
		if y.zero() {
			c.program(pgmHFPDivide)
		}
		n := 14
		if !long {
			n = 6
		}
		h := hfpDiv(get(r1), y, n)
		r, code := c.hfpFinish(h, false)
		set(r1, r)
		c.raise(code)
	default:
		c.unknown()
	}
}

// hfpDXR implements DIVIDE (extended HFP).
func (c *CPU) hfpDXR(r1, r2 int) {
	c.fprCheckExt(r1)
	c.fprCheckExt(r2)
	y := c.getExt(r2)
	if y.zero() {
		c.program(pgmHFPDivide)
	}
	h := hfpDiv(c.getExt(r1), y, 28)
	r, code := c.hfpFinish(h, false)
	c.setExt(r1, r)
	c.raise(code)
}

// execB3 handles B3xx RRE floating-point instructions (HFP subset).
func (c *CPU) execB3() {
	op := c.op[:]
	r1, r2 := int(op[3]>>4), int(op[3]&0xf)
	switch op[1] {
	case 0x65: // LXR
		c.fprCheckExt(r1)
		c.fprCheckExt(r2)
		c.FPR[r1], c.FPR[r1+2] = c.FPR[r2], c.FPR[r2+2]
	case 0x74: // LZER
		c.fprCheck(r1)
		c.FPR[r1] &= 0xffffffff
	case 0x75: // LZDR
		c.fprCheck(r1)
		c.FPR[r1] = 0
	case 0x76: // LZXR
		c.fprCheckExt(r1)
		c.FPR[r1], c.FPR[r1+2] = 0, 0
	case 0x77, 0x7f: // FIER, FIDR
		c.fprCheck(r1)
		c.fprCheck(r2)
		long := op[1] == 0x7f
		var h hfp
		if long {
			h = c.getLong(r2)
		} else {
			h = c.getShort(r2)
		}
		// Truncate to integer: drop fraction digits below 16**0.
		digits := h.exp - 64
		if digits <= 0 {
			h = hfp{frac: new(big.Int), n: h.n}
		} else if digits < h.n {
			sh := uint(4 * (h.n - digits))
			h.frac.Rsh(h.frac, sh)
			h.frac.Lsh(h.frac, sh)
			h.normalize()
		}
		if long {
			c.setLong(r1, h)
		} else {
			c.setShort(r1, h)
		}
	case 0xb4, 0xb5: // CEFR, CDFR: convert from fixed
		c.fprCheck(r1)
		v := int64(int32(c.GR[r2]))
		h := hfp{neg: v < 0, exp: 64 + 8, frac: big.NewInt(0), n: 14}
		if v < 0 {
			v = -v
		}
		h.frac.SetInt64(v)
		h.frac.Lsh(h.frac, 4*6)
		h.normalize()
		if v == 0 {
			h = hfp{frac: new(big.Int), n: 14}
		}
		if op[1] == 0xb4 {
			c.setShort(r1, h.convert(6))
		} else {
			c.setLong(r1, h)
		}
	case 0xb8, 0xb9: // CFER, CFDR: convert to fixed (mask m3 rounding)
		c.fprCheck(r2)
		var h hfp
		if op[1] == 0xb8 {
			h = c.getShort(r2).convert(14)
		} else {
			h = c.getLong(r2)
		}
		f := new(big.Float).SetInt(h.frac)
		f.SetMantExp(f, 4*(h.exp-64-h.n))
		i, _ := f.Int64()
		if h.neg {
			i = -i
		}
		if i > 0x7fffffff || i < -0x80000000 {
			c.PSW.CC = 3
			c.GR[r1] = 0x80000000
			return
		}
		c.GR[r1] = uint32(int32(i))
		c.PSW.CC = hfpCC(h)
	default:
		c.unknown()
	}
}

// execED handles EDxx RXE-format instructions.
func (c *CPU) execED() {
	op := c.op[:]
	r1 := int(op[1] >> 4)
	a := c.eaRX(op)
	b := int(op[2] >> 4)
	switch op[5] {
	case 0x34: // SQE
		c.fprCheck(r1)
		c.setShort(r1, hfpSqrt(hfpShort(c.fetchWord(a, b)), c))
	case 0x35: // SQD
		c.fprCheck(r1)
		c.setLong(r1, hfpSqrt(hfpLong(c.fetchDouble(a, b)), c))
	case 0x37: // MEE
		c.fprCheck(r1)
		h := hfpMul(c.getShort(r1), hfpShort(c.fetchWord(a, b)), 6)
		r, code := c.hfpFinish(h, false)
		c.setShort(r1, r)
		c.raise(code)
	default:
		c.unknown()
	}
}

func hfpSqrt(h hfp, c *CPU) hfp {
	if h.zero() {
		return hfp{frac: new(big.Int), n: h.n}
	}
	if h.neg {
		c.program(pgmHFPSquareRoot)
	}
	h.normalize()
	// value = frac/16^n * 16^(e-64)
	e := h.exp - 64
	f := new(big.Int).Set(h.frac)
	if e%2 != 0 {
		f.Lsh(f, 4)
		e++
	}
	// sqrt(frac * 16^(n+?)) scaled to n digits
	f.Lsh(f, uint(4*h.n))
	s := new(big.Int).Sqrt(f)
	r := hfp{exp: e/2 + 64, frac: s, n: h.n}
	for r.frac.Cmp(pow16(h.n)) >= 0 {
		r.frac.Rsh(r.frac, 4)
		r.exp++
	}
	r.normalize()
	return r
}
