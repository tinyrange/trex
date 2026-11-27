package r3000

import "math"

func (c *r4kCPU) cop0(word, format, rt, rd uint32, x *r4kInstruction) {
	if !c.kernel() && c.cp0[status]&(1<<28) == 0 {
		x.code = 11
		return
	}
	switch format {
	case 0:
		c.gpr[rt] = mipsWord(uint32(c.cp0[rd]))
	case 1:
		c.gpr[rt] = c.cp0[rd]
	case 4, 5:
		v := c.gpr[rt]
		if format == 4 {
			v = mipsWord(uint32(v))
		}
		switch rd {
		case 0:
			c.cp0[rd] = v & 0x8000003f
		case 1, 8, 15, 27: // Random, BadVAddr, PRId, CacheErr.
		case 2, 3:
			c.cp0[rd] = v & 0x3fffffff
		case 5:
			c.cp0[rd] = v & 0x01ffe000
		case 6:
			c.cp0[rd], c.cp0[1] = v&63, uint64(len(c.tlb)-1)
		case 9, 11, status:
			c.cp0[rd] = uint64(uint32(v))
			if rd == 11 {
				c.cp0[cause] &^= 1 << 15
			}
		case 10:
			c.cp0[rd] = v & (r4kVPN | 255)
		case cause:
			c.cp0[rd] = c.cp0[rd]&^0x300 | v&0x300
		case 16:
			c.cp0[rd] = c.cp0[rd]&^7 | v&7
		default:
			c.cp0[rd] = v
		}
	case 16:
		i := c.cp0[0] & 63
		switch word & 63 {
		case 1:
			if i < uint64(len(c.tlb)) {
				t := c.tlb[i]
				c.cp0[10], c.cp0[2], c.cp0[3], c.cp0[5] = t.hi, t.even, t.odd, t.mask
			}
		case 6, 2:
			if word&63 == 6 {
				i = c.cp0[1]
			}
			if i < uint64(len(c.tlb)) {
				c.tlb[i] = r4kTLB{c.cp0[10], c.cp0[2], c.cp0[3], c.cp0[5]}
			}
		case 8:
			i := c.probe(c.cp0[10])
			c.cp0[0] = 1 << 31
			if i >= 0 {
				c.cp0[0] = uint64(i)
			}
		case 24:
			x.annul, x.target = true, c.cp0[epc]
			if c.cp0[status]&r4kERL != 0 {
				x.target = c.cp0[30]
				c.cp0[status] &^= r4kERL
			} else {
				c.cp0[status] &^= r4kEXL
			}
			c.linked = false
		default:
			x.code = 10
		}
	default:
		x.code = 10
	}
}

func (c *r4kCPU) fpWord(reg uint32) uint32 {
	if c.cp0[status]&r4kFR == 0 && reg&1 != 0 {
		return uint32(c.fpr[reg-1] >> 32)
	}
	return uint32(c.fpr[reg])
}

func (c *r4kCPU) putFPWord(reg, value uint32) {
	base := reg
	shift := uint32(0)
	if c.cp0[status]&r4kFR == 0 && reg&1 != 0 {
		base, shift = reg-1, 32
	}
	c.fpr[base] = c.fpr[base]&^(uint64(0xffffffff)<<shift) | uint64(value)<<shift
}

func (c *r4kCPU) fpDoubleReg(reg uint32) uint32 {
	if c.cp0[status]&r4kFR == 0 {
		return reg &^ 1
	}
	return reg
}

func (c *r4kCPU) cop1(word, format, ft, fs uint32, x *r4kInstruction) {
	if c.cp0[status]&(1<<29) == 0 {
		x.code, x.coprocessor = 11, 1
		return
	}
	switch format {
	case 0:
		c.gpr[ft] = mipsWord(c.fpWord(fs))
	case 1:
		c.gpr[ft] = c.fpr[c.fpDoubleReg(fs)]
	case 2:
		var n uint32
		switch fs {
		case 0:
			n = 0x0500
		case 31:
			n = c.fcsr
		}
		c.gpr[ft] = mipsWord(n)
	case 4:
		c.putFPWord(fs, uint32(c.gpr[ft]))
	case 5:
		c.fpr[c.fpDoubleReg(fs)] = c.gpr[ft]
	case 6:
		if fs == 31 {
			c.fcsr = uint32(c.gpr[ft]) & 0x0183ffff
		}
	case 8:
		if ft > 3 {
			x.code = 10
			return
		}
		c.branch(x, (c.fcsr&(1<<23) != 0) == (ft&1 != 0), ft&2 != 0, uint64(int64(int16(word)))<<2)
	case 16, 17, 20, 21:
		c.fpOperation(word, format, ft, fs, x)
	default:
		x.code = 10
	}
}

func (c *r4kCPU) fpOperand(format, reg uint32) float64 {
	switch format {
	case 17:
		return math.Float64frombits(c.fpr[c.fpDoubleReg(reg)])
	case 20:
		return float64(int32(c.fpWord(reg)))
	case 21:
		return float64(int64(c.fpr[c.fpDoubleReg(reg)]))
	default:
		return float64(math.Float32frombits(c.fpWord(reg)))
	}
}

func (c *r4kCPU) fpFlags(flags uint32, x *r4kInstruction) bool {
	c.fcsr = c.fcsr&^(63<<12) | flags<<12
	enabled := c.fcsr >> 7 & 31
	c.fcsr |= (flags &^ enabled) << 2
	if flags&enabled != 0 {
		x.code = 15
		return false
	}
	return true
}

func (c *r4kCPU) fpOperation(word, format, ft, fs uint32, x *r4kInstruction) {
	fd, function := word>>6&31, word&63
	if format >= 20 && function != 32 && function != 33 {
		x.code = 10
		return
	}
	a := c.fpOperand(format, fs)
	b := c.fpOperand(format, ft)
	result, flags := a, uint32(0)
	double := format == 17
	switch function {
	case 0:
		result = a + b
	case 1:
		result = a - b
	case 2:
		result = a * b
	case 3:
		if b == 0 && !math.IsNaN(a) && !math.IsInf(a, 0) {
			flags = 8
			if a == 0 {
				flags = 16
			}
		}
		result = a / b
	case 4:
		if a < 0 {
			flags = 16
		}
		result = math.Sqrt(a)
	case 5:
		result = math.Abs(a)
	case 6:
		if double {
			c.fpr[c.fpDoubleReg(fd)] = c.fpr[c.fpDoubleReg(fs)]
		} else {
			c.putFPWord(fd, c.fpWord(fs))
		}
		return
	case 7:
		result = -a
	case 32, 33:
		double = function == 33
	case 8, 9, 10, 11, 12, 13, 14, 15, 36, 37:
		mode := c.fcsr & 3
		if function < 16 {
			mode = function & 3
		}
		switch mode {
		case 0:
			result = math.RoundToEven(a)
		case 1:
			result = math.Trunc(a)
		case 2:
			result = math.Ceil(a)
		case 3:
			result = math.Floor(a)
		}
		long := function == 37 || function < 12
		bound := float64(1 << 31)
		if long {
			bound = 1 << 63
		}
		n := uint64(bound) - 1
		if math.IsNaN(result) || result < -bound || result >= bound {
			flags = 16
		} else {
			n = uint64(int64(result))
			if result != a {
				flags = 1
			}
		}
		if c.fpFlags(flags, x) {
			if long {
				c.fpr[c.fpDoubleReg(fd)] = n
			} else {
				c.putFPWord(fd, uint32(n))
			}
		}
		return
	default:
		if function < 48 {
			x.code = 10
			return
		}
		unordered := math.IsNaN(a) || math.IsNaN(b)
		if unordered && function&8 != 0 {
			flags = 16
		}
		if c.fpFlags(flags, x) {
			set := unordered && function&1 != 0 || a == b && function&2 != 0 || a < b && function&4 != 0
			c.fcsr = c.fcsr&^(1<<23) | truth(set)<<23
		}
		return
	}
	if double {
		if c.fpFlags(flags, x) {
			c.fpr[c.fpDoubleReg(fd)] = math.Float64bits(result)
		}
		return
	}
	single := float32(result)
	if !math.IsNaN(result) && float64(single) != result {
		flags |= 1
		switch {
		case math.IsInf(float64(single), 0):
			flags |= 4
		case math.Abs(result) < 0x1p-126:
			flags |= 2
		}
	}
	if c.fpFlags(flags, x) {
		c.putFPWord(fd, math.Float32bits(single))
	}
}
