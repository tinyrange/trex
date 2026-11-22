package power

import (
	"fmt"
	"math"
	"math/bits"
)

func rotl64(v uint64, n uint) uint64 { return bits.RotateLeft64(v, int(n&63)) }

func rotl32(v uint64, n uint) uint64 {
	w := v & 0xffffffff
	return rotl64(w|w<<32, n)
}

// Mask returns the Power ISA MASK(mb, me) with bit 0 most significant.
func Mask(mb, me uint) uint64 {
	a := ^uint64(0) >> mb
	b := ^uint64(0) << (63 - me)
	if mb <= me {
		return a & b
	}
	return a | b
}

func (c *CPU) ra0(ra uint32) uint64 {
	if ra == 0 {
		return 0
	}
	return c.GPR[ra]
}

func (c *CPU) setCA(ca, ca32 bool) {
	c.XER &^= XERCA | XERCA32
	if ca {
		c.XER |= XERCA
	}
	if ca32 {
		c.XER |= XERCA32
	}
}

func (c *CPU) setOV(ov, ov32 bool) {
	c.XER &^= XEROV | XEROV32
	if ov {
		c.XER |= XEROV | XERSO
	}
	if ov32 {
		c.XER |= XEROV32
	}
}

// add returns a+b+carry and the 64- and 32-bit carries and overflows.
func add3(a, b, ci uint64) (r uint64, ca, ca32, ov, ov32 bool) {
	r, c1 := bits.Add64(a, b, ci)
	ca = c1 != 0
	ca32 = (a&0xffffffff)+(b&0xffffffff)+ci > 0xffffffff
	ov = (^(a^b)&(a^r))>>63 != 0
	ov32 = (^(a^b)&(a^r))>>31&1 != 0
	return
}

func (c *CPU) branchTarget(t uint64) uint64 { return c.mask(t) }

func (c *CPU) condition(bo, bi uint32, decrement bool) bool {
	if decrement && bo&4 == 0 {
		c.CTR--
		ctr := c.CTR
		if c.MSR&MSRSF == 0 {
			ctr &= 0xffffffff
		}
		if (ctr != 0) == (bo&2 != 0) {
			return false
		}
	}
	return bo&16 != 0 || c.CRBit(uint(bi)) == (bo&8 != 0)
}

func trapCondition(to uint32, a, b int64) bool {
	return to&16 != 0 && a < b || to&8 != 0 && a > b || to&4 != 0 && a == b ||
		to&2 != 0 && uint64(a) < uint64(b) || to&1 != 0 && uint64(a) > uint64(b)
}

func (c *CPU) exec(w uint32) {
	po := w >> 26
	rt, ra, rb := (w>>21)&31, (w>>16)&31, (w>>11)&31
	si := uint64(int64(int16(w)))
	ui := uint64(w & 0xffff)
	switch po {
	case 2: // tdi
		if trapCondition(rt, int64(c.GPR[ra]), int64(si)) {
			c.program(ProgTrap)
		}
	case 3: // twi
		if trapCondition(rt, int64(int32(c.GPR[ra])), int64(int32(si))) {
			c.program(ProgTrap)
		}
	case 7: // mulli
		c.GPR[rt] = c.GPR[ra] * si
	case 8: // subfic
		r, ca, ca32, _, _ := add3(^c.GPR[ra], si, 1)
		c.GPR[rt] = r
		c.setCA(ca, ca32)
	case 10: // cmpli
		bf := uint(rt >> 2)
		if rt&1 != 0 {
			c.compareFieldU(bf, c.GPR[ra], ui)
		} else {
			c.compareFieldU(bf, c.GPR[ra]&0xffffffff, ui)
		}
	case 11: // cmpi
		bf := uint(rt >> 2)
		if rt&1 != 0 {
			c.compareField(bf, int64(c.GPR[ra]), int64(si))
		} else {
			c.compareField(bf, int64(int32(c.GPR[ra])), int64(si))
		}
	case 12, 13: // addic, addic.
		r, ca, ca32, _, _ := add3(c.GPR[ra], si, 0)
		c.offsetCarry(c.GPR[ra], si, r)
		c.GPR[rt] = r
		c.setCA(ca, ca32)
		if po == 13 {
			c.setCR0(r)
		}
	case 14: // addi
		c.GPR[rt] = c.ra0(ra) + si
	case 15: // addis
		c.GPR[rt] = c.ra0(ra) + si<<16
	case 16: // bc
		bo, bi := rt, ra
		ok := c.condition(bo, bi, true)
		if w&1 != 0 {
			c.LR = c.nextPC
		}
		if ok {
			d := uint64(int64(int16(w & 0xfffc)))
			if w&2 != 0 {
				c.nextPC = c.branchTarget(d)
			} else {
				c.nextPC = c.branchTarget(c.PC + d)
			}
		}
	case 17: // sc / PowerPC AS scv
		lev := (w >> 5) & 0x7f
		if w&3 == 1 {
			if !c.m.as || c.MSR&MSRTA == 0 {
				c.illegal(w)
				return
			}
			// AS Book III 2.2.3, 7.5.15: this translated vector uses
			// LR/CTR, not SRR0/SRR1. EE, RI, ME and FP exception mode
			// survive; FP, PR, PMM, SE and BE are cleared.
			c.LR = c.mask(c.nextPC)
			c.CTR = c.MSR &^ uint64(0x783f0000)
			c.setMSR((c.MSR | MSRSF | MSRIR | MSRDR) &^ (MSRFP | MSRPR | 1<<61 | 1<<10 | 1<<9 | 0x783f0000))
			c.nextPC = 0xffffffffff003000 | uint64(lev)<<5
			c.resValid = false
			c.m.noteInterrupt(c, c.nextPC)
			return
		}
		if w&2 == 0 {
			c.illegal(w)
			return
		}
		if lev == 1 && c.MSR&MSRPR == 0 {
			c.hypercall()
			return
		}
		if lev == 0 || lev == 1 {
			c.Interrupt(VecSystemCall, c.nextPC, 0)
			return
		}
		c.illegal(w)
	case 18: // b
		d := uint64(int64(int32(w&0x03fffffc<<6) >> 6))
		if w&1 != 0 {
			c.LR = c.nextPC
		}
		if w&2 != 0 {
			c.nextPC = c.branchTarget(d)
		} else {
			c.nextPC = c.branchTarget(c.PC + d)
		}
	case 19:
		c.exec19(w)
	case 20: // rlwimi
		sh, mb, me := uint(rb), uint((w>>6)&31), uint((w>>1)&31)
		m := Mask(mb+32, me+32)
		r := rotl32(c.GPR[rt], sh)&m | c.GPR[ra]&^m
		c.GPR[ra] = r
		if w&1 != 0 {
			c.setCR0(r)
		}
	case 21, 23: // rlwinm, rlwnm
		sh := uint(rb)
		if po == 23 {
			sh = uint(c.GPR[rb] & 31)
		}
		mb, me := uint((w>>6)&31), uint((w>>1)&31)
		r := rotl32(c.GPR[rt], sh) & Mask(mb+32, me+32)
		c.GPR[ra] = r
		if w&1 != 0 {
			c.setCR0(r)
		}
	case 24: // ori
		c.GPR[ra] = c.GPR[rt] | ui
	case 25:
		c.GPR[ra] = c.GPR[rt] | ui<<16
	case 26:
		c.GPR[ra] = c.GPR[rt] ^ ui
	case 27:
		c.GPR[ra] = c.GPR[rt] ^ ui<<16
	case 28:
		c.GPR[ra] = c.GPR[rt] & ui
		c.setCR0(c.GPR[ra])
	case 29:
		c.GPR[ra] = c.GPR[rt] & (ui << 16)
		c.setCR0(c.GPR[ra])
	case 30:
		c.exec30(w)
	case 31:
		c.exec31(w)
	case 32, 33: // lwz, lwzu
		c.loadD(w, 4, false, po == 33)
	case 34, 35: // lbz, lbzu
		c.loadD(w, 1, false, po == 35)
	case 36, 37: // stw, stwu
		c.storeD(w, 4, po == 37)
	case 38, 39: // stb, stbu
		c.storeD(w, 1, po == 39)
	case 40, 41: // lhz, lhzu
		c.loadD(w, 2, false, po == 41)
	case 42, 43: // lha, lhau
		c.loadD(w, 2, true, po == 43)
	case 44, 45: // sth, sthu
		c.storeD(w, 2, po == 45)
	case 46: // lmw
		ea := c.ra0(ra) + si
		for r := rt; r < 32; r++ {
			v, ok := c.Load(ea, 4)
			if !ok {
				return
			}
			c.GPR[r] = v
			ea += 4
		}
	case 47: // stmw
		ea := c.ra0(ra) + si
		for r := rt; r < 32; r++ {
			if !c.Store(ea, 4, c.GPR[r]) {
				return
			}
			ea += 4
		}
	case 48, 49, 50, 51, 52, 53, 54, 55: // lfs lfsu lfd lfdu stfs stfsu stfd stfdu
		if !c.fpAvailable() {
			return
		}
		ea := c.ra0(ra) + si
		update := po&1 != 0
		switch po {
		case 48, 49:
			v, ok := c.Load(ea, 4)
			if !ok {
				return
			}
			c.FPR[rt] = math.Float64bits(float64(math.Float32frombits(uint32(v))))
		case 50, 51:
			v, ok := c.Load(ea, 8)
			if !ok {
				return
			}
			c.FPR[rt] = v
		case 52, 53:
			if !c.Store(ea, 4, uint64(math.Float32bits(float32(math.Float64frombits(c.FPR[rt]))))) {
				return
			}
		default:
			if !c.Store(ea, 8, c.FPR[rt]) {
				return
			}
		}
		if update {
			c.GPR[ra] = ea
		}
	case 56: // lq
		if rt&1 != 0 || rt == ra {
			c.illegal(w)
			return
		}
		ea := c.ra0(ra) + uint64(int64(int16(w&0xfff0)))
		if c.m.as && ea&15 != 0 {
			c.DAR = ea
			c.Interrupt(VecAlignment, c.PC, 0)
			return
		}
		hi, ok := c.Load(ea, 8)
		if !ok {
			return
		}
		lo, ok := c.Load(ea+8, 8)
		if !ok {
			return
		}
		c.GPR[rt], c.GPR[rt+1] = hi, lo
		if c.m.as {
			// AS Book I p43: lq replaces TGCC, preserving FXCC and all
			// other XER fields. PT selects the accepted pointer types.
			c.XER &^= XERT02 | XERT07 | XERTAG
			if c.m.tagAt(c, ea) {
				c.XER |= XERTAG
				pt := w & 15
				if hi&(uint64(1)<<61) == 0 && (uint32(8)>>(hi>>62))&pt != 0 {
					c.XER |= XERT02
				}
				if hi>>56 == uint64(0xa0|pt) {
					c.XER |= XERT07
				}
			}
		}
	case 58:
		ea := c.ra0(ra) + uint64(int64(int16(w&0xfffc)))
		switch w & 3 {
		case 0, 1: // ld, ldu
			v, ok := c.Load(ea, 8)
			if !ok {
				return
			}
			c.GPR[rt] = v
			if w&3 == 1 {
				c.GPR[ra] = ea
			}
		case 2: // lwa
			v, ok := c.Load(ea, 4)
			if !ok {
				return
			}
			c.GPR[rt] = uint64(int64(int32(v)))
		default:
			if c.m.as {
				c.multipleDoubleword(rt, ea, true)
				return
			}
			c.illegal(w)
		}
	case 59:
		c.exec59(w)
	case 62:
		ea := c.ra0(ra) + uint64(int64(int16(w&0xfffc)))
		switch w & 3 {
		case 0, 1: // std, stdu
			if !c.Store(ea, 8, c.GPR[rt]) {
				return
			}
			if w&3 == 1 {
				c.GPR[ra] = ea
			}
		case 2: // stq
			if rt&1 != 0 {
				c.illegal(w)
				return
			}
			if c.m.as && ea&15 != 0 {
				c.DAR = ea
				c.Interrupt(VecAlignment, c.PC, 0)
				return
			}
			if !c.Store(ea, 8, c.GPR[rt]) || !c.Store(ea+8, 8, c.GPR[rt+1]) {
				return
			}
			if c.m.as && c.XER&XERTAG != 0 {
				c.m.setTag(c, ea)
			}
		default:
			if c.m.as {
				c.multipleDoubleword(rt, ea, false)
				return
			}
			c.illegal(w)
		}
	case 63:
		c.exec63(w)
	default:
		c.illegal(w)
	}
}

func (c *CPU) loadD(w uint32, n int, signed, update bool) {
	rt, ra := (w>>21)&31, (w>>16)&31
	ea := c.ra0(ra) + uint64(int64(int16(w)))
	v, ok := c.Load(ea, n)
	if !ok {
		return
	}
	if signed {
		v = uint64(int64(int16(v)))
	}
	c.GPR[rt] = v
	if update {
		c.GPR[ra] = ea
	}
}

func (c *CPU) storeD(w uint32, n int, update bool) {
	rs, ra := (w>>21)&31, (w>>16)&31
	ea := c.ra0(ra) + uint64(int64(int16(w)))
	if !c.Store(ea, n, c.GPR[rs]) {
		return
	}
	if update {
		c.GPR[ra] = ea
	}
}

func (c *CPU) exec19(w uint32) {
	bt, ba, bb := uint((w>>21)&31), uint((w>>16)&31), uint((w>>11)&31)
	switch (w >> 1) & 0x3ff {
	case 0: // mcrf
		v := (c.CR >> (28 - 4*(ba>>2))) & 0xf
		c.SetCRField(bt>>2, v)
	case 16: // bclr
		target := c.LR &^ 3
		ok := c.condition(uint32(bt), uint32(ba), true)
		if w&1 != 0 {
			c.LR = c.nextPC
		}
		if ok {
			c.nextPC = c.branchTarget(target)
		}
	case 528: // bcctr
		target := c.CTR &^ 3
		ok := c.condition(uint32(bt), uint32(ba), false)
		if w&1 != 0 {
			c.LR = c.nextPC
		}
		if ok {
			c.nextPC = c.branchTarget(target)
		}
	case 18: // rfid
		if !c.privileged() {
			return
		}
		c.setMSR(c.SRR1)
		c.nextPC = c.mask(c.SRR0 &^ 3)
		c.resValid = false
	case 82: // PowerPC AS rfscv
		if !c.m.as || c.MSR&MSRTA == 0 {
			c.illegal(w)
			return
		}
		if !c.privileged() {
			return
		}
		// Restore full-function bits from CTR; setMSR preserves ME/HV
		// and forces relocation and EE when returning to problem state.
		c.setMSR(c.CTR &^ uint64(0x783f0000))
		c.nextPC = c.mask(c.LR &^ 3)
		c.resValid = false
	case 150: // isync
	case 257:
		c.SetCRBit(bt, c.CRBit(ba) && c.CRBit(bb))
	case 449:
		c.SetCRBit(bt, c.CRBit(ba) || c.CRBit(bb))
	case 193:
		c.SetCRBit(bt, c.CRBit(ba) != c.CRBit(bb))
	case 225:
		c.SetCRBit(bt, !(c.CRBit(ba) && c.CRBit(bb)))
	case 33:
		c.SetCRBit(bt, !(c.CRBit(ba) || c.CRBit(bb)))
	case 289:
		c.SetCRBit(bt, c.CRBit(ba) == c.CRBit(bb))
	case 129:
		c.SetCRBit(bt, c.CRBit(ba) && !c.CRBit(bb))
	case 417:
		c.SetCRBit(bt, c.CRBit(ba) || !c.CRBit(bb))
	default:
		c.illegal(w)
	}
}

func (c *CPU) exec30(w uint32) {
	rs, ra := (w>>21)&31, (w>>16)&31
	sh := uint((w>>11)&31) | uint((w>>1)&1)<<5
	mf := (w >> 5) & 63
	mb := uint(mf>>1 | (mf&1)<<5)
	var r uint64
	switch (w >> 2) & 7 {
	case 0: // rldicl
		r = rotl64(c.GPR[rs], sh) & Mask(mb, 63)
	case 1: // rldicr
		r = rotl64(c.GPR[rs], sh) & Mask(0, mb)
	case 2: // rldic
		r = rotl64(c.GPR[rs], sh) & Mask(mb, 63-sh)
	case 3: // rldimi
		m := Mask(mb, 63-sh)
		r = rotl64(c.GPR[rs], sh)&m | c.GPR[ra]&^m
	case 4:
		n := uint(c.GPR[(w>>11)&31] & 63)
		switch (w >> 1) & 0xf {
		case 8: // rldcl
			r = rotl64(c.GPR[rs], n) & Mask(mb, 63)
		case 9: // rldcr
			r = rotl64(c.GPR[rs], n) & Mask(0, mb)
		default:
			c.illegal(w)
			return
		}
	case 6, 7:
		if !c.m.as || !c.conditionalSelect(w) {
			c.illegal(w)
		}
		return
	default:
		c.illegal(w)
		return
	}
	c.GPR[ra] = r
	if w&1 != 0 {
		c.setCR0(r)
	}
}

// conditionalSelect implements the PowerPC AS MDS-form selects. XBI names
// XER bit 32+XBI; compares update FXCC independently of their CR field.
// See PowerPC AS Book I v2.00 sections 3.2.2 and 3.3.11.
func (c *CPU) conditionalSelect(w uint32) bool {
	rs, ra, sh := (w>>21)&31, (w>>16)&31, (w>>11)&31
	xbi := (w >> 7) & 15
	if w&0x60 != 0 {
		return false
	}
	first, second := uint64(int64(int8(rs<<3)>>3)), uint64(int64(int8(sh<<3)>>3))
	if (w>>2)&7 == 7 {
		first = c.GPR[rs]
	}
	if (w>>1)&1 != 0 {
		second = c.GPR[sh]
	}
	if c.XER&(uint64(1)<<(31-xbi)) != 0 {
		c.GPR[ra] = first
	} else {
		c.GPR[ra] = second
	}
	if w&1 != 0 {
		c.setCR0(c.GPR[ra])
	}
	return true
}

// xoForms marks the nine-bit XO-form extended opcodes of primary opcode 31.
var xoForms = func() (t [512]bool) {
	for _, xo := range []uint32{8, 9, 10, 11, 40, 73, 75, 104, 136, 138, 200, 202, 232, 233, 234, 235, 266, 393, 395, 425, 427, 457, 459, 489, 491} {
		t[xo] = true
	}
	return
}()

// accessSize31 gives the operand size of the opcode-31 indexed storage
// accesses whose implementation is shared by size.
var accessSize31 = func() (t [1024]uint8) {
	for xo, n := range map[uint32]uint8{20: 4, 84: 8, 52: 1, 116: 2, // lwarx ldarx lbarx lharx
		150: 4, 214: 8, 694: 1, 726: 2, 182: 16, // stwcx. stdcx. stbcx. sthcx. stqcx.
		21: 8, 53: 8, 23: 4, 55: 4, 87: 1, 119: 1, 279: 2, 311: 2, 343: 2, 375: 2, 341: 4, 373: 4, // indexed loads
		149: 8, 181: 8, 151: 4, 183: 4, 215: 1, 247: 1, 407: 2, 439: 2, // indexed stores
		534: 4, 790: 2, 532: 8, 662: 4, 918: 2, 660: 8} { // byte-reversed
		t[xo] = n
	}
	return
}()

func (c *CPU) exec31(w uint32) {
	// AS TX-form has a six-bit extended opcode (36); the preceding four
	// bits select XER[32+XBI], rather than extending the opcode. UI is a
	// software trap parameter and does not participate in the predicate.
	// PowerPC AS Book I v2.00 p74.
	if c.m.as && (w>>1)&63 == 36 {
		to, xbi := (w>>21)&31, (w>>7)&15
		if to > 1 || w&1 != 0 {
			c.illegal(w)
			return
		}
		if (c.XER>>(31-xbi))&1 == uint64(to) {
			c.program(ProgTrap)
		}
		return
	}
	rt, ra, rb := (w>>21)&31, (w>>16)&31, (w>>11)&31
	rc := w&1 != 0
	if (w>>1)&0x1f == 15 { // isel
		if c.CRBit(uint((w >> 6) & 31)) {
			c.GPR[rt] = c.ra0(ra)
		} else {
			c.GPR[rt] = c.GPR[rb]
		}
		return
	}
	if (w>>2)&0x1ff == 413 { // sradi
		sh := uint(rb) | uint((w>>1)&1)<<5
		c.shiftRightAlgebraic(ra, rt, sh, 64, rc)
		return
	}
	if xo := (w >> 1) & 0x1ff; xoForms[xo] {
		c.execXO(w, xo)
		return
	}
	switch (w >> 1) & 0x3ff {
	case 51, 179: // mfvsrd/mtvsrd (XX1-form; bit0 extends VSR index, not Rc)
		if rb != 0 {
			c.illegal(w)
			return
		}
		idx := rt | (w&1)<<5
		// Power ISA2.07 Book I p110: the lower bank uses FP availability;
		// the upper bank uses Vector availability. MSR.VSX is not required.
		if idx < 32 {
			if !c.fpAvailable() {
				return
			}
		} else if c.MSR&MSRVEC == 0 {
			c.Interrupt(VecVecUnavail, c.PC, 0)
			return
		}
		value := c.readVSR(idx)
		if (w>>1)&0x3ff == 51 {
			c.GPR[ra] = value[0]
		} else {
			value[0] = c.GPR[ra]
			c.writeVSR(idx, value)
		}
		// Doubleword1 is architecturally undefined; retain its existing bits.
	case 64: // cmpla: PowerPC AS Compare Logical Addresses (Book I 3.3.9)
		if !c.m.as || rt&3 != 1 || rc {
			c.illegal(w)
			return
		}
		a, b := c.GPR[ra], c.GPR[rb]
		v := uint32(1) // incomparable, independent of XER[SO]
		if a>>48 == b>>48 && (a>>48 == 0 || a>>24 == b>>24) {
			switch {
			case a < b:
				v = 8
			case a > b:
				v = 4
			default:
				v = 2
			}
		}
		c.SetCRField(uint(rt>>2), v)
		c.XER = c.XER&^(uint64(15)<<24) | uint64(v)<<24
	case 0, 32: // cmp, cmpl
		bf, l := uint(rt>>2), rt&1 != 0
		a, b := c.GPR[ra], c.GPR[rb]
		if (w>>1)&0x3ff == 0 {
			if l {
				c.compareField(bf, int64(a), int64(b))
			} else {
				c.compareField(bf, int64(int32(a)), int64(int32(b)))
			}
		} else if l {
			c.compareFieldU(bf, a, b)
		} else {
			c.compareFieldU(bf, a&0xffffffff, b&0xffffffff)
		}
	case 4: // tw
		if c.m.as && c.MSR&MSRTA != 0 && (rt == 28 || rt == 30) {
			c.illegal(w)
			return
		}
		if trapCondition(rt, int64(int32(c.GPR[ra])), int64(int32(c.GPR[rb]))) {
			c.program(ProgTrap)
		}
	case 68: // td
		a, b := c.GPR[ra], c.GPR[rb]
		trap := trapCondition(rt, int64(a), int64(b))
		if c.m.as && c.MSR&MSRTA != 0 {
			// AS Book I, Trap Doubleword: TO28/30 compare logical
			// address regions instead of their ordinary TO bit union.
			if rt == 28 {
				trap = a>>48 != b>>48 || a>>48 != 0 && (a>>24 != b>>24 || int64(a) < int64(b))
			} else if rt == 29 && c.m.cfg.PVR>>16 == 0x004e {
				// POWER9 AS: TO 29 checks a forward index within the
				// base's 16 MiB segment. A zero base (no backing buffer)
				// traps for any nonzero length.
				trap = (b != 0 && b>>48 == 0) || a>>24 != b>>24 || a < b
			} else if rt == 30 {
				trap = a>>24 != b>>24 || int64(a) < int64(b) || a < b
			}
		}
		if trap {
			c.program(ProgTrap)
		}
	case 19: // mfcr, mfocrf
		if w&(1<<20) != 0 {
			fxm := (w >> 12) & 0xff
			var m uint32
			for i := 0; i < 8; i++ {
				if fxm&(0x80>>i) != 0 {
					m |= 0xf << (28 - 4*i)
				}
			}
			c.GPR[rt] = uint64(c.CR & m)
		} else {
			c.GPR[rt] = uint64(c.CR)
		}
	case 144: // mtcrf, mtocrf
		fxm := (w >> 12) & 0xff
		var m uint32
		for i := 0; i < 8; i++ {
			if fxm&(0x80>>i) != 0 {
				m |= 0xf << (28 - 4*i)
			}
		}
		c.CR = c.CR&^m | uint32(c.GPR[rt])&m
	case 83: // mfmsr
		if c.privileged() {
			c.GPR[rt] = c.MSR
		}
	case 146: // mtmsr
		if c.privileged() {
			if w&(1<<16) != 0 {
				c.setMSR(c.MSR&^(MSREE|MSRRI) | c.GPR[rt]&(MSREE|MSRRI))
			} else {
				c.setMSR(c.MSR&^0xffffffff | c.GPR[rt]&0xffffffff)
			}
		}
	case 178: // mtmsrd
		if c.privileged() {
			if w&(1<<16) != 0 {
				c.setMSR(c.MSR&^(MSREE|MSRRI) | c.GPR[rt]&(MSREE|MSRRI))
			} else {
				c.setMSR(c.GPR[rt])
			}
		}
	case 339, 371: // mfspr, mftb
		spr := int(rb<<5 | ra)
		if v, ok := c.mfspr(spr); ok {
			c.GPR[rt] = v
		}
	case 467: // mtspr
		c.mtspr(int(rb<<5|ra), c.GPR[rt])
	case 20, 84, 52, 116: // lwarx ldarx lbarx lharx
		n := int(accessSize31[(w>>1)&0x3ff])
		ea := c.ra0(ra) + c.GPR[rb]
		v, ok := c.Load(ea, n)
		if !ok {
			return
		}
		r, _ := c.Translate(ea, false, accessRead)
		c.reserve(r, n)
		c.GPR[rt] = v
	case 276: // lqarx
		ea := c.ra0(ra) + c.GPR[rb]
		hi, ok := c.Load(ea, 8)
		if !ok {
			return
		}
		lo, ok := c.Load(ea+8, 8)
		if !ok {
			return
		}
		r, _ := c.Translate(ea, false, accessRead)
		c.reserve(r, 16)
		c.GPR[rt], c.GPR[rt+1] = hi, lo
	case 150, 214, 694, 726, 182: // stwcx. stdcx. stbcx. sthcx. stqcx.
		n := int(accessSize31[(w>>1)&0x3ff])
		ea := c.ra0(ra) + c.GPR[rb]
		r, err := c.Translate(ea, false, accessWrite)
		// For differing operand addresses the ISA permits either result;
		// implement the POWER9 reservation at cache-line granularity.
		success := c.resValid && err == nil && r/reservationGranule == c.resAddr/reservationGranule
		c.resValid = false
		if success {
			ok := true
			if n == 16 {
				ok = c.Store(ea, 8, c.GPR[rt]) && c.Store(ea+8, 8, c.GPR[rt+1])
			} else {
				ok = c.Store(ea, n, c.GPR[rt])
			}
			if !ok {
				return
			}
		} else if err != nil {
			// Raise the storage interrupt the store would have taken.
			if _, ok := c.translate(ea, accessWrite); !ok {
				return
			}
		}
		v := uint32(0)
		if success {
			v = 2
		}
		if c.m.as {
			// AS conditional stores record success in FXCC as well as
			// CR0, clearing LT/GT/IC independently of XER[SO].
			c.XER = c.XER&^(uint64(15)<<24) | uint64(v)<<24
		}
		if c.XER&XERSO != 0 {
			v |= 1
		}
		c.SetCRField(0, v)
	case 21, 53, 23, 55, 87, 119, 279, 311, 343, 375, 341, 373: // indexed loads
		xo := (w >> 1) & 0x3ff
		n := int(accessSize31[xo])
		ea := c.ra0(ra) + c.GPR[rb]
		v, ok := c.Load(ea, n)
		if !ok {
			return
		}
		switch xo {
		case 343, 375:
			v = uint64(int64(int16(v)))
		case 341, 373:
			v = uint64(int64(int32(v)))
		}
		c.GPR[rt] = v
		if xo == 53 || xo == 55 || xo == 119 || xo == 311 || xo == 375 || xo == 373 {
			c.GPR[ra] = ea
		}
	case 149, 181, 151, 183, 215, 247, 407, 439: // indexed stores
		xo := (w >> 1) & 0x3ff
		n := int(accessSize31[xo])
		ea := c.ra0(ra) + c.GPR[rb]
		if !c.Store(ea, n, c.GPR[rt]) {
			return
		}
		if xo == 181 || xo == 183 || xo == 247 || xo == 439 {
			c.GPR[ra] = ea
		}
	case 534, 790, 532: // lwbrx lhbrx ldbrx
		n := int(accessSize31[(w>>1)&0x3ff])
		v, ok := c.Load(c.ra0(ra)+c.GPR[rb], n)
		if !ok {
			return
		}
		c.GPR[rt] = bits.ReverseBytes64(v) >> (64 - 8*n)
	case 662, 918, 660: // stwbrx sthbrx stdbrx
		n := int(accessSize31[(w>>1)&0x3ff])
		c.Store(c.ra0(ra)+c.GPR[rb], n, bits.ReverseBytes64(c.GPR[rt])>>(64-8*n))
	case 597, 725: // lswi, stswi
		n := int(rb)
		if n == 0 {
			n = 32
		}
		c.stringOp(w, c.ra0(ra), n, (w>>1)&0x3ff == 597)
	case 533, 661: // lswx, stswx
		c.stringOp(w, c.ra0(ra)+c.GPR[rb], int(c.XER&0x7f), (w>>1)&0x3ff == 533)
	case 499: // AS settag (Book I p96): set XER[43], independent of prior loads
		if !c.m.as || w != 0x7c0103e6 {
			c.illegal(w)
			return
		}
		c.XER |= XERTAG
	case 544: // AS mcrxrt BF (Book I p97): 0 || XER[41:43], non-destructive
		if !c.m.as || c.MSR&MSRTA == 0 || rt&3 != 0 || ra != 0 || rb != 0 || w&1 != 0 {
			c.illegal(w)
			return
		}
		c.SetCRField(uint(rt>>2), uint32(c.XER>>20)&7)
	case 93: // AS dtcs. RA,RS (Book I p94): decimal sign test and clear
		if !c.m.as || c.MSR&MSRTA == 0 || rb != 0 || !rc {
			c.illegal(w)
			return
		}
		value := c.GPR[rt]
		// B and D are the two negative packed-decimal sign encodings.
		// Every other nibble denotes positive, including a zero magnitude.
		sign := int64(1)
		if value&15 == 0xb || value&15 == 0xd {
			sign = -1
		}
		c.compareField(0, sign, 0)
		c.GPR[ra] = value &^ 15
		c.XER &^= XERCA
	case 61: // AS dsixes RA (Book I p94)
		if !c.m.as || c.MSR&MSRTA == 0 || rt != 0 || rb != 0 || rc {
			c.illegal(w)
			return
		}
		c.GPR[ra] = c.decimalSixes()
	case 629, 757: // AS lsdi, stsdi (Book I §3.3.6)
		n := int(rb)
		if n == 0 {
			n = 32
		}
		load := (w>>1)&0x3ff == 629
		if !c.m.as || c.MSR&MSRTA == 0 || rc || (load && int((ra-rt)&31) < (n+7)/8) {
			c.illegal(w)
			return
		}
		c.stringDoubleword(rt, c.ra0(ra), n, load)
	case 565, 693: // AS: load/store string doubleword indexed (length in XER)
		if !c.m.as {
			c.illegal(w)
			return
		}
		c.stringDoubleword(rt, c.ra0(ra)+c.GPR[rb], int(c.XER&0x7f), (w>>1)&0x3ff == 565)
	case 24, 27, 536, 539: // slw sld srw srd
		xo := (w >> 1) & 0x3ff
		n := c.GPR[rb]
		var r uint64
		switch xo {
		case 24:
			if n&32 == 0 {
				r = (c.GPR[rt] << (n & 31)) & 0xffffffff
			}
		case 27:
			if n&64 == 0 {
				r = c.GPR[rt] << (n & 63)
			}
		case 536:
			if n&32 == 0 {
				r = (c.GPR[rt] & 0xffffffff) >> (n & 31)
			}
		case 539:
			if n&64 == 0 {
				r = c.GPR[rt] >> (n & 63)
			}
		}
		c.GPR[ra] = r
		if rc {
			c.setCR0(r)
		}
	case 792: // sraw
		n := uint(c.GPR[rb] & 63)
		if n > 32 {
			n = 32
		}
		c.shiftRightAlgebraic(ra, rt, n, 32, rc)
	case 794: // srad
		n := uint(c.GPR[rb] & 127)
		if n > 64 {
			n = 64
		}
		c.shiftRightAlgebraic(ra, rt, n, 64, rc)
	case 824: // srawi
		c.shiftRightAlgebraic(ra, rt, uint(rb), 32, rc)
	case 26: // cntlzw
		c.logical(ra, uint64(bits.LeadingZeros32(uint32(c.GPR[rt]))), rc)
	case 58:
		c.logical(ra, uint64(bits.LeadingZeros64(c.GPR[rt])), rc)
	case 538:
		c.logical(ra, uint64(bits.TrailingZeros32(uint32(c.GPR[rt]))), rc)
	case 570:
		c.logical(ra, uint64(bits.TrailingZeros64(c.GPR[rt])), rc)
	case 122: // popcntb
		var r uint64
		for i := 0; i < 64; i += 8 {
			r |= uint64(bits.OnesCount8(uint8(c.GPR[rt]>>i))) << i
		}
		c.GPR[ra] = r
	case 378:
		v := c.GPR[rt]
		c.GPR[ra] = uint64(bits.OnesCount32(uint32(v>>32)))<<32 | uint64(bits.OnesCount32(uint32(v)))
	case 506:
		c.GPR[ra] = uint64(bits.OnesCount64(c.GPR[rt]))
	case 186: // prtyd
		var p uint64
		for i := 0; i < 64; i += 8 {
			p ^= c.GPR[rt] >> i & 1
		}
		c.GPR[ra] = p
	case 508: // cmpb
		var r uint64
		for i := 0; i < 64; i += 8 {
			if byte(c.GPR[rt]>>i) == byte(c.GPR[rb]>>i) {
				r |= 0xff << i
			}
		}
		c.GPR[ra] = r
	case 252: // bpermd
		var r uint64
		for i := 0; i < 8; i++ {
			idx := c.GPR[rt] >> (56 - 8*i) & 0xff
			if idx < 64 && c.GPR[rb]&(1<<(63-idx)) != 0 {
				r |= 1 << (7 - i)
			}
		}
		c.GPR[ra] = r
	case 28:
		c.logical(ra, c.GPR[rt]&c.GPR[rb], rc)
	case 60:
		c.logical(ra, c.GPR[rt]&^c.GPR[rb], rc)
	case 124:
		c.logical(ra, ^(c.GPR[rt] | c.GPR[rb]), rc)
	case 284:
		c.logical(ra, ^(c.GPR[rt] ^ c.GPR[rb]), rc)
	case 316:
		c.logical(ra, c.GPR[rt]^c.GPR[rb], rc)
	case 412:
		c.logical(ra, c.GPR[rt]|^c.GPR[rb], rc)
	case 444:
		c.logical(ra, c.GPR[rt]|c.GPR[rb], rc)
	case 476:
		c.logical(ra, ^(c.GPR[rt] & c.GPR[rb]), rc)
	case 922:
		c.logical(ra, uint64(int64(int16(c.GPR[rt]))), rc)
	case 954:
		c.logical(ra, uint64(int64(int8(c.GPR[rt]))), rc)
	case 986:
		c.logical(ra, uint64(int64(int32(c.GPR[rt]))), rc)
	case 265, 777, 267, 779: // modud modsd moduw modsw
		a, b := c.GPR[ra], c.GPR[rb]
		var r uint64
		switch (w >> 1) & 0x3ff {
		case 265:
			if b != 0 {
				r = a % b
			}
		case 777:
			if b != 0 && !(int64(a) == math.MinInt64 && int64(b) == -1) {
				r = uint64(int64(a) % int64(b))
			}
		case 267:
			if uint32(b) != 0 {
				r = uint64(uint32(a) % uint32(b))
			}
		case 779:
			if int32(b) != 0 && !(int32(a) == math.MinInt32 && int32(b) == -1) {
				r = uint64(int64(int32(a) % int32(b)))
			}
		}
		c.GPR[rt] = r
	case 128: // setb
		v := (c.CR >> (28 - 4*(ra>>2))) & 0xf
		switch {
		case v&8 != 0:
			c.GPR[rt] = ^uint64(0)
		case v&4 != 0:
			c.GPR[rt] = 1
		default:
			c.GPR[rt] = 0
		}
	case 86, 54, 278, 246, 982, 598, 854, 30, 62: // dcbf dcbst dcbt dcbtst icbi sync eieio wait
	case 1014: // dcbz
		ea := (c.ra0(ra) + c.GPR[rb]) &^ 127
		for i := uint64(0); i < 128; i += 8 {
			if !c.Store(ea+i, 8, 0) {
				return
			}
		}
	case 402: // slbmte
		if !c.privileged() {
			return
		}
		if c.SLBMTE(c.GPR[rt], c.GPR[rb]) != nil {
			c.program(ProgIllegal)
		}
	case 434: // slbie
		if !c.privileged() {
			return
		}
		ea := c.GPR[rb]
		for i, e := range c.SLB {
			if e.Valid && e.ESID == ea>>e.segmentShift() {
				e.Valid = false
				c.setSLB(i, e)
			}
		}
		c.tlbGen++
	case 498: // slbia
		if !c.privileged() {
			return
		}
		for i := 1; i < len(c.SLB); i++ {
			e := c.SLB[i]
			e.Valid = false
			c.setSLB(i, e)
		}
		c.tlbGen++
	case 915, 851: // slbmfee, slbmfev
		if !c.privileged() {
			return
		}
		e := c.SLB[c.GPR[rb]&63]
		if (w>>1)&0x3ff == 915 {
			v := e.ESID << e.segmentShift()
			if e.Valid {
				v |= 1 << 27
			}
			c.GPR[rt] = v
		} else {
			c.GPR[rt] = uint64(e.B)<<62 | e.VSID<<12 | e.Flags
		}
	case 979: // slbfee.
		if !c.privileged() {
			return
		}
		e, ok := c.FindSLB(c.GPR[rb])
		v := uint32(0)
		c.GPR[rt] = 0
		if ok {
			c.GPR[rt] = uint64(e.B)<<62 | e.VSID<<12 | e.Flags
			v = 2
		}
		if c.XER&XERSO != 0 {
			v |= 1
		}
		c.SetCRField(0, v)
	case 274, 566: // tlbiel, tlbsync: translation caches are host-owned
		if c.privileged() {
			c.tlbGen++
		}
	case 142: // msgsndp
		if c.privileged() {
			c.m.Event("doorbell", c, fmt.Sprintf("%x", c.GPR[rb]))
		}
	case 103, 359, 844, 780, 268, 300: // lvx lvxl lxvd2x lxvw4x lxvx (bit 25 reserved)
		c.vectorLoadStore(w, true)
	case 231, 487, 972, 908, 396, 428: // stvx stvxl stxvd2x stxvw4x stxvx
		c.vectorLoadStore(w, false)
	case 535, 567, 599, 631, 663, 695, 727, 759: // lfsx lfsux lfdx lfdux stfsx stfsux stfdx stfdux
		if !c.fpAvailable() {
			return
		}
		xo := (w >> 1) & 0x3ff
		ea := c.ra0(ra) + c.GPR[rb]
		switch xo {
		case 535, 567:
			v, ok := c.Load(ea, 4)
			if !ok {
				return
			}
			c.FPR[rt] = math.Float64bits(float64(math.Float32frombits(uint32(v))))
		case 599, 631:
			v, ok := c.Load(ea, 8)
			if !ok {
				return
			}
			c.FPR[rt] = v
		case 663, 695:
			if !c.Store(ea, 4, uint64(math.Float32bits(float32(math.Float64frombits(c.FPR[rt]))))) {
				return
			}
		default:
			if !c.Store(ea, 8, c.FPR[rt]) {
				return
			}
		}
		if xo&32 != 0 {
			c.GPR[ra] = ea
		}
	default:
		c.illegal(w)
	}
}

func (c *CPU) logical(ra uint32, v uint64, rc bool) {
	c.GPR[ra] = v
	if rc {
		c.setCR0(v)
	}
}

func (c *CPU) shiftRightAlgebraic(ra, rs uint32, n uint, width int, rc bool) {
	var v int64
	if width == 32 {
		v = int64(int32(c.GPR[rs]))
	} else {
		v = int64(c.GPR[rs])
	}
	var r int64
	var lost uint64
	if n >= uint(width) {
		r, lost = v>>63, uint64(v)
	} else {
		r, lost = v>>n, uint64(v)&(1<<n-1)
	}
	ca := v < 0 && lost != 0
	c.GPR[ra] = uint64(r)
	c.setCA(ca, ca)
	if rc {
		c.setCR0(uint64(r))
	}
}

func (c *CPU) execXO(w uint32, xo uint32) {
	rt, ra, rb := (w>>21)&31, (w>>16)&31, (w>>11)&31
	oe, rc := w&(1<<10) != 0, w&1 != 0
	a, b := c.GPR[ra], c.GPR[rb]
	ca := c.XER >> 29 & 1
	var r uint64
	var carry, carry32, ov, ov32, setCarry bool
	switch xo {
	case 266: // add
		r, _, _, ov, ov32 = add3(a, b, 0)
	case 40: // subf
		r, _, _, ov, ov32 = add3(^a, b, 1)
	case 10: // addc
		r, carry, carry32, ov, ov32 = add3(a, b, 0)
		c.decimalCarries(a, b, r)
		c.offsetCarry(a, b, r)
		setCarry = true
	case 8: // subfc
		r, carry, carry32, ov, ov32 = add3(^a, b, 1)
		c.decimalCarries(^a, b, r)
		setCarry = true
	case 138: // adde
		r, carry, carry32, ov, ov32 = add3(a, b, ca)
		setCarry = true
	case 136: // subfe
		r, carry, carry32, ov, ov32 = add3(^a, b, ca)
		setCarry = true
	case 202: // addze
		r, carry, carry32, ov, ov32 = add3(a, 0, ca)
		setCarry = true
	case 200: // subfze
		r, carry, carry32, ov, ov32 = add3(^a, 0, ca)
		setCarry = true
	case 234: // addme
		r, carry, carry32, ov, ov32 = add3(a, ^uint64(0), ca)
		setCarry = true
	case 232: // subfme
		r, carry, carry32, ov, ov32 = add3(^a, ^uint64(0), ca)
		setCarry = true
	case 104: // neg
		r = -a
		ov = a == 1<<63
		ov32 = uint32(a) == 1<<31
	case 233: // mulld
		hi, lo := bits.Mul64(a, b)
		r = lo
		sh := int64(hi)
		if int64(a) < 0 {
			sh -= int64(b)
		}
		if int64(b) < 0 {
			sh -= int64(a)
		}
		ov = !(sh == 0 && int64(lo) >= 0 || sh == -1 && int64(lo) < 0)
		ov32 = ov
	case 235: // mullw
		p := int64(int32(a)) * int64(int32(b))
		r = uint64(p)
		ov = p != int64(int32(p))
		ov32 = ov
	case 73: // mulhd
		hi, _ := bits.Mul64(a, b)
		if int64(a) < 0 {
			hi -= b
		}
		if int64(b) < 0 {
			hi -= a
		}
		r = hi
	case 9: // mulhdu
		r, _ = bits.Mul64(a, b)
	case 75: // mulhw
		r = uint64(int64(int32(a))*int64(int32(b))) >> 32 & 0xffffffff
	case 11: // mulhwu
		r = (a & 0xffffffff) * (b & 0xffffffff) >> 32
	case 489: // divd
		if b == 0 || int64(a) == math.MinInt64 && int64(b) == -1 {
			ov = true
		} else {
			r = uint64(int64(a) / int64(b))
		}
		ov32 = ov
	case 457: // divdu
		if b == 0 {
			ov = true
		} else {
			r = a / b
		}
		ov32 = ov
	case 491: // divw
		if int32(b) == 0 || int32(a) == math.MinInt32 && int32(b) == -1 {
			ov = true
		} else {
			r = uint64(uint32(int32(a) / int32(b)))
		}
		ov32 = ov
	case 459: // divwu
		if uint32(b) == 0 {
			ov = true
		} else {
			r = uint64(uint32(a) / uint32(b))
		}
		ov32 = ov
	case 393: // divdeu
		if b == 0 || a >= b {
			ov = true
		} else {
			r, _ = bits.Div64(a, 0, b)
		}
		ov32 = ov
	case 425: // divde
		q, ok := divde(int64(a), int64(b))
		r, ov, ov32 = uint64(q), !ok, !ok
	default:
		c.illegal(w)
		return
	}
	c.GPR[rt] = r
	if setCarry {
		c.setCA(carry, carry32)
	}
	if oe {
		c.setOV(ov, ov32)
	}
	if rc {
		c.setCR0(r)
	}
}

func divde(a, b int64) (int64, bool) {
	if b == 0 {
		return 0, false
	}
	neg := (a < 0) != (b < 0)
	ua, ub := uint64(a), uint64(b)
	if a < 0 {
		ua = uint64(-a)
	}
	if b < 0 {
		ub = uint64(-b)
	}
	if ua >= ub {
		return 0, false
	}
	q, _ := bits.Div64(ua, 0, ub)
	if neg {
		if q > 1<<63 {
			return 0, false
		}
		return -int64(q), true
	}
	if q >= 1<<63 {
		return 0, false
	}
	return int64(q), true
}

func (c *CPU) stringOp(w uint32, ea uint64, n int, load bool) {
	r := (w >> 21) & 31
	for i := 0; i < n; i++ {
		shift := uint(24 - 8*(i%4))
		if load {
			if i%4 == 0 {
				c.GPR[r] = 0
			}
			b, ok := c.Load(ea, 1)
			if !ok {
				return
			}
			c.GPR[r] |= b << shift
		} else if !c.Store(ea, 1, c.GPR[r]>>shift) {
			return
		}
		ea++
		if i%4 == 3 {
			r = (r + 1) & 31
		}
	}
}

// multipleDoubleword loads or stores registers rt..31 as consecutive
// doublewords (PowerPC AS lmd/stmd). Loads complete only if every access does.
func (c *CPU) multipleDoubleword(rt uint32, ea uint64, load bool) {
	var vals [32]uint64
	for r := rt; r < 32; r++ {
		if load {
			v, ok := c.Load(ea, 8)
			if !ok {
				return
			}
			vals[r] = v
		} else if !c.Store(ea, 8, c.GPR[r]) {
			return
		}
		ea += 8
	}
	if load {
		copy(c.GPR[rt:], vals[rt:])
	}
}

// stringDoubleword moves n bytes between storage and consecutive registers
// starting at r, eight bytes per register, left-justified; a partially
// filled register's remaining low-order bytes are zero (PowerPC AS lsdx/stsdx).
func (c *CPU) stringDoubleword(r uint32, ea uint64, n int, load bool) {
	for i := 0; i < n; i++ {
		shift := uint(56 - 8*(i%8))
		if load {
			if i%8 == 0 {
				c.GPR[r] = 0
			}
			b, ok := c.Load(ea, 1)
			if !ok {
				return
			}
			c.GPR[r] |= b << shift
		} else if !c.Store(ea, 1, c.GPR[r]>>shift) {
			return
		}
		ea++
		if i%8 == 7 {
			r = (r + 1) & 31
		}
	}
}

func (c *CPU) fpAvailable() bool {
	if c.MSR&MSRFP == 0 {
		c.Interrupt(VecFPUnavailable, c.PC, 0)
		return false
	}
	return true
}

func (c *CPU) vectorLoadStore(w uint32, load bool) {
	xo := (w >> 1) & 0x3ff
	t := (w >> 21) & 31
	vsx := xo == 844 || xo == 780 || xo == 268 || xo == 300 || xo == 972 || xo == 908 || xo == 396 || xo == 428
	idx := t + 32
	if vsx {
		idx = t | (w&1)<<5
		if c.MSR&MSRVSX == 0 {
			c.Interrupt(VecVSXUnavail, c.PC, 0)
			return
		}
	} else if c.MSR&MSRVEC == 0 {
		c.Interrupt(VecVecUnavail, c.PC, 0)
		return
	}
	ea := c.ra0((w>>16)&31) + c.GPR[(w>>11)&31]
	if !vsx {
		ea &^= 15
	}
	if load {
		hi, ok := c.Load(ea, 8)
		if !ok {
			return
		}
		lo, ok := c.Load(ea+8, 8)
		if !ok {
			return
		}
		c.writeVSR(idx, [2]uint64{hi, lo})
		return
	}
	value := c.readVSR(idx)
	if c.Store(ea, 8, value[0]) {
		c.Store(ea+8, 8, value[1])
	}
}

func userReadableSPR(n int) bool {
	switch n {
	case 1, 3, 8, 9, 13, 256, 259, 268, 269,
		769, 770, 771, 772, 773, 774, 775, 776, 779, 780, 781, 782,
		800, 801, 802, 804, 805, 806:
		return true
	}
	return false
}

// mfspr reads an SPR, raising a privileged-instruction interrupt from problem state.
func (c *CPU) mfspr(n int) (uint64, bool) {
	if n&0x10 != 0 && c.MSR&MSRPR != 0 && !userReadableSPR(n) {
		c.program(ProgPrivileged)
		return 0, false
	}
	switch n {
	case 1:
		return c.XER, true
	case 8:
		return c.LR, true
	case 9:
		return c.CTR, true
	case 18:
		return uint64(c.DSISR), true
	case 19:
		return c.DAR, true
	case 22:
		return c.DEC(), true
	case 26:
		return c.SRR0, true
	case 27:
		return c.SRR1, true
	case 268:
		return c.m.TB(), true
	case 269:
		return c.m.TB() >> 32, true
	case 848: // IC: virtual instruction count
		return c.Instructions + c.icOffset, true
	case 849: // VTB: virtual time base
		return c.m.TB() + c.vtbOffset, true
	case 308: // SPURR/PURR: fixed-frequency virtual CPU utilization
		return c.Instructions*512/uint64(c.m.cfg.MIPS) + c.spurrOffset, true
	case 309:
		return c.Instructions*512/uint64(c.m.cfg.MIPS) + c.purrOffset, true
	case 152:
		return c.ctrl, true
	case 272, 273, 274, 275:
		return c.SPRG[n-272], true
	case 259:
		return c.SPRG[3], true
	case 287:
		return uint64(c.m.cfg.PVR), true
	case 1023:
		return uint64(c.Index), true
	case 136:
		return c.ctrl, true
	}
	v, ok := c.SPR[n]
	if !ok && c.m.eventRoom() {
		c.m.Event("spr-read", c, fmt.Sprintf("%d", n))
	}
	return v, true
}

// mtspr writes an SPR. Only DEC changes interrupt timing (SetDEC ends the
// unchecked run); the others are plain state.
func (c *CPU) mtspr(n int, v uint64) {
	if n&0x10 != 0 && c.MSR&MSRPR != 0 {
		c.program(ProgPrivileged)
		return
	}
	switch n {
	case 1:
		if c.m.as {
			// AS keeps decimal carries and condition/type fields, including
			// FXCC, across explicit XER save/restore. Bits0:15 are reserved.
			c.XER = v & 0x0000ffffffff007f
		} else {
			c.XER = v & (XERSO | XEROV | XERCA | XEROV32 | XERCA32 | 0x7f)
		}
	// These fields mirror their SPR map entries for native blocks.
	case 848:
		c.icOffset = v - c.Instructions
		c.SPR[n] = c.icOffset
	case 849:
		c.vtbOffset = v - c.m.TB()
		c.SPR[n] = c.vtbOffset
	case 308:
		c.spurrOffset = v - c.Instructions*512/uint64(c.m.cfg.MIPS)
		c.SPR[n] = c.spurrOffset
	case 309:
		c.purrOffset = v - c.Instructions*512/uint64(c.m.cfg.MIPS)
		c.SPR[n] = c.purrOffset
	case 152:
		// CTRL is mirrored in c.ctrl only (mfspr 136/152 read it), so
		// native blocks can write it.
		c.ctrl = v
	case 8:
		c.LR = v
	case 9:
		c.CTR = v
	case 18:
		c.DSISR = uint32(v)
	case 19:
		c.DAR = v
	case 22:
		c.SetDEC(v)
	case 26:
		c.SRR0 = v
	case 27:
		c.SRR1 = v
	case 272, 273, 274, 275:
		c.SPRG[n-272] = v
	default:
		if _, ok := c.SPR[n]; !ok && c.m.eventRoom() {
			c.m.Event("spr-write", c, fmt.Sprintf("%d=%x", n, v))
		}
		c.SPR[n] = v
	}
}

func (c *CPU) exec59(w uint32) {
	if !c.fpAvailable() {
		return
	}
	if (w>>1)&0xff == 3 { // dqua / dquaq
		c.quantizeDecimal(w, false)
		return
	}
	switch (w >> 1) & 0x3ff {
	case 770: // drsp
		c.roundDecimalToShort(w)
		return
	case 258: // dctdp
		c.decimalShortToLong(w)
		return
	case 642: // dcmpu
		c.compareDecimalUnordered(w, false)
		return
	}
	t, a, b, cc := (w>>21)&31, (w>>16)&31, (w>>11)&31, (w>>6)&31
	fa, fb, fc := math.Float64frombits(c.FPR[a]), math.Float64frombits(c.FPR[b]), math.Float64frombits(c.FPR[cc])
	var r float64
	switch (w >> 1) & 0x1f {
	case 18:
		r = fa / fb
	case 20:
		r = fa - fb
	case 21:
		r = fa + fb
	case 25:
		r = fa * fc
	case 28:
		r = fa*fc - fb
	case 29:
		r = fa*fc + fb
	case 30:
		r = -(fa*fc - fb)
	case 31:
		r = -(fa*fc + fb)
	default:
		if (w>>1)&0x3ff == 846 { // fcfids
			r = float64(int64(c.FPR[b]))
			break
		}
		c.illegal(w)
		return
	}
	c.FPR[t] = math.Float64bits(float64(float32(r)))
}

func (c *CPU) exec63(w uint32) {
	if !c.fpAvailable() {
		return
	}
	if (w>>1)&0xff == 3 { // dqua / dquaq
		c.quantizeDecimal(w, true)
		return
	}
	if (w>>1)&0x3ff == 642 { // dcmpuq
		c.compareDecimalUnordered(w, true)
		return
	}
	t, a, b, cc := (w>>21)&31, (w>>16)&31, (w>>11)&31, (w>>6)&31
	fa, fb, fc := math.Float64frombits(c.FPR[a]), math.Float64frombits(c.FPR[b]), math.Float64frombits(c.FPR[cc])
	set := func(v float64) { c.FPR[t] = math.Float64bits(v) }
	switch (w >> 1) & 0x1f {
	case 18:
		set(fa / fb)
		return
	case 20:
		set(fa - fb)
		return
	case 21:
		set(fa + fb)
		return
	case 22:
		set(math.Sqrt(fb))
		return
	case 23: // fsel
		if fa >= 0 {
			set(fc)
		} else {
			set(fb)
		}
		return
	case 25:
		set(fa * fc)
		return
	case 28:
		set(fa*fc - fb)
		return
	case 29:
		set(math.FMA(fa, fc, fb))
		return
	case 30:
		set(-(fa*fc - fb))
		return
	case 31:
		set(-(fa*fc + fb))
		return
	}
	switch (w >> 1) & 0x3ff {
	case 0, 32: // fcmpu, fcmpo
		v := uint32(1)
		switch {
		case fa < fb:
			v = 8
		case fa > fb:
			v = 4
		case fa == fb:
			v = 2
		}
		c.SetCRField(uint(t>>2), v)
	case 8: // fcpsgn: copy bits, including signaling NaN payloads
		c.FPR[t] = c.FPR[b]&0x7fffffffffffffff | c.FPR[a]&0x8000000000000000
		c.fpRecord(w)
	case 72:
		c.FPR[t] = c.FPR[b]
	case 40:
		c.FPR[t] = c.FPR[b] ^ 1<<63
	case 264:
		c.FPR[t] = c.FPR[b] &^ (1 << 63)
	case 136:
		c.FPR[t] = c.FPR[b] | 1<<63
	case 12: // frsp
		set(float64(float32(fb)))
	case 15, 14: // fctiwz, fctiw
		set(math.Float64frombits(uint64(uint32(int32(clampInt(math.Trunc(fb), math.MinInt32, math.MaxInt32))))))
	case 815, 814: // fctidz, fctid
		c.FPR[t] = uint64(int64(clampInt(math.Trunc(fb), math.MinInt64, math.MaxInt64)))
	case 846: // fcfid
		set(float64(int64(c.FPR[b])))
	case 974: // fcfidu
		c.convertFromUnsigned(w)
	case 943, 143, 142: // fctiduz, fctiwuz, fctiwu
		c.convertToUnsigned(w)
	case 488: // frim
		c.roundToIntegral(w, math.Floor)
	case 456: // frip
		c.roundToIntegral(w, math.Ceil)
	case 424: // friz
		c.roundToIntegral(w, math.Trunc)
	case 392: // frin: nearest integer, ties away from zero, independent of RN
		c.roundToIntegral(w, math.Round)
	case 583: // mffs
		c.FPR[t] = c.FPSCR
	case 711: // mtfsf
		c.FPSCR = c.FPR[b] & 0xffffffff
	case 70: // mtfsb0 (VX/FEX are read-only summaries)
		if t != 1 && t != 2 {
			c.FPSCR &^= uint64(1) << (31 - t)
		}
		c.fpSummaries()
		c.fpRecord(w)
	case 38, 134, 64: // mtfsb1 mtfsfi mcrfs: exceptions are not modelled
	default:
		c.illegal(w)
	}
}

func clampInt(v, lo, hi float64) float64 {
	if math.IsNaN(v) || v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
