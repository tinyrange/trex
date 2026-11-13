package s390

// Instruction decoding helpers. Instruction bytes are held in c.op (up to 6).

var ilenTable = [4]uint32{2, 4, 4, 6}

func ilen(op byte) uint32 { return ilenTable[op>>6] }

func (c *CPU) gr(r int) uint32 {
	if r == 0 {
		return 0
	}
	return c.GR[r]
}

// eaRX computes X2+B2+D2 for RX format.
func (c *CPU) eaRX(op []byte) uint32 {
	x := int(op[1] & 0xf)
	b := int(op[2] >> 4)
	d := uint32(op[2]&0xf)<<8 | uint32(op[3])
	return (c.gr(x) + c.gr(b) + d) & c.amask
}

// eaS computes B+D from a 2-byte base-displacement field.
func (c *CPU) eaBD(hi, lo byte) uint32 {
	b := int(hi >> 4)
	d := uint32(hi&0xf)<<8 | uint32(lo)
	return (c.gr(b) + d) & c.amask
}

func (c *CPU) setCC(cc byte) { c.PSW.CC = cc }

func ccSigned(x int32) byte {
	switch {
	case x == 0:
		return 0
	case x < 0:
		return 1
	}
	return 2
}

func ccSigned64(x int64) byte {
	switch {
	case x == 0:
		return 0
	case x < 0:
		return 1
	}
	return 2
}

func ccCompare(a, b int64) byte {
	switch {
	case a == b:
		return 0
	case a < b:
		return 1
	}
	return 2
}

func ccCompareU(a, b uint64) byte {
	switch {
	case a == b:
		return 0
	case a < b:
		return 1
	}
	return 2
}

func (c *CPU) overflow() {
	c.PSW.CC = 3
	if c.PSW.ProgMask&8 != 0 {
		c.program(pgmFixedOverflow)
	}
}

func (c *CPU) add(a, b uint32) uint32 {
	r := a + b
	if int32((a^r)&(b^r)) < 0 {
		c.overflow()
		return r
	}
	c.PSW.CC = ccSigned(int32(r))
	return r
}

func (c *CPU) sub(a, b uint32) uint32 {
	r := a - b
	if int32((a^b)&(a^r)) < 0 {
		c.overflow()
		return r
	}
	c.PSW.CC = ccSigned(int32(r))
	return r
}

func (c *CPU) addLogical(a, b uint32) uint32 {
	s := uint64(a) + uint64(b)
	r := uint32(s)
	c.PSW.CC = 0
	if s>>32 != 0 {
		c.PSW.CC = 2
	}
	if r != 0 {
		c.PSW.CC |= 1
	}
	return r
}

func (c *CPU) subLogical(a, b uint32) uint32 {
	s := uint64(a) + uint64(^b) + 1
	r := uint32(s)
	c.PSW.CC = 0
	if s>>32 != 0 {
		c.PSW.CC = 2
	}
	if r != 0 {
		c.PSW.CC |= 1
	}
	return r
}

func (c *CPU) logicCC(r uint32) uint32 {
	if r == 0 {
		c.PSW.CC = 0
	} else {
		c.PSW.CC = 1
	}
	return r
}

func (c *CPU) branch(target uint32) {
	c.next = target & c.amask
}

// linkInfo returns BAL-style link information.
func (c *CPU) balLink() uint32 {
	if c.PSW.Amode31 {
		return 0x80000000 | c.next
	}
	return (c.ilc/2)<<30 | uint32(c.PSW.CC)<<28 | uint32(c.PSW.ProgMask)<<24 | c.next&0xffffff
}

func (c *CPU) basLink() uint32 {
	if c.PSW.Amode31 {
		return 0x80000000 | c.next
	}
	return c.next & 0xffffff
}

func (c *CPU) cond(mask byte) bool { return mask&(8>>c.PSW.CC) != 0 }

func (c *CPU) privileged() {
	if c.PSW.Problem {
		c.program(pgmPrivileged)
	}
	if c.sie != nil {
		c.sieInterceptCheck()
	}
}

func (c *CPU) even(r int) {
	if r&1 != 0 {
		c.program(pgmSpecification)
	}
}

func sext16(x uint16) uint32 { return uint32(int32(int16(x))) }

func (c *CPU) unknown() {
	op := uint16(c.op[0]) << 8
	switch c.op[0] {
	case 0x01, 0xa5, 0xa7, 0xb2, 0xb3, 0xb9, 0xc0, 0xe3, 0xe5, 0xeb, 0xec, 0xed:
		op |= uint16(c.op[1])
		if c.op[0] == 0xa7 || c.op[0] == 0xa5 || c.op[0] == 0xc0 {
			op = uint16(c.op[0])<<8 | uint16(c.op[1]&0xf)
		}
		if c.op[0] == 0xe3 || c.op[0] == 0xeb || c.op[0] == 0xec || c.op[0] == 0xed {
			op = uint16(c.op[0])<<8 | uint16(c.op[5])
		}
	}
	if c.Unknown == nil {
		c.Unknown = map[uint16]uint64{}
	}
	c.Unknown[op]++
	c.program(pgmOperation)
}

// execute runs one decoded instruction held in c.op.
func (c *CPU) execute() {
	op := c.op[:]
	switch op[0] {
	// ---- RR ----
	case 0x01:
		c.execE()
	case 0x04: // SPM
		r1 := int(op[1] >> 4)
		c.PSW.CC = byte(c.GR[r1]>>28) & 3
		c.PSW.ProgMask = byte(c.GR[r1]>>24) & 0xf
	case 0x05: // BALR
		r1, r2 := int(op[1]>>4), int(op[1]&0xf)
		t := c.GR[r2]
		c.GR[r1] = c.balLink()
		if r2 != 0 {
			c.branch(t)
		}
	case 0x06: // BCTR
		r1, r2 := int(op[1]>>4), int(op[1]&0xf)
		t := c.GR[r2]
		c.GR[r1]--
		if c.GR[r1] != 0 && r2 != 0 {
			c.branch(t)
		}
	case 0x07: // BCR
		m, r2 := op[1]>>4, int(op[1]&0xf)
		if r2 != 0 && c.cond(m) {
			c.branch(c.GR[r2])
		}
	case 0x08: // SSK (System/370)
		if !c.M.S370 {
			c.unknown()
		}
		c.ssk370(int(op[1]>>4), int(op[1]&0xf))
	case 0x09: // ISK (System/370)
		if !c.M.S370 {
			c.unknown()
		}
		c.isk370(int(op[1]>>4), int(op[1]&0xf))
	case 0x9c, 0x9d, 0x9e, 0x9f: // SIO(F), TIO/CLRIO, HIO/HDV, TCH (System/370)
		if !c.M.S370 {
			c.unknown()
		}
		c.io370(op, c.eaBD(op[2], op[3]))
	case 0x0a: // SVC
		c.takeSVC(op[1])
	case 0x0b: // BSM
		r1, r2 := int(op[1]>>4), int(op[1]&0xf)
		t := c.GR[r2]
		if r1 != 0 {
			if c.PSW.Amode31 {
				c.GR[r1] |= 0x80000000
			} else {
				c.GR[r1] &^= 0x80000000
			}
		}
		if r2 != 0 {
			c.PSW.Amode31 = t&0x80000000 != 0
			c.setAmode()
			c.branch(t)
		}
	case 0x0c: // BASSM
		r1, r2 := int(op[1]>>4), int(op[1]&0xf)
		t := c.GR[r2]
		c.GR[r1] = c.basLink()
		if r2 != 0 {
			c.PSW.Amode31 = t&0x80000000 != 0
			c.setAmode()
			c.branch(t)
		}
	case 0x0d: // BASR
		r1, r2 := int(op[1]>>4), int(op[1]&0xf)
		t := c.GR[r2]
		c.GR[r1] = c.basLink()
		if r2 != 0 {
			c.branch(t)
		}
	case 0x0e:
		c.mvcl(int(op[1]>>4), int(op[1]&0xf))
	case 0x0f:
		c.clcl(int(op[1]>>4), int(op[1]&0xf))
	case 0x10: // LPR
		r1, r2 := int(op[1]>>4), int(op[1]&0xf)
		x := int32(c.GR[r2])
		if x == -1<<31 {
			c.GR[r1] = uint32(x)
			c.overflow()
			return
		}
		if x < 0 {
			x = -x
		}
		c.GR[r1] = uint32(x)
		c.PSW.CC = ccSigned(x)
	case 0x11: // LNR
		r1, r2 := int(op[1]>>4), int(op[1]&0xf)
		x := int32(c.GR[r2])
		if x > 0 {
			x = -x
		}
		c.GR[r1] = uint32(x)
		c.PSW.CC = ccSigned(x)
	case 0x12: // LTR
		r1, r2 := int(op[1]>>4), int(op[1]&0xf)
		c.GR[r1] = c.GR[r2]
		c.PSW.CC = ccSigned(int32(c.GR[r1]))
	case 0x13: // LCR
		r1, r2 := int(op[1]>>4), int(op[1]&0xf)
		x := int32(c.GR[r2])
		c.GR[r1] = uint32(-x)
		if x == -1<<31 {
			c.overflow()
			return
		}
		c.PSW.CC = ccSigned(-x)
	case 0x14:
		r1, r2 := int(op[1]>>4), int(op[1]&0xf)
		c.GR[r1] = c.logicCC(c.GR[r1] & c.GR[r2])
	case 0x15:
		r1, r2 := int(op[1]>>4), int(op[1]&0xf)
		c.PSW.CC = ccCompareU(uint64(c.GR[r1]), uint64(c.GR[r2]))
	case 0x16:
		r1, r2 := int(op[1]>>4), int(op[1]&0xf)
		c.GR[r1] = c.logicCC(c.GR[r1] | c.GR[r2])
	case 0x17:
		r1, r2 := int(op[1]>>4), int(op[1]&0xf)
		c.GR[r1] = c.logicCC(c.GR[r1] ^ c.GR[r2])
	case 0x18:
		c.GR[op[1]>>4] = c.GR[op[1]&0xf]
	case 0x19:
		r1, r2 := int(op[1]>>4), int(op[1]&0xf)
		c.PSW.CC = ccCompare(int64(int32(c.GR[r1])), int64(int32(c.GR[r2])))
	case 0x1a:
		r1, r2 := int(op[1]>>4), int(op[1]&0xf)
		c.GR[r1] = c.add(c.GR[r1], c.GR[r2])
	case 0x1b:
		r1, r2 := int(op[1]>>4), int(op[1]&0xf)
		c.GR[r1] = c.sub(c.GR[r1], c.GR[r2])
	case 0x1c: // MR
		r1, r2 := int(op[1]>>4), int(op[1]&0xf)
		c.even(r1)
		p := int64(int32(c.GR[r1+1])) * int64(int32(c.GR[r2]))
		c.GR[r1], c.GR[r1+1] = uint32(uint64(p)>>32), uint32(p)
	case 0x1d: // DR
		r1, r2 := int(op[1]>>4), int(op[1]&0xf)
		c.even(r1)
		c.divide(r1, c.GR[r2])
	case 0x1e:
		r1, r2 := int(op[1]>>4), int(op[1]&0xf)
		c.GR[r1] = c.addLogical(c.GR[r1], c.GR[r2])
	case 0x1f:
		r1, r2 := int(op[1]>>4), int(op[1]&0xf)
		c.GR[r1] = c.subLogical(c.GR[r1], c.GR[r2])
	case 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f:
		c.hfpRR(op[0], int(op[1]>>4), int(op[1]&0xf))

	// ---- RX ----
	case 0x40:
		c.storeHalf(c.eaRX(op), int(op[2]>>4), uint16(c.GR[op[1]>>4]))
	case 0x41:
		c.GR[op[1]>>4] = c.eaRX(op)
	case 0x42:
		c.storeByte(c.eaRX(op), int(op[2]>>4), byte(c.GR[op[1]>>4]))
	case 0x43:
		r1 := op[1] >> 4
		c.GR[r1] = c.GR[r1]&^0xff | uint32(c.fetchByte(c.eaRX(op), int(op[2]>>4)))
	case 0x44:
		c.ex(int(op[1]>>4), c.eaRX(op))
	case 0x45: // BAL
		t := c.eaRX(op)
		c.GR[op[1]>>4] = c.balLink()
		c.branch(t)
	case 0x46: // BCT
		r1 := op[1] >> 4
		t := c.eaRX(op)
		c.GR[r1]--
		if c.GR[r1] != 0 {
			c.branch(t)
		}
	case 0x47: // BC
		if c.cond(op[1] >> 4) {
			c.branch(c.eaRX(op))
		}
	case 0x48:
		c.GR[op[1]>>4] = sext16(c.fetchHalf(c.eaRX(op), int(op[2]>>4)))
	case 0x49:
		r1 := op[1] >> 4
		c.PSW.CC = ccCompare(int64(int32(c.GR[r1])), int64(int16(c.fetchHalf(c.eaRX(op), int(op[2]>>4)))))
	case 0x4a:
		r1 := op[1] >> 4
		c.GR[r1] = c.add(c.GR[r1], sext16(c.fetchHalf(c.eaRX(op), int(op[2]>>4))))
	case 0x4b:
		r1 := op[1] >> 4
		c.GR[r1] = c.sub(c.GR[r1], sext16(c.fetchHalf(c.eaRX(op), int(op[2]>>4))))
	case 0x4c:
		r1 := op[1] >> 4
		c.GR[r1] = uint32(int32(c.GR[r1]) * int32(int16(c.fetchHalf(c.eaRX(op), int(op[2]>>4)))))
	case 0x4d: // BAS
		t := c.eaRX(op)
		c.GR[op[1]>>4] = c.basLink()
		c.branch(t)
	case 0x4e: // CVD
		a := c.eaRX(op)
		c.storeDouble(a, int(op[2]>>4), cvd(int32(c.GR[op[1]>>4])))
	case 0x4f: // CVB
		c.GR[op[1]>>4] = c.cvb(c.fetchDouble(c.eaRX(op), int(op[2]>>4)))
	case 0x50:
		c.storeWord(c.eaRX(op), int(op[2]>>4), c.GR[op[1]>>4])
	case 0x51: // LAE
		r1, b2 := int(op[1]>>4), int(op[2]>>4)
		c.GR[r1] = c.eaRX(op)
		c.setLAEAR(r1, b2)
	case 0x54:
		r1 := op[1] >> 4
		c.GR[r1] = c.logicCC(c.GR[r1] & c.fetchWord(c.eaRX(op), int(op[2]>>4)))
	case 0x55:
		r1 := op[1] >> 4
		c.PSW.CC = ccCompareU(uint64(c.GR[r1]), uint64(c.fetchWord(c.eaRX(op), int(op[2]>>4))))
	case 0x56:
		r1 := op[1] >> 4
		c.GR[r1] = c.logicCC(c.GR[r1] | c.fetchWord(c.eaRX(op), int(op[2]>>4)))
	case 0x57:
		r1 := op[1] >> 4
		c.GR[r1] = c.logicCC(c.GR[r1] ^ c.fetchWord(c.eaRX(op), int(op[2]>>4)))
	case 0x58:
		c.GR[op[1]>>4] = c.fetchWord(c.eaRX(op), int(op[2]>>4))
	case 0x59:
		r1 := op[1] >> 4
		c.PSW.CC = ccCompare(int64(int32(c.GR[r1])), int64(int32(c.fetchWord(c.eaRX(op), int(op[2]>>4)))))
	case 0x5a:
		r1 := op[1] >> 4
		c.GR[r1] = c.add(c.GR[r1], c.fetchWord(c.eaRX(op), int(op[2]>>4)))
	case 0x5b:
		r1 := op[1] >> 4
		c.GR[r1] = c.sub(c.GR[r1], c.fetchWord(c.eaRX(op), int(op[2]>>4)))
	case 0x5c: // M
		r1 := int(op[1] >> 4)
		c.even(r1)
		p := int64(int32(c.GR[r1+1])) * int64(int32(c.fetchWord(c.eaRX(op), int(op[2]>>4))))
		c.GR[r1], c.GR[r1+1] = uint32(uint64(p)>>32), uint32(p)
	case 0x5d: // D
		r1 := int(op[1] >> 4)
		c.even(r1)
		c.divide(r1, c.fetchWord(c.eaRX(op), int(op[2]>>4)))
	case 0x5e:
		r1 := op[1] >> 4
		c.GR[r1] = c.addLogical(c.GR[r1], c.fetchWord(c.eaRX(op), int(op[2]>>4)))
	case 0x5f:
		r1 := op[1] >> 4
		c.GR[r1] = c.subLogical(c.GR[r1], c.fetchWord(c.eaRX(op), int(op[2]>>4)))
	case 0x60, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f:
		c.hfpRX(op[0], int(op[1]>>4), c.eaRX(op), int(op[2]>>4))
	case 0x71: // MS
		r1 := op[1] >> 4
		c.GR[r1] = uint32(int32(c.GR[r1]) * int32(c.fetchWord(c.eaRX(op), int(op[2]>>4))))

	// ---- RS / SI ----
	case 0x80: // SSM
		c.privileged()
		if c.CR[0]&0x40000000 != 0 {
			c.program(pgmSpecialOperation)
		}
		x := c.fetchByte(c.eaBD(op[2], op[3]), int(op[2]>>4))
		if x&0xb8 != 0 && !c.PSW.BC {
			c.program(pgmSpecification)
		}
		c.setSystemMask(x)
	case 0x82: // LPSW
		c.privileged()
		a := c.eaBD(op[2], op[3])
		if a&7 != 0 {
			c.program(pgmSpecification)
		}
		x := c.fetchDouble(a, int(op[2]>>4))
		if _, ok := c.decodePSW(x); !ok {
			c.program(pgmSpecification)
		}
		c.loadPSW(x)
		c.next = c.PSW.IA
		c.pswChanged = true
	case 0x83: // DIAGNOSE
		c.privileged()
		c.diagnose(int(op[1]>>4), int(op[1]&0xf), c.eaBD(op[2], op[3]))
	case 0x84, 0x85: // BRXH, BRXLE
		r1, r3 := int(op[1]>>4), int(op[1]&0xf)
		i := int32(int16(be.Uint16(op[2:])))
		inc := int32(c.GR[r3])
		cmp := int32(c.GR[r3|1])
		v := int32(c.GR[r1]) + inc
		c.GR[r1] = uint32(v)
		if (op[0] == 0x84 && v > cmp) || (op[0] == 0x85 && v <= cmp) {
			c.branch(c.ia + uint32(i*2))
		}
	case 0x86, 0x87: // BXH, BXLE
		r1, r3 := int(op[1]>>4), int(op[1]&0xf)
		t := c.eaBD(op[2], op[3])
		inc := int32(c.GR[r3])
		cmp := int32(c.GR[r3|1])
		v := int32(c.GR[r1]) + inc
		c.GR[r1] = uint32(v)
		if (op[0] == 0x86 && v > cmp) || (op[0] == 0x87 && v <= cmp) {
			c.branch(t)
		}
	case 0x88:
		r1 := op[1] >> 4
		c.GR[r1] = shr32(c.GR[r1], c.eaBD(op[2], op[3])&63)
	case 0x89:
		r1 := op[1] >> 4
		c.GR[r1] = shl32(c.GR[r1], c.eaBD(op[2], op[3])&63)
	case 0x8a: // SRA
		r1 := op[1] >> 4
		n := c.eaBD(op[2], op[3]) & 63
		if n > 31 {
			n = 31
		}
		c.GR[r1] = uint32(int32(c.GR[r1]) >> n)
		c.PSW.CC = ccSigned(int32(c.GR[r1]))
	case 0x8b: // SLA
		r1 := op[1] >> 4
		n := c.eaBD(op[2], op[3]) & 63
		sign := c.GR[r1] & 0x80000000
		ov := false
		m := c.GR[r1] & 0x7fffffff
		for i := uint32(0); i < n; i++ {
			if (m&0x40000000 != 0) != (sign != 0) {
				ov = true
			}
			m = m << 1 & 0x7fffffff
		}
		c.GR[r1] = sign | m
		if ov {
			c.overflow()
			return
		}
		c.PSW.CC = ccSigned(int32(c.GR[r1]))
	case 0x8c, 0x8d, 0x8e, 0x8f:
		r1 := int(op[1] >> 4)
		c.even(r1)
		n := c.eaBD(op[2], op[3]) & 63
		v := uint64(c.GR[r1])<<32 | uint64(c.GR[r1+1])
		switch op[0] {
		case 0x8c:
			v = shr64(v, n)
		case 0x8d:
			v = shl64(v, n)
		case 0x8e:
			v = uint64(int64(v) >> n)
			c.PSW.CC = ccSigned64(int64(v))
		case 0x8f:
			sign := v & (1 << 63)
			m := v &^ (1 << 63)
			ov := false
			for i := uint32(0); i < n; i++ {
				if (m&(1<<62) != 0) != (sign != 0) {
					ov = true
				}
				m = m << 1 &^ (1 << 63)
			}
			v = sign | m
			c.GR[r1], c.GR[r1+1] = uint32(v>>32), uint32(v)
			if ov {
				c.overflow()
				return
			}
			c.PSW.CC = ccSigned64(int64(v))
		}
		c.GR[r1], c.GR[r1+1] = uint32(v>>32), uint32(v)
	case 0x90: // STM
		c.stm(int(op[1]>>4), int(op[1]&0xf), c.eaBD(op[2], op[3]), int(op[2]>>4))
	case 0x91: // TM
		x := c.fetchByte(c.eaBD(op[2], op[3]), int(op[2]>>4)) & op[1]
		switch {
		case x == 0:
			c.PSW.CC = 0
		case x == op[1]:
			c.PSW.CC = 3
		default:
			c.PSW.CC = 1
		}
	case 0x92:
		c.storeByte(c.eaBD(op[2], op[3]), int(op[2]>>4), op[1])
	case 0x93: // TS
		a := c.absolute(c.eaBD(op[2], op[3]), accStore, int(op[2]>>4))
		c.PSW.CC = c.S.Mem[a] >> 7
		c.S.Mem[a] = 0xff
	case 0x94, 0x95, 0x96, 0x97:
		a := c.eaBD(op[2], op[3])
		b := int(op[2] >> 4)
		if op[0] == 0x95 {
			c.PSW.CC = ccCompareU(uint64(c.fetchByte(a, b)), uint64(op[1]))
			return
		}
		p := c.absolute(a, accStore, b)
		x := c.S.Mem[p]
		switch op[0] {
		case 0x94:
			x &= op[1]
		case 0x96:
			x |= op[1]
		case 0x97:
			x ^= op[1]
		}
		c.S.Mem[p] = x
		c.PSW.CC = 0
		if x != 0 {
			c.PSW.CC = 1
		}
	case 0x98: // LM
		c.lm(int(op[1]>>4), int(op[1]&0xf), c.eaBD(op[2], op[3]), int(op[2]>>4))
	case 0x99: // TRACE
		c.privileged()
	case 0x9a: // LAM
		r1, r3 := int(op[1]>>4), int(op[1]&0xf)
		a := c.eaBD(op[2], op[3])
		if a&3 != 0 {
			c.program(pgmSpecification)
		}
		// Fetch every word before loading: the operand is translated
		// with the access registers as they were (the B2 register may be
		// among those loaded).
		var vals [16]uint32
		n := 0
		for r := r1; ; r = (r + 1) & 15 {
			vals[n] = c.fetchWord(a, int(op[2]>>4))
			n++
			a = (a + 4) & c.amask
			if r == r3 {
				break
			}
		}
		for i, r := 0, r1; i < n; i, r = i+1, (r+1)&15 {
			c.AR[r] = vals[i]
		}
	case 0x9b: // STAM
		r1, r3 := int(op[1]>>4), int(op[1]&0xf)
		a := c.eaBD(op[2], op[3])
		if a&3 != 0 {
			c.program(pgmSpecification)
		}
		for r := r1; ; r = (r + 1) & 15 {
			c.storeWord(a, int(op[2]>>4), c.AR[r])
			a = (a + 4) & c.amask
			if r == r3 {
				break
			}
		}
	case 0xa7:
		c.execRI()
	case 0xa8:
		c.mvcle(int(op[1]>>4), int(op[1]&0xf), c.eaBD(op[2], op[3]))
	case 0xa9:
		c.clcle(int(op[1]>>4), int(op[1]&0xf), c.eaBD(op[2], op[3]))
	case 0xac, 0xad: // STNSM, STOSM
		c.privileged()
		a := c.eaBD(op[2], op[3])
		old := byte(c.PSW.Encode() >> 56)
		c.storeByte(a, int(op[2]>>4), old)
		x := old & op[1]
		if op[0] == 0xad {
			x = old | op[1]
			if x&0xb8 != 0 && !c.PSW.BC {
				c.program(pgmSpecification)
			}
		}
		c.setSystemMask(x)
	case 0xae: // SIGP
		c.privileged()
		c.sigp(int(op[1]>>4), int(op[1]&0xf), c.eaBD(op[2], op[3]))
	case 0xaf: // MC
		if op[1]&0xf0 != 0 {
			c.program(pgmSpecification)
		}
	case 0xb1: // LRA
		c.privileged()
		if c.M.S370 {
			c.lra370(int(op[1]>>4), c.eaRX(op))
			break
		}
		c.lra(int(op[1]>>4), c.eaRX(op), int(op[2]>>4))
	case 0xb2:
		c.execB2()
	case 0xb3:
		c.execB3()
	case 0xb6: // STCTL
		c.privileged()
		r1, r3 := int(op[1]>>4), int(op[1]&0xf)
		a := c.eaBD(op[2], op[3])
		if a&3 != 0 {
			c.program(pgmSpecification)
		}
		n := uint32((r3-r1)&15) + 1
		c.checkStore(a, n*4, int(op[2]>>4))
		for r := r1; ; r = (r + 1) & 15 {
			c.storeWord(a, int(op[2]>>4), c.CR[r])
			a = (a + 4) & c.amask
			if r == r3 {
				break
			}
		}
	case 0xb7: // LCTL
		c.privileged()
		r1, r3 := int(op[1]>>4), int(op[1]&0xf)
		a := c.eaBD(op[2], op[3])
		if a&3 != 0 {
			c.program(pgmSpecification)
		}
		n := uint32((r3-r1)&15) + 1
		c.checkFetch(a, n*4, int(op[2]>>4))
		var vals [16]uint32
		for i := uint32(0); i < n; i++ {
			vals[i] = c.fetchWord(a+4*i, int(op[2]>>4))
		}
		for i, r := uint32(0), r1; i < n; i, r = i+1, (r+1)&15 {
			c.setCR(r, vals[i])
		}
	case 0xb9:
		c.execB9()
	case 0xba: // CS
		r1, r3 := int(op[1]>>4), int(op[1]&0xf)
		a := c.eaBD(op[2], op[3])
		if a&3 != 0 {
			c.program(pgmSpecification)
		}
		p := c.absolute(a, accStore, int(op[2]>>4))
		cur := be.Uint32(c.S.Mem[p:])
		if cur == c.GR[r1] {
			be.PutUint32(c.S.Mem[p:], c.GR[r3])
			c.PSW.CC = 0
		} else {
			c.GR[r1] = cur
			c.PSW.CC = 1
		}
	case 0xbb: // CDS
		r1, r3 := int(op[1]>>4), int(op[1]&0xf)
		c.even(r1)
		c.even(r3)
		a := c.eaBD(op[2], op[3])
		if a&7 != 0 {
			c.program(pgmSpecification)
		}
		p := c.absolute(a, accStore, int(op[2]>>4))
		cur := be.Uint64(c.S.Mem[p:])
		if cur == uint64(c.GR[r1])<<32|uint64(c.GR[r1+1]) {
			be.PutUint64(c.S.Mem[p:], uint64(c.GR[r3])<<32|uint64(c.GR[r3+1]))
			c.PSW.CC = 0
		} else {
			c.GR[r1], c.GR[r1+1] = uint32(cur>>32), uint32(cur)
			c.PSW.CC = 1
		}
	case 0xbd: // CLM
		r1, m := int(op[1]>>4), op[1]&0xf
		a := c.eaBD(op[2], op[3])
		c.PSW.CC = 0
		for i := 0; i < 4; i++ {
			if m&(8>>i) == 0 {
				continue
			}
			x := byte(c.GR[r1] >> (24 - 8*i))
			y := c.fetchByte(a, int(op[2]>>4))
			a = (a + 1) & c.amask
			if x != y {
				if x < y {
					c.PSW.CC = 1
				} else {
					c.PSW.CC = 2
				}
				return
			}
		}
	case 0xbe: // STCM
		r1, m := int(op[1]>>4), op[1]&0xf
		a := c.eaBD(op[2], op[3])
		var buf [4]byte
		n := 0
		for i := 0; i < 4; i++ {
			if m&(8>>i) != 0 {
				buf[n] = byte(c.GR[r1] >> (24 - 8*i))
				n++
			}
		}
		c.checkStore(a, uint32(n), int(op[2]>>4))
		for i := 0; i < n; i++ {
			c.storeByte(a+uint32(i), int(op[2]>>4), buf[i])
		}
	case 0xbf: // ICM
		r1, m := int(op[1]>>4), op[1]&0xf
		a := c.eaBD(op[2], op[3])
		v := c.GR[r1]
		first := true
		c.PSW.CC = 0
		for i := 0; i < 4; i++ {
			if m&(8>>i) == 0 {
				continue
			}
			y := c.fetchByte(a, int(op[2]>>4))
			a = (a + 1) & c.amask
			sh := uint(24 - 8*i)
			v = v&^(0xff<<sh) | uint32(y)<<sh
			if first {
				first = false
				if y&0x80 != 0 {
					c.PSW.CC = 1
				}
			}
			if y != 0 && c.PSW.CC == 0 {
				c.PSW.CC = 2
			}
		}
		c.GR[r1] = v

	// ---- SS ----
	case 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xdc, 0xdd, 0xde, 0xdf, 0xe8:
		c.ssCharacter()
	case 0xd9, 0xda, 0xdb:
		c.mvcKey()
	case 0xe5:
		c.execE5()
	case 0xed:
		c.execED()
	case 0xee: // PLO
		c.plo(int(op[1]>>4), int(op[1]&0xf), c.eaBD(op[2], op[3]), int(op[2]>>4), c.eaBD(op[4], op[5]), int(op[4]>>4))
	case 0xf0, 0xf1, 0xf2, 0xf3, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd:
		c.ssDecimal()
	default:
		c.unknown()
	}
}

func shr32(x uint32, n uint32) uint32 {
	if n > 31 {
		return 0
	}
	return x >> n
}
func shl32(x uint32, n uint32) uint32 {
	if n > 31 {
		return 0
	}
	return x << n
}
func shr64(x uint64, n uint32) uint64 {
	if n > 63 {
		return 0
	}
	return x >> n
}
func shl64(x uint64, n uint32) uint64 {
	if n > 63 {
		return 0
	}
	return x << n
}

func (c *CPU) divide(r1 int, d uint32) {
	if d == 0 {
		c.program(pgmFixedDivide)
	}
	n := int64(uint64(c.GR[r1])<<32 | uint64(c.GR[r1+1]))
	dv := int64(int32(d))
	q := n / dv
	r := n % dv
	if q > 0x7fffffff || q < -0x80000000 {
		c.program(pgmFixedDivide)
	}
	c.GR[r1], c.GR[r1+1] = uint32(r), uint32(q)
}

func (c *CPU) stm(r1, r3 int, a uint32, b int) {
	n := uint32((r3-r1)&15) + 1
	c.checkStore(a, n*4, b)
	if p := c.span(a, n*4, accStore, b); p != nil {
		for i, r := uint32(0), r1; i < n; i, r = i+1, (r+1)&15 {
			be.PutUint32(p[i*4:], c.GR[r])
		}
		return
	}
	for r := r1; ; r = (r + 1) & 15 {
		c.storeWord(a, b, c.GR[r])
		a = (a + 4) & c.amask
		if r == r3 {
			break
		}
	}
}

func (c *CPU) lm(r1, r3 int, a uint32, b int) {
	n := uint32((r3-r1)&15) + 1
	if p := c.span(a, n*4, accFetch, b); p != nil {
		for i, r := uint32(0), r1; i < n; i, r = i+1, (r+1)&15 {
			c.GR[r] = be.Uint32(p[i*4:])
		}
		return
	}
	c.checkFetch(a, n*4, b)
	var vals [16]uint32
	for i := uint32(0); i < n; i++ {
		vals[i] = c.fetchWord(a+4*i, b)
	}
	for i, r := uint32(0), r1; i < n; i, r = i+1, (r+1)&15 {
		c.GR[r] = vals[i]
	}
}

func (c *CPU) setSystemMask(x byte) {
	w := c.PSW.Encode()
	w = w&^(0xff<<56) | uint64(x)<<56
	p, _ := c.decodePSW(w)
	p.IA = c.PSW.IA
	p.Amode31 = c.PSW.Amode31
	p.IntCode, p.ILC = c.PSW.IntCode, c.PSW.ILC
	c.PSW = p
	c.pswChanged = true
}

func (c *CPU) setCR(r int, v uint32) {
	old := c.CR[r]
	c.CR[r] = v
	switch r {
	case 0:
		if old&0x00f80000 != v&0x00f80000 {
			c.purgeTLB()
		}
		c.dtlbGen++ // protection-override and low-address controls
		c.pswChanged = true
	case 1, 7, 13:
		// TLB entries are tagged by STD; no purge required.
	case 6, 14:
		c.pswChanged = true
	}
}

func (c *CPU) setLAEAR(r1, b2 int) {
	switch c.PSW.AS {
	case 0:
		c.AR[r1] = 0
	case 2:
		c.AR[r1] = 1
	case 3:
		c.AR[r1] = 2
	default:
		if b2 == 0 {
			c.AR[r1] = 0
		} else {
			c.AR[r1] = c.AR[b2]
		}
	}
}

// ex executes the target of EXECUTE.
func (c *CPU) ex(r1 int, a uint32) {
	if a&1 != 0 {
		c.program(pgmSpecification)
	}
	var t [6]byte
	t[0] = c.fetchInstrByte(a)
	t[1] = c.fetchInstrByte(a + 1)
	n := ilen(t[0])
	for i := uint32(2); i < n; i++ {
		t[i] = c.fetchInstrByte(a + i)
	}
	if t[0] == 0x44 {
		c.program(pgmExecute)
	}
	if r1 != 0 {
		t[1] |= byte(c.GR[r1])
	}
	saveOp := c.op
	saveIA := c.ia
	c.op = t
	c.exAddr = true
	c.exIA = saveIA
	c.ia = a
	c.execute()
	c.exAddr = false
	c.ia = saveIA
	c.op = saveOp
}

func (c *CPU) fetchInstrByte(v uint32) byte {
	a := c.absolute(v, accInstr, 0)
	return c.S.Mem[a]
}

// execRI handles A7x relative/immediate instructions.
func (c *CPU) execRI() {
	op := c.op[:]
	r1 := int(op[1] >> 4)
	i := be.Uint16(op[2:])
	switch op[1] & 0xf {
	case 0x0, 0x1: // TMH, TML
		var x uint16
		if op[1]&0xf == 0 {
			x = uint16(c.GR[r1] >> 16)
		} else {
			x = uint16(c.GR[r1])
		}
		x &= i
		switch {
		case x == 0:
			c.PSW.CC = 0
		case x == i:
			c.PSW.CC = 3
		default:
			c.PSW.CC = 1
			// leftmost selected bit one -> cc 2
			for b := uint16(0x8000); b != 0; b >>= 1 {
				if i&b != 0 {
					if x&b != 0 {
						c.PSW.CC = 2
					}
					break
				}
			}
		}
	case 0x4: // BRC
		if c.cond(byte(r1)) {
			c.branch(c.ia + uint32(int32(int16(i))*2))
		}
	case 0x5: // BRAS
		c.GR[r1] = c.basLink()
		c.branch(c.ia + uint32(int32(int16(i))*2))
	case 0x6: // BRCT
		c.GR[r1]--
		if c.GR[r1] != 0 {
			c.branch(c.ia + uint32(int32(int16(i))*2))
		}
	case 0x8: // LHI
		c.GR[r1] = sext16(i)
	case 0xa: // AHI
		c.GR[r1] = c.add(c.GR[r1], sext16(i))
	case 0xc: // MHI
		c.GR[r1] = uint32(int32(c.GR[r1]) * int32(int16(i)))
	case 0xe: // CHI
		c.PSW.CC = ccCompare(int64(int32(c.GR[r1])), int64(int16(i)))
	default:
		c.unknown()
	}
}

// execE handles 01xx E-format instructions.
func (c *CPU) execE() {
	switch c.op[1] {
	case 0x01: // PR
		c.pr()
	case 0x02: // UPT
		c.unknown()
	case 0x07: // SCKPF
		c.privileged()
		if c.GR[0]&0xffff0000 != 0 {
			c.program(pgmSpecification)
		}
		c.M.todProgrammable = uint16(c.GR[0])
	default:
		c.unknown()
	}
}
