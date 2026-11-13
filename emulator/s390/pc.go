package s390

// PROGRAM CALL (ESA/390): PC-number translation through the linkage and
// entry tables, the basic and stacking operations, and the to-current-
// primary (PC-cp) and space-switching (PC-ss) variants. ASN tracing and
// the subspace-group replacement are not performed.

// pcEntry is a fetched entry-table entry (16 bytes, or 32 with ASF).
type pcEntry struct {
	akm, asn uint16
	ia       uint32 // A bit, EIA and P bit (word 1)
	parm     uint32
	ekm      uint16
	stacking bool
	ctl      byte // bits 128-135: T, reserved, K, M, E, C, S
	ek       byte
	eeax     uint16
	asteo    uint32 // bits 161-185 (ASF only)
	extended bool
}

func (c *CPU) pcTranslate(num uint32) pcEntry {
	asf := c.CR[0]&0x00010000 != 0
	ltd := c.CR[5]
	if asf {
		ltd = c.readRealWord(c.CR[5]&0x7fffffc0 + 12)
		if ltd&0x80000000 == 0 {
			c.program(pgmSpecialOperation)
		}
	}
	lx, ex := num>>8&0xfff, num&0xff
	if lx>>5 > ltd&0x7f {
		c.program(pgmLXTranslation)
	}
	lte := c.readRealWord(ltd&0x7fffff80 + lx*4)
	if lte&0x80000000 != 0 {
		c.program(pgmLXTranslation)
	}
	if ex>>2 > lte&0x3f {
		c.program(pgmEXTranslation)
	}
	size := uint32(16)
	if asf {
		size = 32
	}
	ete := lte&0x7fffffc0 + ex*size
	w := func(i uint32) uint32 { return c.readRealWord(ete + 4*i) }
	e := pcEntry{extended: asf}
	w0 := w(0)
	e.akm, e.asn = uint16(w0>>16), uint16(w0)
	e.ia = w(1)
	e.parm = w(2)
	e.ekm = uint16(w(3) >> 16)
	if asf {
		w4 := w(4)
		e.ctl = byte(w4 >> 24)
		e.stacking = e.ctl&0x80 != 0
		e.ek = byte(w4>>20) & 0xf
		e.eeax = uint16(w4)
		e.asteo = w(5) & 0x7fffffc0
	}
	if e.ia&0x80000000 == 0 && e.ia&0x7f000000 != 0 {
		c.program(pgmPCTranslationSpec)
	}
	return e
}

func (c *CPU) pc(a uint32) {
	if !c.PSW.DAT || c.PSW.AS == 2 || c.PSW.AS == 3 {
		c.program(pgmSpecialOperation)
	}
	asf := c.CR[0]&0x00010000 != 0
	if !asf && (c.PSW.AS == 1 || c.CR[5]&0x80000000 == 0) {
		c.program(pgmSpecialOperation)
	}
	num := a & 0xfffff
	e := c.pcTranslate(num)
	if !e.stacking && c.PSW.AS == 1 {
		c.program(pgmSpecialOperation)
	}
	if c.PSW.Problem && e.akm&uint16(c.CR[3]>>16) == 0 {
		c.program(pgmPrivileged)
	}
	// PC-ss: locate the new primary ASTE before anything changes.
	var asteo uint32
	if e.asn != 0 {
		if c.CR[14]&0x00080000 == 0 {
			c.program(pgmSpecialOperation)
		}
		if asf && e.asteo != 0 {
			asteo = e.asteo
			if c.readRealWord(asteo)&0x80000000 != 0 {
				c.program(pgmASXTranslation)
			}
		} else {
			var code uint16
			asteo, code = c.asnTranslateEx(e.asn)
			if code != 0 {
				c.program(code)
			}
		}
	}
	oldPSTD, oldPASN := c.CR[1], uint16(c.CR[4])
	if e.stacking {
		p := c.PSW
		p.IA = c.next
		csi := uint32(0)
		if e.asn != 0 {
			csi = uint32(e.asn)<<16 | c.readRealWord(asteo+20)&0xffff
		}
		c.stack(lsPCState, p.Encode(), csi, num)
	} else {
		ret := c.next
		if c.PSW.Amode31 {
			ret |= 0x80000000
		} else {
			ret &= 0x00ffffff
		}
		if c.PSW.Problem {
			ret |= 1
		}
		c.GR[14] = ret
		c.GR[3] = c.CR[3]&0xffff0000 | uint32(oldPASN)
	}
	// Entry state.
	c.PSW.Amode31 = e.ia&0x80000000 != 0
	if c.PSW.Amode31 {
		c.amask = 0x7fffffff
	} else {
		c.amask = 0x00ffffff
	}
	c.PSW.Problem = e.ia&1 != 0
	c.next = e.ia & 0x7ffffffe
	if e.stacking && e.ctl&0x10 != 0 { // K
		c.PSW.Key = e.ek
	}
	if e.stacking && e.ctl&0x08 != 0 { // M
		c.CR[3] = c.CR[3]&0x0000ffff | uint32(e.ekm)<<16
	} else {
		c.CR[3] |= uint32(e.ekm) << 16
	}
	if e.stacking && e.ctl&0x04 != 0 { // E
		c.CR[8] = c.CR[8]&0x0000ffff | uint32(e.eeax)<<16
	}
	if e.stacking {
		c.PSW.AS = 0
		if e.ctl&0x02 != 0 { // C
			c.PSW.AS = 1
		}
	}
	c.GR[4] = e.parm
	if e.asn == 0 {
		// PC-cp: SASN and SSTD become the current PASN and PSTD.
		c.CR[3] = c.CR[3]&0xffff0000 | uint32(oldPASN)
		c.CR[7] = c.CR[1]
	} else {
		c.CR[4] = c.readRealWord(asteo+4)&0xffff0000 | uint32(e.asn)
		c.CR[1] = c.readRealWord(asteo + 8)
		if asf {
			c.CR[5] = asteo & 0x7fffffc0
		} else {
			c.CR[5] = c.readRealWord(asteo + 12)
		}
		if e.stacking && e.ctl&0x01 != 0 { // S: SASN = new PASN
			c.CR[3] = c.CR[3]&0xffff0000 | uint32(e.asn)
			c.CR[7] = c.CR[1]
		} else {
			c.CR[3] = c.CR[3]&0xffff0000 | uint32(oldPASN)
			c.CR[7] = oldPSTD
		}
	}
	c.pswChanged = true
	c.ipageValid = false
	if e.asn != 0 && (oldPSTD|c.CR[1])&0x80000000 != 0 {
		// Space-switch event: the operation is completed and the old
		// PASN identifies the space that was left.
		c.setLowWord(0xa8, uint32(oldPASN))
		panic(programCheck{code: pgmSpaceSwitch})
	}
}

// primaryAuthorized applies the primary-authority test (the P bit of the
// authority-table entry) of an ASTE for an authorization index.
func (c *CPU) primaryAuthorized(asteo uint32, ax uint16) bool {
	ato := c.readRealWord(asteo) & 0x7ffffffc
	atl := (c.readRealWord(asteo+4) >> 4) & 0xfff
	if uint32(ax>>4) > atl {
		return false
	}
	b := c.S.Mem[c.realAbs(ato+uint32(ax)/4, accFetch)]
	return b&(0x80>>((ax%4)*2)) != 0
}

// pt is PROGRAM TRANSFER: GR r1 holds the new PSW-key mask (ANDed) and
// PASN/SASN, GR r2 the addressing mode, instruction address and problem
// state.
func (c *CPU) pt(r1, r2 int) {
	if !c.PSW.DAT || c.PSW.AS != 0 {
		c.program(pgmSpecialOperation)
	}
	asf := c.CR[0]&0x00010000 != 0
	ltd := c.CR[5]
	if asf {
		ltd = c.readRealWord(c.CR[5]&0x7fffffc0 + 12)
	}
	if ltd&0x80000000 == 0 {
		c.program(pgmSpecialOperation)
	}
	g1, g2 := c.GR[r1], c.GR[r2]
	if c.PSW.Problem && g2&1 == 0 {
		c.program(pgmPrivileged)
	}
	if g2&0x80000000 == 0 && g2&0x7f000000 != 0 {
		c.program(pgmSpecification)
	}
	asn := uint16(g1)
	oldPSTD, oldPASN := c.CR[1], uint16(c.CR[4])
	ss := asn != oldPASN
	var asteo uint32
	if ss {
		if c.CR[14]&0x00080000 == 0 {
			c.program(pgmSpecialOperation)
		}
		var code uint16
		asteo, code = c.asnTranslateEx(asn)
		if code != 0 {
			c.program(code)
		}
		if !c.primaryAuthorized(asteo, uint16(c.CR[4]>>16)) {
			c.program(pgmPrimaryAuthority)
		}
	}
	c.PSW.Problem = g2&1 != 0
	c.PSW.Amode31 = g2&0x80000000 != 0
	if c.PSW.Amode31 {
		c.amask = 0x7fffffff
	} else {
		c.amask = 0x00ffffff
	}
	c.next = g2 & 0x7ffffffe & c.amask
	c.CR[3] = (c.CR[3] & g1 & 0xffff0000) | uint32(asn)
	if ss {
		c.CR[1] = c.readRealWord(asteo + 8)
		c.CR[4] = c.readRealWord(asteo+4)&0xffff0000 | uint32(asn)
		if asf {
			c.CR[5] = asteo & 0x7fffffc0
		} else {
			c.CR[5] = c.readRealWord(asteo + 12)
		}
	}
	c.CR[7] = c.CR[1]
	c.pswChanged = true
	c.ipageValid = false
	if ss && (oldPSTD|c.CR[1])&0x80000000 != 0 {
		c.setLowWord(0xa8, uint32(oldPASN))
		panic(programCheck{code: pgmSpaceSwitch})
	}
}

// ssar is SET SECONDARY ASN. To the current primary (SSAR-cp) the SSTD
// becomes the PSTD; otherwise (SSAR-ss) the ASN is translated, the
// current authorization index must be secondary-authorized by the ASTE,
// and the SSTD comes from the ASTE.
func (c *CPU) ssar(asn uint16) {
	if !c.PSW.DAT || c.CR[14]&0x00080000 == 0 {
		c.program(pgmSpecialOperation)
	}
	if asn == uint16(c.CR[4]) {
		c.CR[3] = c.CR[3]&0xffff0000 | uint32(asn)
		c.CR[7] = c.CR[1]
		return
	}
	asteo, code := c.asnTranslateEx(asn)
	if code != 0 {
		c.program(code)
	}
	if !c.secondaryAuthorized(asteo, uint16(c.CR[4]>>16)) {
		c.program(pgmSecondaryAuthority)
	}
	c.CR[3] = c.CR[3]&0xffff0000 | uint32(asn)
	c.CR[7] = c.readRealWord(asteo + 8)
}

// extraction applies the conditions of the semiprivileged extraction
// instructions (IAC, IVSK, EPAR, ESAR): DAT must be on, and in the problem
// state the extraction-authority control (CR0 bit 4) must be one.
func (c *CPU) extraction() {
	if !c.PSW.DAT {
		c.program(pgmSpecialOperation)
	}
	if c.PSW.Problem && c.CR[0]&0x08000000 == 0 {
		c.program(pgmPrivileged)
	}
}
