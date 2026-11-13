package s390

// The ESA/390 linkage stack: BRANCH AND STACK, PROGRAM RETURN, EXTRACT
// STACKED REGISTERS, EXTRACT STACKED STATE and MODIFY STACKED STATE. The
// stack is in the home address space (CR13); CR15 holds the address of the
// current entry descriptor. A state entry is 168 bytes: GR0-15, AR0-15,
// PKM/SASN/EAX/PASN, the PSW, bytes 144-159 and its entry descriptor.

const (
	lsHeader      = 1
	lsTrailer     = 2
	lsBranchState = 4
	lsPCState     = 5
	lsStateSize   = 168
)

// lsAbs translates a home virtual address of the linkage stack. Key
// protection does not apply; page protection and addressing do.
func (c *CPU) lsAbs(v uint32, acc access) uint32 {
	v &= 0x7fffffff
	c.excMode = 3
	real, prot := c.translate(v, c.CR[13], acc)
	if acc == accStore && prot {
		c.excAddr, c.excDATProt = v, true
		c.program(pgmProtection)
	}
	a := c.realToAbs(real)
	if !c.S.valid(a, 1) {
		c.program(pgmAddressing)
	}
	return a
}

func (c *CPU) lsWord(v uint32) uint32 { return be.Uint32(c.S.Mem[c.lsAbs(v, accFetch):]) }

// lsCheck applies the conditions shared by the stack instructions: the
// address-space-function control and DAT, and the allowed modes.
func (c *CPU) lsCheck(home bool) {
	if c.CR[0]&0x00010000 == 0 || !c.PSW.DAT || c.PSW.AS == 2 || c.PSW.AS == 3 && !home {
		c.program(pgmSpecialOperation)
	}
}

// stack forms a state entry (the stacking process).
func (c *CPU) stack(typ byte, psw uint64, w144, w148 uint32) {
	cur := c.CR[15] & 0x7ffffff8
	w0 := c.lsWord(cur)
	if w0&0xffff < lsStateSize {
		rfs := w0 & 0xffff
		if rfs&7 != 0 {
			c.program(pgmStackSpecification)
		}
		tw := c.lsWord(cur + 8 + rfs + 4)
		if tw&0x80000000 == 0 {
			c.program(pgmStackFull)
		}
		hdr := tw & 0x7ffffff8
		hw0 := c.lsWord(hdr)
		if hw0&0xffff < lsStateSize {
			c.program(pgmStackSpecification)
		}
		back := c.lsAbs(hdr-4, accStore)
		be.PutUint32(c.S.Mem[back:], 0x80000000|cur)
		cur, w0 = hdr, hw0
	}
	entry := cur + 8
	// Translate every page of the new entry and the current descriptor
	// before storing, so an exception leaves the stack unchanged.
	c.lsAbs(cur+4, accStore)
	c.lsAbs(entry, accStore)
	c.lsAbs(entry+lsStateSize-1, accStore)
	put := func(off, x uint32) {
		be.PutUint32(c.S.Mem[c.lsAbs(entry+off, accStore):], x)
	}
	for i := uint32(0); i < 16; i++ {
		put(4*i, c.GR[i])
		put(64+4*i, c.AR[i])
	}
	put(128, c.CR[3])
	put(132, c.CR[8]&0xffff0000|c.CR[4]&0xffff)
	put(136, uint32(psw>>32))
	put(140, uint32(psw))
	put(144, w144)
	put(148, w148)
	put(152, 0)
	put(156, 0)
	put(160, uint32(typ)<<24|w0&0x00ff0000|(w0&0xffff-lsStateSize))
	put(164, 0)
	nes := c.lsAbs(cur+4, accStore)
	be.PutUint16(c.S.Mem[nes:], lsStateSize)
	c.CR[15] = (entry + 160) & 0x7ffffff8
}

// lastState locates the last state entry (the locating part of the
// unstacking process) and returns its descriptor address and entry type.
func (c *CPU) lastState(pr bool) (uint32, byte) {
	desc := c.CR[15] & 0x7ffffff8
	w0 := c.lsWord(desc)
	et := byte(w0>>24) & 0x7f
	if et == lsHeader {
		if pr && w0&0x80000000 != 0 {
			c.program(pgmStackOperation)
		}
		back := c.lsWord(desc - 4)
		if back&0x80000000 == 0 {
			c.program(pgmStackEmpty)
		}
		desc = back & 0x7ffffff8
		w0 = c.lsWord(desc)
		et = byte(w0>>24) & 0x7f
		if et == lsHeader {
			c.program(pgmStackSpecification)
		}
	}
	if et != lsBranchState && et != lsPCState {
		c.program(pgmStackType)
	}
	if pr && w0&0x80000000 != 0 {
		c.program(pgmStackOperation)
	}
	return desc, et
}

// bakr is BRANCH AND STACK.
func (c *CPU) bakr(r1, r2 int) {
	c.lsCheck(false)
	p := c.PSW
	p.IA = c.next
	psw := p.Encode()
	if r1 != 0 {
		ret := c.GR[r1]
		if ret&0x80000000 != 0 {
			ret = 0x80000000 | ret&0x7fffffff
		} else {
			ret &= 0x00ffffff
		}
		psw = psw&0xffffffff00000000 | uint64(ret)
	}
	target := c.next
	if r2 != 0 {
		target = c.GR[r2] & c.amask
	}
	amode := uint32(0)
	if c.PSW.Amode31 {
		amode = 0x80000000
	}
	c.stack(lsBranchState, psw, 0, amode|target)
	if r2 != 0 {
		c.branch(c.GR[r2])
	}
}

// pr is PROGRAM RETURN.
func (c *CPU) pr() {
	c.lsCheck(false)
	desc, et := c.lastState(true)
	entry := desc - 160
	word := func(off uint32) uint32 { return c.lsWord(entry + off) }
	// Fetch everything before changing state (the operation is nullified
	// or suppressed on exceptions).
	var gr, ar [16]uint32
	for i := 2; i <= 14; i++ {
		gr[i], ar[i] = word(uint32(4*i)), word(uint32(64+4*i))
	}
	cr3, eaxPasn := word(128), word(132)
	psw := uint64(word(136))<<32 | uint64(word(140))
	prev := c.lsAbs(desc-lsStateSize+4, accStore)
	cr := c.CR
	if et == lsPCState {
		if c.CR[14]&0x00080000 == 0 && (uint16(eaxPasn) != uint16(c.CR[4]) || uint16(cr3) != uint16(eaxPasn)) {
			c.program(pgmSpecialOperation)
		}
		pasn, sasn := uint16(eaxPasn), uint16(cr3)
		cr[3] = cr3
		cr[8] = cr[8]&0x0000ffff | eaxPasn&0xffff0000
		if pasn != uint16(c.CR[4]) {
			asteo, code := c.asnTranslateEx(pasn)
			if code != 0 {
				c.program(code)
			}
			cr[1] = c.readRealWord(asteo + 8)
			cr[4] = c.readRealWord(asteo+4)&0xffff0000 | uint32(pasn)
			cr[5] = asteo & 0x7fffffc0
		}
		if sasn == pasn {
			cr[7] = cr[1]
		} else {
			asteo, code := c.asnTranslateEx(sasn)
			if code != 0 {
				c.program(code)
			}
			if !c.secondaryAuthorized(asteo, uint16(cr[4]>>16)) {
				c.program(pgmSecondaryAuthority)
			}
			cr[7] = c.readRealWord(asteo + 8)
		}
	}
	for i := 2; i <= 14; i++ {
		c.GR[i], c.AR[i] = gr[i], ar[i]
	}
	c.CR = cr
	be.PutUint16(c.S.Mem[prev:], 0)
	c.CR[15] = (desc - lsStateSize) & 0x7ffffff8
	per := c.PSW.PER
	if !c.loadPSW(psw) {
		c.earlySpec = true
	}
	c.PSW.PER = per
	c.next = c.PSW.IA
	c.pswChanged = true
	c.ipageValid = false
}

// asnTranslateEx is ASN translation with its program exceptions: AFX or ASX
// translation when the first-table entry or the ASTE is invalid.
func (c *CPU) asnTranslateEx(asn uint16) (uint32, uint16) {
	afto := (c.CR[14] & 0x7ffff) << 12
	afte := c.readRealWord(afto + uint32(asn>>6)*4)
	if afte&0x80000000 != 0 {
		return 0, pgmAFXTranslation
	}
	asteo := afte&0x7fffffc0 + uint32(asn&0x3f)*64
	if c.readRealWord(asteo)&0x80000000 != 0 {
		return 0, pgmASXTranslation
	}
	return asteo, 0
}

// ereg is EXTRACT STACKED REGISTERS.
func (c *CPU) ereg(r1, r2 int) {
	c.lsCheck(true)
	desc, _ := c.lastState(false)
	entry := desc - 160
	for r := r1; ; r = (r + 1) & 15 {
		c.GR[r] = c.lsWord(entry + uint32(4*r))
		c.AR[r] = c.lsWord(entry + 64 + uint32(4*r))
		if r == r2 {
			break
		}
	}
}

// esta is EXTRACT STACKED STATE.
func (c *CPU) esta(r1, r2 int) {
	c.lsCheck(true)
	code := c.GR[r2] & 0xff
	if r1&1 != 0 || code > 3 {
		c.program(pgmSpecification)
	}
	desc, et := c.lastState(false)
	off := desc - 160 + 128 + 8*code
	c.GR[r1], c.GR[r1+1] = c.lsWord(off), c.lsWord(off+4)
	c.PSW.CC = 0
	if et == lsPCState {
		c.PSW.CC = 1
	}
}

// msta is MODIFY STACKED STATE.
func (c *CPU) msta(r1 int) {
	if r1&1 != 0 {
		c.program(pgmSpecification)
	}
	c.lsCheck(true)
	desc, _ := c.lastState(false)
	a := desc - 160 + 152
	b1, b2 := c.lsAbs(a, accStore), c.lsAbs(a+4, accStore)
	be.PutUint32(c.S.Mem[b1:], c.GR[r1])
	be.PutUint32(c.S.Mem[b2:], c.GR[r1+1])
}
