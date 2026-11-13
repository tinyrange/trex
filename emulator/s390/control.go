package s390

import "fmt"

// execB2 handles B2xx S- and RRE-format instructions.
func (c *CPU) execB2() {
	op := c.op[:]
	a := c.eaBD(op[2], op[3])
	b := int(op[2] >> 4)
	r1, r2 := int(op[3]>>4), int(op[3]&0xf)
	switch op[1] {
	case 0x02: // STIDP
		c.privileged()
		if a&7 != 0 {
			c.program(pgmSpecification)
		}
		c.storeDouble(a, b, uint64(0x00)<<56|uint64(c.M.cfg.CPUSerial&0xffffff)<<32|uint64(c.M.cfg.CPUModel)<<16)
	case 0x03: // STIDC (System/370)
		if !c.M.S370 {
			c.unknown()
		}
		c.stidc(a)
	case 0x13: // RRB (System/370)
		if !c.M.S370 {
			c.unknown()
		}
		c.rrb370(a)
	case 0x5f: // CHSC
		c.privileged()
		c.chsc(r1)
	case 0xb1: // STFL
		c.privileged()
		c.setLowWord(0xc8, c.M.Facilities)
	case 0x04: // SCK
		c.privileged()
		if a&7 != 0 {
			c.program(pgmSpecification)
		}
		v := c.fetchDouble(a, b)
		c.M.event("sck", c, fmt.Sprintf("tod %016X -> %016X", c.M.tod, v))
		c.M.tod = v
		c.PSW.CC = 0
	case 0x05: // STCK
		if c.sie != nil && c.sie.ic[2]&0x80 != 0 {
			panic(sieExitRequest{code: sieCodeInst})
		}
		t := c.M.stck()
		if c.sie != nil {
			t += c.sie.epoch
		}
		c.stores++ // a loop reading the clock is timing, not idling
		c.storeDouble(a, b, t)
		c.PSW.CC = 0
	case 0x06: // SCKC
		c.privileged()
		if a&7 != 0 {
			c.program(pgmSpecification)
		}
		c.ClockComparator = c.fetchDouble(a, b)
		c.pswChanged = true
	case 0x07: // STCKC
		c.privileged()
		if a&7 != 0 {
			c.program(pgmSpecification)
		}
		c.storeDouble(a, b, c.ClockComparator)
	case 0x08: // SPT
		c.privileged()
		if a&7 != 0 {
			c.program(pgmSpecification)
		}
		v := int64(c.fetchDouble(a, b))
		c.setCPUTimer(v)
		c.pswChanged = true
	case 0x09: // STPT
		c.privileged()
		if a&7 != 0 {
			c.program(pgmSpecification)
		}
		c.stores++
		c.storeDouble(a, b, uint64(c.cpuTimer()))
	case 0x0a: // SPKA
		if c.PSW.Problem && c.CR[3]&(0x80000000>>(a>>4&0xf)) == 0 {
			c.program(pgmPrivileged)
		}
		c.PSW.Key = byte(a>>4) & 0xf
		c.ipageValid = false
	case 0x0b: // IPK
		c.GR[2] = c.GR[2]&^0xff | uint32(c.PSW.Key)<<4
	case 0x0d: // PTLB
		c.privileged()
		c.purgeTLB()
	case 0x10: // SPX
		c.privileged()
		if a&3 != 0 {
			c.program(pgmSpecification)
		}
		p := c.fetchWord(a, b) & 0x7ffff000
		if !c.S.valid(p, 4096) {
			c.program(pgmAddressing)
		}
		c.Prefix = p
		c.purgeTLB()
		c.ipageValid = false
	case 0x11: // STPX
		c.privileged()
		if a&3 != 0 {
			c.program(pgmSpecification)
		}
		c.storeWord(a, b, c.Prefix)
	case 0x12: // STAP
		c.privileged()
		if a&1 != 0 {
			c.program(pgmSpecification)
		}
		if c.sie != nil {
			c.storeHalf(a, b, c.sie.cpuad)
		} else {
			c.storeHalf(a, b, c.Addr)
		}
	case 0x14: // SIE
		c.privileged()
		c.sieEnter(a, b)
	case 0x18: // PC
		c.pc(a)
	case 0x19: // SAC
		c.sac(a)
	case 0x1a: // CFC
		c.unknown()
	case 0x20: // SERVC
		c.privileged()
		c.M.sclp.servc(c, c.GR[r1], c.GR[r2])
	case 0x21: // IPTE
		c.privileged()
		pto := c.GR[r1] & 0x7fffffc0
		px := c.GR[r2] >> 12 & 0xff
		ea := (pto + px*4) & 0x7fffffff
		abs := c.realAbs(ea, accStore)
		be.PutUint32(c.S.Mem[abs:], be.Uint32(c.S.Mem[abs:])|0x400)
		for _, o := range c.M.CPUs {
			o.purgeTLB()
		}
	case 0x22: // IPM
		c.GR[r1] = c.GR[r1]&0x00ffffff | uint32(c.PSW.CC)<<28 | uint32(c.PSW.ProgMask)<<24
	case 0x23: // IVSK
		c.extraction()
		x := c.GR[r2] & c.amask
		real, _ := c.translate(x, c.stdFor(accFetch, r2), accFetch)
		abs := c.realToAbs(real)
		if !c.S.valid(abs, 1) {
			c.program(pgmAddressing)
		}
		c.GR[r1] = c.GR[r1]&^0xff | uint32(*c.S.key(abs)&0xf8)
	case 0x24: // IAC
		c.extraction()
		// PSW bits 16-17 in reversed order: 0 primary, 1 secondary,
		// 2 access register, 3 home (the SET ADDRESS SPACE CONTROL code).
		code := c.PSW.AS>>1 | c.PSW.AS&1<<1
		c.GR[r1] = c.GR[r1]&^0xff00 | uint32(code)<<8
		c.PSW.CC = code
	case 0x25: // SSAR
		c.ssar(uint16(c.GR[r1]))
	case 0x26: // EPAR
		c.extraction()
		c.GR[r1] = c.CR[4] & 0xffff
	case 0x27: // ESAR
		c.extraction()
		c.GR[r1] = c.CR[3] & 0xffff
	case 0x29: // ISKE
		c.privileged()
		abs := c.realToAbs(c.GR[r2] & 0x7fffffff)
		if !c.S.valid(abs, 1) {
			c.program(pgmAddressing)
		}
		c.GR[r1] = c.GR[r1]&^0xff | uint32(*c.S.key(abs)&0xfe)
	case 0x2a: // RRBE
		c.privileged()
		abs := c.realToAbs(c.GR[r2] & 0x7fffffff)
		if !c.S.valid(abs, 1) {
			c.program(pgmAddressing)
		}
		k := c.S.key(abs)
		c.PSW.CC = (*k >> 1) & 3
		*k &^= keyRef
		c.M.keyGen++
	case 0x2b: // SSKE
		c.privileged()
		abs := c.realToAbs(c.GR[r2] & 0x7fffffff)
		if !c.S.valid(abs, 1) {
			c.program(pgmAddressing)
		}
		*c.S.key(abs) = byte(c.GR[r1]) & 0xfe
		c.M.keyGen++
		for _, o := range c.M.CPUs {
			o.ipageValid = false
		}
	case 0x2c: // TB: test and clear a 4K block
		c.privileged()
		abs := c.realToAbs(c.GR[r2] & 0x7ffff000)
		if !c.S.valid(abs, 4096) {
			c.program(pgmAddressing)
		}
		if c.CR[0]&0x10000000 != 0 && c.GR[r2]&0x7ffff000 == 0 {
			c.program(pgmProtection)
		}
		blk := c.S.Mem[abs : abs+4096]
		for i := range blk {
			blk[i] = 0
		}
		*c.S.key(abs) |= keyRef | keyChg
		c.icache.invalidatePage(abs)
		c.GR[0] = 0
		c.PSW.CC = 0
	case 0x2d: // DXR
		c.hfpDXR(r1, r2)
	case 0x2e, 0x2f: // PGIN, PGOUT: no expanded storage
		c.privileged()
		c.PSW.CC = 3
	case 0x30:
		c.csch()
	case 0x31:
		c.hsch()
	case 0x32:
		c.msch(a, b)
	case 0x33:
		c.ssch(a, b)
	case 0x34:
		c.stsch(a, b)
	case 0x35:
		c.tsch(a, b)
	case 0x36:
		c.tpi(a, b)
	case 0x37: // SAL
		c.privileged()
	case 0x38:
		c.rsch()
	case 0x39:
		c.stcrw(a, b)
	case 0x3a: // STCPS
		c.privileged()
		for i := uint32(0); i < 32; i++ {
			c.storeByte(a+i, b, 0)
		}
	case 0x3b: // RCHP
		c.privileged()
		c.PSW.CC = 3
	case 0x3c: // SCHM
		c.privileged()
	case 0x40: // BAKR
		c.bakr(r1, r2)
	case 0x41: // CKSM
		c.cksm(r1, r2)
	case 0x46: // STURA
		c.privileged()
		x := c.GR[r2] & 0x7fffffff
		if x&3 != 0 {
			c.program(pgmSpecification)
		}
		abs := c.realAbs(x, accStore)
		be.PutUint32(c.S.Mem[abs:], c.GR[r1])
		*c.S.key(abs) |= keyRef | keyChg
		c.icache.invalidatePage(abs)
	case 0x47: // MSTA
		c.msta(r1)
	case 0x48: // PALB
		c.privileged()
	case 0x49: // EREG
		c.ereg(r1, r2)
	case 0x4a: // ESTA
		c.esta(r1, r2)
	case 0x4b: // LURA
		c.privileged()
		x := c.GR[r2] & 0x7fffffff
		if x&3 != 0 {
			c.program(pgmSpecification)
		}
		abs := c.realAbs(x, accFetch)
		c.GR[r1] = be.Uint32(c.S.Mem[abs:])
	case 0x4c: // TAR
		c.PSW.CC = 0
		if c.AR[r1] > 1 {
			c.PSW.CC = 3
		}
	case 0x4d: // CPYA
		c.AR[r1] = c.AR[r2]
	case 0x4e: // SAR
		c.AR[r1] = c.GR[r2]
	case 0x4f: // EAR
		c.GR[r1] = c.AR[r2]
	case 0x28: // PT
		c.pt(r1, r2)
	case 0x50: // CSP
		c.privileged()
		c.even(r1)
		// General register R2 holds the second-operand address and the
		// purge controls (bit 31 purges the TLB). In ESA/390 the operand
		// is a logical address, translated when DAT is on.
		x := c.GR[r2] & 0x7ffffffc
		if !c.PSW.Amode31 {
			x &= 0x00fffffc
		}
		abs := c.absolute(x, accStore, r2)
		cur := be.Uint32(c.S.Mem[abs:])
		if cur == c.GR[r1] {
			be.PutUint32(c.S.Mem[abs:], c.GR[r1+1])
			c.PSW.CC = 0
			if c.GR[r2]&1 != 0 {
				for _, o := range c.M.CPUs {
					o.purgeTLB()
				}
			}
		} else {
			c.GR[r1] = cur
			c.PSW.CC = 1
		}
	case 0x52: // MSR
		c.GR[r1] = uint32(int32(c.GR[r1]) * int32(c.GR[r2]))
	case 0x54: // MVPG
		c.mvpg(r1, r2)
	case 0x55: // MVST
		c.mvst(r1, r2)
	case 0x57: // CUSE
		c.cuse(r1, r2)
	case 0xa6: // CUUTF
		c.cuutf(r1, r2)
	case 0xa7: // CUTFU
		c.cutfu(r1, r2)
	case 0x7d: // STSI
		c.privileged()
		c.stsi(a, b)
	case 0x5a: // BSA
		c.bsa(r1, r2)
	case 0x63: // CMPSC
		c.cmpsc(r1, r2)
	case 0x62: // LKPG
		c.privileged()
		c.lkpg(r1, r2)
	case 0x58: // BSG
		c.bsg(r1, r2)
	case 0x5d: // CLST
		c.clst(r1, r2)
	case 0x5e: // SRST
		c.srst(r1, r2)
	case 0x76: // XSCH
		c.xsch()
	case 0x78: // STCKE
		t := c.M.stck()
		c.checkStore(a, 16, b)
		c.storeByte(a, b, 0)
		c.storeDouble(a+1, b, t)
		for i := uint32(9); i < 16; i++ {
			c.storeByte(a+i, b, 0)
		}
		c.storeHalf(a+14, b, c.M.todProgrammable)
		c.PSW.CC = 0
	case 0x79: // SACF
		c.sac(a)
	case 0x99: // SRNM
		c.FPC = c.FPC&^3 | a&3
	case 0x9c: // STFPC
		c.storeWord(a, b, c.FPC)
	case 0x9d: // LFPC
		v := c.fetchWord(a, b)
		if v&0x07070700 != 0 {
			c.program(pgmSpecification)
		}
		c.FPC = v
	case 0xa5: // TRE
		c.tre(r1, r2)
	case 0xf0: // IUCV: simulated by the host for guests
		if c.sie != nil {
			panic(sieExitRequest{code: sieCodeInst})
		}
		c.unknown()
	case 0xff: // TRAP4
		c.unknown()
	default:
		c.unknown()
	}
}

func (m *Machine) stck() uint64 {
	t := m.tod
	if t <= m.lastStck {
		t = m.lastStck + 1
	}
	m.lastStck = t
	return t
}

// sac sets the address-space control.
func (c *CPU) sac(a uint32) {
	mode := byte(a>>8) & 0xf
	if !c.PSW.DAT {
		c.program(pgmSpecialOperation)
	}
	switch mode {
	case 0:
		c.PSW.AS = 0
	case 1:
		c.PSW.AS = 2
	case 2:
		c.PSW.AS = 1
	case 3:
		if c.PSW.Problem {
			c.program(pgmPrivileged)
		}
		c.PSW.AS = 3
	default:
		c.program(pgmSpecification)
	}
	c.ipageValid = false
}

// alet performs access-register translation of an access-list-entry token
// to a segment-table designation.
func (c *CPU) alet(a uint32, acc access) uint32 {
	switch a {
	case 0:
		return c.CR[1]
	case 1:
		return c.CR[7]
	}
	if a&0xfe000000 != 0 {
		c.program(pgmALETSpecification)
	}
	// Access-list designation: DU-AL from the DUCT, or the primary AL from
	// the primary ASTE.
	var ald uint32
	if a&0x01000000 == 0 {
		duct := c.CR[2] & 0x7fffffc0
		ald = c.readRealWord(duct + 16)
	} else {
		paste := c.CR[5] & 0x7fffffc0
		ald = c.readRealWord(paste + 16)
	}
	alo := ald & 0x7fffff80
	all := ald & 0x7f
	alen := a & 0xffff
	if alen>>3 > all {
		c.program(pgmALENTranslation)
	}
	ale := alo + alen*16
	w0 := c.readRealWord(ale)
	if w0&0x80000000 != 0 {
		c.program(pgmALENTranslation)
	}
	if byte(w0>>16) != byte(a>>16) {
		c.program(pgmALESequence)
	}
	asteo := c.readRealWord(ale+8) & 0x7fffffc0
	astesn := c.readRealWord(ale + 12)
	aw0 := c.readRealWord(asteo)
	if aw0&0x80000000 != 0 {
		c.program(pgmASTEValidity)
	}
	if c.readRealWord(asteo+20) != astesn {
		c.program(pgmASTESequence)
	}
	if w0&0x01000000 != 0 { // private: extended authorization
		eax := c.CR[8] >> 16
		if eax != w0&0xffff {
			ato := aw0 & 0x7ffffffc
			atl := c.readRealWord(asteo+4) & 0xfff0
			if eax>>2 > atl>>4<<2|3 && eax>>2 > atl {
				c.program(pgmExtendedAuthority)
			}
			b := c.S.Mem[c.realAbs(ato+eax/4, accFetch)]
			if b&(0x40>>(2*(eax%4))) == 0 {
				c.program(pgmExtendedAuthority)
			}
		}
	}
	if acc == accStore && w0&0x02000000 != 0 { // fetch-only
		c.program(pgmProtection)
	}
	return c.readRealWord(asteo + 8)
}

// lra performs LOAD REAL ADDRESS.
func (c *CPU) lra(r1 int, a uint32, b int) {
	std := c.stdFor(accFetch, b)
	if c.PSW.AS == 1 && b != 0 {
		std = c.alet(c.AR[b], accFetch)
	}
	v := a & 0x7fffffff
	sto := std & 0x7ffff000
	stl := std & 0x7f
	sx := v >> 20
	if sx>>4 > stl {
		c.GR[r1] = 0x80000000 | (sto+sx*4)&0x7fffffff
		c.PSW.CC = 3
		return
	}
	steAddr := (sto + sx*4) & 0x7fffffff
	ste := c.readRealWord(steAddr)
	if ste&0x20 != 0 {
		c.GR[r1] = steAddr
		c.PSW.CC = 1
		return
	}
	pto := ste & 0x7fffffc0
	ptl := ste & 0xf
	px := (v >> 12) & 0xff
	if px>>4 > ptl {
		c.GR[r1] = 0x80000000 | (pto+px*4)&0x7fffffff
		c.PSW.CC = 3
		return
	}
	pteAddr := (pto + px*4) & 0x7fffffff
	pte := c.readRealWord(pteAddr)
	if pte&0x400 != 0 {
		c.GR[r1] = pteAddr
		c.PSW.CC = 2
		return
	}
	c.GR[r1] = pte&0x7ffff000 | v&0xfff
	c.PSW.CC = 0
}

// diagnose is model dependent; this model implements none.
func (c *CPU) diagnose(r1, r3 int, a uint32) {
	c.program(pgmSpecification)
}

// SIGNAL PROCESSOR orders.
func (c *CPU) sigp(r1, r3 int, a uint32) {
	order := a & 0xff
	addr := uint16(c.GR[r3])
	var t *CPU
	for _, o := range c.M.CPUs {
		if o.Addr == addr {
			t = o
		}
	}
	if t == nil {
		c.PSW.CC = 3
		return
	}
	status := uint32(0)
	switch order {
	case 0x01: // sense
		if t.Stopped {
			status |= 0x40
		}
		if t.Check {
			status |= 0x10
		}
		if status == 0 {
			c.PSW.CC = 0
			return
		}
	case 0x02: // external call
		t.extPending |= extExternalCall
		t.extCallFrom = c.Addr
		t.pswChanged = true
	case 0x03: // emergency signal
		t.extPending |= extEmergency
		t.emergency |= 1 << c.Addr
		t.pswChanged = true
	case 0x04: // start
		t.Stopped = false
	case 0x05, 0x06: // stop, restart
		if order == 0x05 {
			t.Stopped = true
		} else {
			t.Restart()
		}
	case 0x09: // stop and store status
		t.storeStatus(t.Prefix)
		t.Stopped = true
	case 0x0b, 0x0c: // initial CPU reset, CPU reset
		t.Reset(order == 0x0b)
	case 0x0d: // set prefix
		if t.Stopped {
			t.Prefix = c.GR[r1] & 0x7ffff000
			t.purgeTLB()
		} else {
			status |= 0x200
		}
	case 0x0e: // store status at address
		t.storeStatus(c.GR[r1] & 0x7ffffe00)
	case 0x12: // set architecture: ESA/390 only
		status |= 0x200
	default:
		status |= 0x2 // invalid order
	}
	if status != 0 {
		c.GR[r1] = status
		c.PSW.CC = 1
		return
	}
	c.PSW.CC = 0
}

// storeStatus stores the architected status at an absolute address.
func (c *CPU) storeStatus(base uint32) {
	m := c.S.Mem
	be.PutUint64(m[base+0xd8:], uint64(c.cpuTimer()))
	be.PutUint64(m[base+0xe0:], c.ClockComparator>>8)
	be.PutUint64(m[base+0x100:], c.PSW.Encode())
	be.PutUint32(m[base+0x108:], c.Prefix)
	for i := 0; i < 16; i++ {
		be.PutUint32(m[base+0x120+uint32(i)*4:], c.AR[i])
		be.PutUint32(m[base+0x180+uint32(i)*4:], c.GR[i])
		be.PutUint32(m[base+0x1c0+uint32(i)*4:], c.CR[i])
	}
	for i := 0; i < 4; i++ {
		be.PutUint64(m[base+0x160+uint32(i)*8:], c.FPR[i*2])
	}
}

// Linkage-stack instructions are not provided by this model: CP running
// natively does not require them. They raise operation exceptions so a guest
// probing for them sees a consistent machine.

// mvpg: MOVE PAGE (real or primary-virtual 4K pages).
func (c *CPU) mvpg(r1, r2 int) {
	if c.GR[0]&0xfffff000 != 0 {
		c.program(pgmSpecification)
	}
	dst := c.GR[r1] & c.amask &^ 0xfff
	src := c.GR[r2] & c.amask &^ 0xfff
	s := c.span(src, 4096, accFetch, r2)
	d := c.span(dst, 4096, accStore, r1)
	copy(d, s)
	c.PSW.CC = 0
}

func (c *CPU) cksm(r1, r2 int) {
	c.even(r2)
	sum := uint64(c.GR[r1])
	a := c.GR[r2] & c.amask
	n := c.GR[r2+1]
	for n > 0 {
		var w uint32
		take := uint32(4)
		if n < 4 {
			take = n
		}
		for i := uint32(0); i < take; i++ {
			w |= uint32(c.fetchByte(a+i, r2)) << (24 - 8*i)
		}
		sum += uint64(w)
		sum = sum&0xffffffff + sum>>32
		a = (a + take) & c.amask
		n -= take
	}
	c.GR[r1] = uint32(sum)
	c.GR[r2] = a
	c.GR[r2+1] = 0
	c.PSW.CC = 0
}

func (c *CPU) mvst(r1, r2 int) {
	if c.GR[0]&0xffffff00 != 0 {
		c.program(pgmSpecification)
	}
	end := byte(c.GR[0])
	d := c.GR[r1] & c.amask
	s := c.GR[r2] & c.amask
	for i := 0; i < 4096; i++ {
		x := c.fetchByte(s, r2)
		c.storeByte(d, r1, x)
		if x == end {
			c.GR[r1] = d
			c.PSW.CC = 1
			return
		}
		d = (d + 1) & c.amask
		s = (s + 1) & c.amask
	}
	c.GR[r1] = d
	c.GR[r2] = s
	c.PSW.CC = 3
}

func (c *CPU) clst(r1, r2 int) {
	if c.GR[0]&0xffffff00 != 0 {
		c.program(pgmSpecification)
	}
	end := byte(c.GR[0])
	a := c.GR[r1] & c.amask
	b := c.GR[r2] & c.amask
	for i := 0; i < 4096; i++ {
		x := c.fetchByte(a, r1)
		y := c.fetchByte(b, r2)
		if x == end && y == end {
			c.PSW.CC = 0
			return
		}
		if x == end || y == end || x != y {
			c.GR[r1], c.GR[r2] = a, b
			switch {
			case x == end:
				c.PSW.CC = 1
			case y == end:
				c.PSW.CC = 2
			case x < y:
				c.PSW.CC = 1
			default:
				c.PSW.CC = 2
			}
			return
		}
		a = (a + 1) & c.amask
		b = (b + 1) & c.amask
	}
	c.GR[r1], c.GR[r2] = a, b
	c.PSW.CC = 3
}

func (c *CPU) srst(r1, r2 int) {
	if c.GR[0]&0xffffff00 != 0 {
		c.program(pgmSpecification)
	}
	ch := byte(c.GR[0])
	end := c.GR[r1] & c.amask
	a := c.GR[r2] & c.amask
	for i := 0; i < 4096; i++ {
		if a == end {
			c.PSW.CC = 2
			return
		}
		if c.fetchByte(a, r2) == ch {
			c.GR[r1] = a
			c.PSW.CC = 1
			return
		}
		a = (a + 1) & c.amask
	}
	c.GR[r2] = a
	c.PSW.CC = 3
}

func (c *CPU) tre(r1, r2 int) {
	c.even(r1)
	test := byte(c.GR[0])
	a := c.GR[r1] & c.amask
	n := c.GR[r1+1]
	t := c.GR[r2] & c.amask
	for i := 0; i < 4096 && n > 0; i++ {
		x := c.fetchByte(a, r1)
		if x == test {
			c.GR[r1], c.GR[r1+1] = a, n
			c.PSW.CC = 1
			return
		}
		c.storeByte(a, r1, c.fetchByte(t+uint32(x), r2))
		a = (a + 1) & c.amask
		n--
	}
	c.GR[r1], c.GR[r1+1] = a, n
	if n == 0 {
		c.PSW.CC = 0
	} else {
		c.PSW.CC = 3
	}
}

// execB9 handles the few B9xx instructions available in ESA/390.
func (c *CPU) execB9() {
	c.unknown()
}

// execE5 handles E5xx SSE-format instructions.
func (c *CPU) execE5() {
	op := c.op[:]
	a1 := c.eaBD(op[2], op[3])
	a2 := c.eaBD(op[4], op[5])
	b1, b2 := int(op[2]>>4), int(op[4]>>4)
	switch op[1] {
	case 0x00: // LASP
		c.privileged()
		c.lasp(a1, b1, a2)
	case 0x01: // TPROT
		c.privileged()
		key := byte(a2>>4) & 0xf
		c.tprot(a1, b1, key)
	case 0x0e, 0x0f: // MVCSK, MVCDK
		c.privileged()
		n := (c.GR[0] & 0xff) + 1
		key := byte(c.GR[1]>>4) & 0xf
		for i := uint32(0); i < n; i++ {
			var x byte
			if op[1] == 0x0e {
				x = c.fetchByteKey(a2+i, b2, key)
				c.storeByte(a1+i, b1, x)
			} else {
				x = c.fetchByte(a2+i, b2)
				c.storeByteKey(a1+i, b1, x, key)
			}
		}
	default:
		_ = b2
		c.unknown()
	}
}

func (c *CPU) withKey(key byte, f func()) {
	save := c.PSW.Key
	c.PSW.Key = key
	defer func() { c.PSW.Key = save }()
	f()
}

func (c *CPU) fetchByteKey(v uint32, b int, key byte) (x byte) {
	c.withKey(key, func() { x = c.fetchByte(v, b) })
	return
}

func (c *CPU) storeByteKey(v uint32, b int, x byte, key byte) {
	c.withKey(key, func() { c.storeByte(v, b, x) })
}

// tprot: TEST PROTECTION.
func (c *CPU) tprot(v uint32, b int, key byte) {
	v &= c.amask
	real := v
	prot := false
	if c.PSW.DAT {
		func() {
			defer func() {
				if r := recover(); r != nil {
					pc, ok := r.(programCheck)
					if !ok {
						panic(r)
					}
					if pc.code == pgmSegment || pc.code == pgmPage {
						c.PSW.CC = 3
						real = ^uint32(0)
						return
					}
					panic(r)
				}
			}()
			real, prot = c.translate(v, c.stdFor(accFetch, b), accFetch)
		}()
		if real == ^uint32(0) {
			return
		}
	}
	abs := c.realAbs(real, accFetch)
	k := *c.S.key(abs)
	spo := k>>4 == 9 && c.CR[0]&0x01000000 != 0 // storage-protection override
	fpo := v < 2048 && c.CR[0]&0x02000000 != 0  // fetch-protection override
	fetchOK := key == 0 || k>>4 == key || k&keyFetch == 0 || spo || fpo
	storeOK := (key == 0 || k>>4 == key || spo) && !prot
	switch {
	case fetchOK && storeOK:
		c.PSW.CC = 0
	case fetchOK:
		c.PSW.CC = 1
	default:
		c.PSW.CC = 2
	}
}

// mvcKey handles MVCK, MVCP and MVCS.
func (c *CPU) mvcKey() {
	op := c.op[:]
	r1, r3 := int(op[1]>>4), int(op[1]&0xf)
	a1 := c.eaBD(op[2], op[3])
	a2 := c.eaBD(op[4], op[5])
	b1, b2 := int(op[2]>>4), int(op[4]>>4)
	n := c.GR[r1]
	key := byte(c.GR[r3]>>4) & 0xf
	cc := byte(0)
	if n > 256 {
		n = 256
		cc = 3
	}
	switch op[0] {
	case 0xd9: // MVCK: source accessed with key
		for i := uint32(0); i < n; i++ {
			c.storeByte(a1+i, b1, c.fetchByteKey(a2+i, b2, key))
		}
	case 0xda, 0xdb: // MVCP, MVCS: primary/secondary moves
		dstAS, srcAS := byte(4|0), byte(4|2)
		if op[0] == 0xdb {
			dstAS, srcAS = 4|2, 4|0
		}
		defer func() { c.spaceOverride = 0 }()
		for i := uint32(0); i < n; i++ {
			c.spaceOverride = srcAS
			var x byte
			if op[0] == 0xda {
				x = c.fetchByteKey(a2+i, b2, key)
			} else {
				x = c.fetchByte(a2+i, b2)
			}
			c.spaceOverride = dstAS
			if op[0] == 0xda {
				c.storeByte(a1+i, b1, x)
			} else {
				c.storeByteKey(a1+i, b1, x, key)
			}
		}
	}
	c.PSW.CC = cc
}

// icache is a placeholder for a decoded-instruction cache.
type icache struct{}

func (icache) invalidatePage(uint32) {}
func (icache) invalidateAll()        {}

// chsc performs CHANNEL SUBSYSTEM CALL. The request block names a command;
// none of the optional CHSC commands are installed, so every well-formed
// request is answered with response code 0004 (command not provided).
func (c *CPU) chsc(r1 int) {
	addr := c.GR[r1] & c.amask
	if addr&0xfff != 0 {
		c.program(pgmSpecification)
	}
	abs := c.realAbs(addr, accFetch)
	req := uint32(be.Uint16(c.S.Mem[abs:]))
	if req < 16 || req > 4096-16 || req&7 != 0 {
		c.program(pgmOperand)
	}
	resp := abs + req
	c.realAbs(addr+req, accStore)
	be.PutUint16(c.S.Mem[resp:], 8)
	be.PutUint16(c.S.Mem[resp+2:], 0x0004)
	be.PutUint32(c.S.Mem[resp+4:], 0)
	*c.S.key(abs) |= keyRef | keyChg
	c.M.event("chsc", c, fmt.Sprintf("command %04X not provided", be.Uint16(c.S.Mem[abs+2:])))
	c.PSW.CC = 0
}

// asnTranslate locates the ASN-second-table entry for an ASN through the
// ASN first table designated by control register 14. ok is false when the
// first-table entry or the ASTE is invalid.
func (c *CPU) asnTranslate(asn uint16) (asteo uint32, ok bool) {
	afto := (c.CR[14] & 0x7ffff) << 12 // bits 13-31
	afte := c.readRealWord(afto + uint32(asn>>6)*4)
	if afte&0x80000000 != 0 {
		return 0, false
	}
	asteo = afte&0x7fffffc0 + uint32(asn&0x3f)*64
	if c.readRealWord(asteo)&0x80000000 != 0 {
		return 0, false
	}
	return asteo, true
}

// secondaryAuthorized applies the secondary-authority test of an ASTE's
// authority table for an authorization index.
func (c *CPU) secondaryAuthorized(asteo uint32, ax uint16) bool {
	ato := c.readRealWord(asteo) & 0x7ffffffc
	atl := (c.readRealWord(asteo+4) >> 4) & 0xfff
	if uint32(ax>>4) > atl {
		return false
	}
	b := c.S.Mem[c.realAbs(ato+uint32(ax)/4, accFetch)]
	return b&(0x40>>((ax%4)*2)) != 0
}

// lasp is LOAD ADDRESS SPACE PARAMETERS. The second-operand address bits
// 29-31 force ASN translation, take the AX from the first operand, and skip
// SASN authorization. Condition codes: 0 loaded, 1 PASN not available,
// 2 SASN not available or not authorized, 3 space-switch event.
func (c *CPU) lasp(a uint32, b int, ctl uint32) {
	if c.CR[14]&0x00080000 == 0 {
		c.program(pgmSpecialOperation)
	}
	if a&7 != 0 {
		c.program(pgmSpecification)
	}
	v := c.fetchDouble(a, b)
	pkm, sasn, ax, pasn := uint16(v>>48), uint16(v>>32), uint16(v>>16), uint16(v)
	force, axFromOperand, skipAuth := ctl&4 != 0, ctl&2 != 0, ctl&1 != 0
	oldPASN, oldSASN := uint16(c.CR[4]), uint16(c.CR[3])
	pstd, pasteo, newAX := c.CR[1], c.CR[5], uint16(c.CR[4]>>16)
	translatedP := false
	if force || pasn != oldPASN {
		asteo, ok := c.asnTranslate(pasn)
		if !ok {
			c.PSW.CC = 1
			return
		}
		std := c.readRealWord(asteo + 8)
		if c.CR[1]&0x80000000 != 0 || std&0x80000000 != 0 {
			c.PSW.CC = 3 // space-switch event
			return
		}
		pstd, pasteo, translatedP = std, asteo, true
		newAX = uint16(c.readRealWord(asteo+4) >> 16)
	}
	if axFromOperand {
		newAX = ax
	}
	sstd := c.CR[7]
	switch {
	case sasn == pasn:
		sstd = pstd
	case sasn == oldSASN && !force && skipAuth:
		// SASN unchanged: no translation.
	default:
		asteo, ok := c.asnTranslate(sasn)
		if !ok {
			c.PSW.CC = 2
			return
		}
		if !skipAuth && !c.secondaryAuthorized(asteo, newAX) {
			c.PSW.CC = 2
			return
		}
		sstd = c.readRealWord(asteo + 8)
	}
	c.CR[3] = uint32(pkm)<<16 | uint32(sasn)
	c.CR[4] = uint32(newAX)<<16 | uint32(pasn)
	if translatedP {
		c.CR[1] = pstd
		c.CR[5] = pasteo & 0x7fffffc0
	}
	c.CR[7] = sstd
	c.PSW.CC = 0
}

// plo is PERFORM LOCKED OPERATION. With one CPU executing at a time the
// lock is implicit. Function codes that are multiples of 4 operate on words
// in general registers; one more than a multiple of 4 operate on
// doublewords in a parameter list addressed by D4(B4).
func (c *CPU) plo(r1, r3 int, a2 uint32, b2 int, a4 uint32, b4 int) {
	g0 := c.GR[0]
	fc := g0 & 0xff
	valid := fc <= 21 && fc%4 <= 1
	if g0&0x100 != 0 { // test bit
		if g0&0xfffffe00 != 0 {
			c.program(pgmSpecification)
		}
		c.PSW.CC = 0
		if !valid {
			c.PSW.CC = 3
		}
		return
	}
	if !valid || g0&0xffffff00 != 0 {
		c.program(pgmSpecification)
	}
	op := fc / 4
	long := fc%4 == 1
	if !long {
		if op >= 1 && r1%2 != 0 || op == 2 && r3%2 != 0 || a2&3 != 0 {
			c.program(pgmSpecification)
		}
		if (op == 0 || op == 2 || op == 3) && a4&3 != 0 || op >= 4 && a4&7 != 0 {
			c.program(pgmSpecification)
		}
		cur := c.fetchWord(a2, b2)
		if cur != c.GR[r1] {
			c.GR[r1] = cur
			c.PSW.CC = 1
			return
		}
		switch op {
		case 0: // compare and load
			c.GR[r3] = c.fetchWord(a4, b4)
		case 1: // compare and swap
			c.storeWord(a2, b2, c.GR[r1+1])
		case 2: // double compare and swap
			cur4 := c.fetchWord(a4, b4)
			if cur4 != c.GR[r3] {
				c.GR[r3] = cur4
				c.PSW.CC = 2
				return
			}
			c.checkStore(a2, 4, b2)
			c.checkStore(a4, 4, b4)
			c.storeWord(a2, b2, c.GR[r1+1])
			c.storeWord(a4, b4, c.GR[r3+1])
		case 3: // compare and swap and store
			c.checkStore(a2, 4, b2)
			c.checkStore(a4, 4, b4)
			c.storeWord(a2, b2, c.GR[r1+1])
			c.storeWord(a4, b4, c.GR[r3])
		case 4, 5: // compare and swap and double/triple store
			type st struct{ addr, val uint32 }
			stores := []st{{c.fetchWord(a4+76, b4) & c.amask, c.fetchWord(a4+60, b4)},
				{c.fetchWord(a4+108, b4) & c.amask, c.fetchWord(a4+92, b4)}}
			if op == 5 {
				stores = append(stores, st{c.fetchWord(a4+140, b4) & c.amask, c.fetchWord(a4+124, b4)})
			}
			c.checkStore(a2, 4, b2)
			for _, s := range stores {
				if s.addr&3 != 0 {
					c.program(pgmSpecification)
				}
				c.checkStore(s.addr, 4, b4)
			}
			c.storeWord(a2, b2, c.GR[r1+1])
			for _, s := range stores {
				c.storeWord(s.addr, b4, s.val)
			}
		}
		c.PSW.CC = 0
		return
	}
	// Doubleword operands; comparison and replacement values in the list.
	if a2&7 != 0 || a4&7 != 0 {
		c.program(pgmSpecification)
	}
	pl := a4
	cur := c.fetchDouble(a2, b2)
	if cmp := c.fetchDouble(pl+8, b4); cur != cmp {
		c.storeDouble(pl+8, b4, cur)
		c.PSW.CC = 1
		return
	}
	addr := func(off uint32) uint32 {
		a := c.fetchWord(pl+off+4, b4) & c.amask
		if a&7 != 0 {
			c.program(pgmSpecification)
		}
		return a
	}
	switch op {
	case 0: // compare and load
		c.storeDouble(pl+40, b4, c.fetchDouble(addr(72), b4))
	case 1:
		c.storeDouble(a2, b2, c.fetchDouble(pl+24, b4))
	case 2:
		a := addr(72)
		cur4 := c.fetchDouble(a, b4)
		if cmp := c.fetchDouble(pl+40, b4); cur4 != cmp {
			c.storeDouble(pl+40, b4, cur4)
			c.PSW.CC = 2
			return
		}
		c.checkStore(a2, 8, b2)
		c.checkStore(a, 8, b4)
		c.storeDouble(a2, b2, c.fetchDouble(pl+24, b4))
		c.storeDouble(a, b4, c.fetchDouble(pl+56, b4))
	default: // store, double store, triple store
		type st struct {
			addr uint32
			val  uint64
		}
		stores := []st{{addr(72), c.fetchDouble(pl+56, b4)}}
		if op >= 4 {
			stores = append(stores, st{addr(104), c.fetchDouble(pl+88, b4)})
		}
		if op == 5 {
			stores = append(stores, st{addr(136), c.fetchDouble(pl+120, b4)})
		}
		c.checkStore(a2, 8, b2)
		for _, s := range stores {
			c.checkStore(s.addr, 8, b4)
		}
		c.storeDouble(a2, b2, c.fetchDouble(pl+24, b4))
		for _, s := range stores {
			c.storeDouble(s.addr, b4, s.val)
		}
	}
	c.PSW.CC = 0
}

// cuse is COMPARE UNTIL SUBSTRING EQUAL: the operands (address in R, length
// in R+1, the shorter padded with the byte in GR1 bits 24-31) are compared
// for a run of equal bytes of the length in GR0 bits 24-31. CC 0: found
// (registers address it), 1: equal bytes at the end shorter than the
// substring length (registers address them), 2: none.
func (c *CPU) cuse(r1, r2 int) {
	c.even(r1)
	c.even(r2)
	ss := c.GR[0] & 0xff
	if ss == 0 {
		c.PSW.CC = 0
		return
	}
	pad := byte(c.GR[1])
	a1, l1 := c.GR[r1]&c.amask, c.GR[r1+1]
	a2, l2 := c.GR[r2]&c.amask, c.GR[r2+1]
	n := max(l1, l2)
	run, start := uint32(0), uint32(0)
	set := func(at uint32) {
		adv1, adv2 := min(at, l1), min(at, l2)
		c.GR[r1] = c.GR[r1]&^c.amask | (a1+adv1)&c.amask
		c.GR[r2] = c.GR[r2]&^c.amask | (a2+adv2)&c.amask
		c.GR[r1+1], c.GR[r2+1] = l1-adv1, l2-adv2
	}
	for i := uint32(0); i < n; i++ {
		b1, b2 := pad, pad
		if i < l1 {
			b1 = c.fetchByte(a1+i, r1)
		}
		if i < l2 {
			b2 = c.fetchByte(a2+i, r2)
		}
		if b1 != b2 {
			run = 0
			continue
		}
		if run == 0 {
			start = i
		}
		run++
		if run == ss {
			set(start)
			c.PSW.CC = 0
			return
		}
	}
	if run > 0 {
		set(start)
		c.PSW.CC = 1
		return
	}
	set(n)
	c.PSW.CC = 2
}

// pteAddress walks ESA/390 DAT for v in the address space of std and
// returns the real address of its page-table entry.
func (c *CPU) pteAddress(v, std uint32) (uint32, bool) {
	v &= 0x7fffffff
	sx := v >> 20
	if sx>>4 > std&0x7f {
		return 0, false
	}
	ste := c.readRealWord((std&0x7ffff000 + sx*4) & 0x7fffffff)
	if ste&0x20 != 0 {
		return 0, false
	}
	px := v >> 12 & 0xff
	if px>>4 > ste&0xf {
		return 0, false
	}
	return (ste&0x7fffffc0 + px*4) & 0x7fffffff, true
}

// lkpg is LOCK PAGE: GR0 bit 22 requests a lock (otherwise an unlock) of
// the page at the address in R2, using the page-lock bit (bit 31) of its
// page-table entry. CC 0 done (a lock also places the real address in R1),
// 1 already in the requested state, 3 the page is not translatable.
func (c *CPU) lkpg(r1, r2 int) {
	if !c.PSW.DAT {
		c.program(pgmSpecialOperation)
	}
	if c.GR[0]&0x0000fd00 != 0 {
		c.program(pgmSpecification)
	}
	v := c.GR[r2] & c.amask
	pa, ok := c.pteAddress(v, c.stdFor(accFetch, r2))
	if !ok {
		c.PSW.CC = 3
		return
	}
	abs := c.realAbs(pa, accStore)
	pte := be.Uint32(c.S.Mem[abs:])
	lock := c.GR[0]&0x200 != 0
	switch {
	case lock && pte&1 != 0, !lock && pte&1 == 0:
		c.PSW.CC = 1
		return
	case lock:
		if pte&0x400 != 0 {
			c.PSW.CC = 3
			return
		}
		be.PutUint32(c.S.Mem[abs:], pte|1)
		c.GR[r1] = pte&0x7ffff000 | v&0xfff
	default:
		be.PutUint32(c.S.Mem[abs:], pte&^1)
	}
	*c.S.key(abs) |= keyRef | keyChg
	c.PSW.CC = 0
}

// cmpsc is COMPRESSION CALL at its operand boundaries: an empty second
// operand ends the operation (CC 0) and an empty first operand with data
// remaining ends it with CC 1. Dictionary compression and expansion are not
// implemented; such requests are reported as an unknown operation.
func (c *CPU) cmpsc(r1, r2 int) {
	c.even(r1)
	c.even(r2)
	switch {
	case c.GR[r2+1] == 0:
		c.PSW.CC = 0
	case c.GR[r1+1] == 0:
		c.PSW.CC = 1
	default:
		c.unknown()
	}
}

// bsa is BRANCH AND SET AUTHORITY. Words 8 and 9 of the dispatchable-unit
// control table (CR2) hold the saved PSW bits 32-63 and the PKM, PSW key,
// reduced-authority bit (word 9 bit 28) and problem-state bit.
func (c *CPU) bsa(r1, r2 int) {
	if c.CR[0]&0x00010000 == 0 { // address-space-function control
		c.program(pgmSpecialOperation)
	}
	duct := c.CR[2] & 0x7fffffc0
	w9a := c.realAbs(duct+36, accStore)
	w8a := c.realAbs(duct+32, accStore)
	w9 := be.Uint32(c.S.Mem[w9a:])
	psw2 := func() uint32 {
		if c.PSW.Amode31 {
			return 0x80000000 | c.next&0x7fffffff
		}
		return c.next & 0x00ffffff
	}
	if w9&0x8 == 0 { // base-authority state
		if r2 == 0 {
			c.program(pgmSpecialOperation)
		}
		key := byte(c.GR[r1]>>4) & 0xf
		if c.PSW.Problem && c.CR[3]&(0x80000000>>key) == 0 {
			c.program(pgmPrivileged)
		}
		target := c.GR[r2]
		var p uint32
		if c.PSW.Problem {
			p = 1
		}
		be.PutUint32(c.S.Mem[w8a:], psw2())
		be.PutUint32(c.S.Mem[w9a:], c.CR[3]&0xffff0000|uint32(c.PSW.Key)<<4|0x8|p)
		*c.S.key(w9a) |= keyRef | keyChg
		c.PSW.Key = key
		c.CR[3] = c.CR[3]&0x0000ffff | c.CR[3]&c.GR[r1]&0xffff0000
		c.PSW.Problem = true
		c.PSW.Amode31 = target&0x80000000 != 0
		c.setAmode()
		c.next = target & c.amask
	} else { // reduced-authority state: return
		if r2 != 0 {
			c.program(pgmSpecialOperation)
		}
		if r1 != 0 {
			c.GR[r1] = psw2()
		}
		w8 := be.Uint32(c.S.Mem[w8a:])
		c.CR[3] = c.CR[3]&0x0000ffff | w9&0xffff0000
		c.PSW.Key = byte(w9>>4) & 0xf
		c.PSW.Problem = w9&1 != 0
		be.PutUint32(c.S.Mem[w9a:], w9&^0x8)
		*c.S.key(w9a) |= keyRef | keyChg
		c.PSW.Amode31 = w8&0x80000000 != 0
		c.setAmode()
		if !c.PSW.Amode31 && w8&0x7f000000 != 0 {
			c.earlySpec = true
		}
		c.next = w8 & c.amask
	}
	c.pswChanged = true
}

// bsg is BRANCH IN SUBSPACE GROUP: the ALET in access register R2 (0 for
// the base space, 1 for the last subspace entered, otherwise an access-list
// entry) selects a destination ASTE in the dispatchable unit's subspace
// group, whose STD becomes the primary STD before the branch.
func (c *CPU) bsg(r1, r2 int) {
	if c.CR[0]&0x00010000 == 0 || !c.PSW.DAT {
		c.program(pgmSpecialOperation)
	}
	duct := c.CR[2] & 0x7fffffc0
	basteo := c.readRealWord(duct) & 0x7fffffc0
	if c.CR[5]&0x7fffffc0 != basteo {
		c.program(pgmSpecialOperation) // primary not in the subspace group
	}
	var alet uint32
	if r2 != 0 {
		alet = c.AR[r2]
	}
	var dasteo uint32
	base, viaALE := false, false
	switch alet {
	case 0:
		dasteo, base = basteo, true
	case 1:
		dasteo = c.readRealWord(duct+4) & 0x7fffffc0
		if dasteo == 0 {
			c.program(pgmSpecialOperation)
		}
		if c.readRealWord(dasteo)&0x80000000 != 0 {
			c.program(pgmASTEValidity)
		}
		if c.readRealWord(dasteo+20) != c.readRealWord(duct+12) {
			c.program(pgmASTESequence)
		}
	default:
		if alet&0xfe000000 != 0 {
			c.program(pgmALETSpecification)
		}
		var ald uint32
		if alet&0x01000000 == 0 {
			ald = c.readRealWord(duct + 16)
		} else {
			ald = c.readRealWord(basteo + 16)
		}
		alen := alet & 0xffff
		if alen>>3 > ald&0x7f {
			c.program(pgmALENTranslation)
		}
		ale := ald&0x7fffff80 + alen*16
		if c.readRealWord(ale)&0x80000000 != 0 {
			c.program(pgmALENTranslation)
		}
		dasteo = c.readRealWord(ale+8) & 0x7fffffc0
		if c.readRealWord(dasteo)&0x80000000 != 0 {
			c.program(pgmASTEValidity)
		}
		if c.readRealWord(dasteo+20) != c.readRealWord(ale+12) {
			c.program(pgmASTESequence)
		}
		viaALE = true
		if dasteo == basteo {
			base = true
		} else if c.readRealWord(dasteo+8)&0x200 == 0 || c.readRealWord(dasteo)&1 != 0 {
			c.program(pgmSpecialOperation) // not a subspace of this group
		}
	}
	std := c.readRealWord(dasteo + 8)
	if base {
		c.CR[1] = std
	} else {
		c.CR[1] = c.CR[1]&0x80000080 | std&^0x80000080
	}
	target := c.GR[r2]
	if r1 != 0 {
		if c.PSW.Amode31 {
			c.GR[r1] = 0x80000000 | c.next&0x7fffffff
		} else {
			c.GR[r1] = c.next & 0x00ffffff
		}
	}
	c.CR[7] = c.CR[1]
	c.CR[3] = c.CR[3]&0xffff0000 | c.CR[4]&0xffff
	w1a := c.realAbs(duct+4, accStore)
	w1 := be.Uint32(c.S.Mem[w1a:])
	switch {
	case base:
		w1 &^= 0x80000000
	case viaALE:
		w1 = 0x80000000 | dasteo
		w3a := c.realAbs(duct+12, accStore)
		be.PutUint32(c.S.Mem[w3a:], c.readRealWord(dasteo+20))
	default:
		w1 |= 0x80000000
	}
	be.PutUint32(c.S.Mem[w1a:], w1)
	*c.S.key(w1a) |= keyRef | keyChg
	c.PSW.Amode31 = target&0x80000000 != 0
	c.setAmode()
	c.next = target & c.amask
	c.pswChanged = true
	c.ipageValid = false
}

// stsi is STORE SYSTEM INFORMATION for a basic machine (configuration
// level 1): SYSIB 1.1.1 (configuration), 1.2.1 (this CPU) and 1.2.2 (CPUs).
func (c *CPU) stsi(a uint32, b int) {
	fc := c.GR[0] >> 28
	if fc == 0 {
		c.GR[0] = c.GR[0]&0x0fffffff | 1<<28
		c.PSW.CC = 0
		return
	}
	if fc > 1 {
		c.PSW.CC = 3
		return
	}
	if c.GR[0]&0x0fffff00 != 0 || c.GR[1]&0xffff0000 != 0 {
		c.program(pgmSpecification)
	}
	s1, s2 := c.GR[0]&0xff, c.GR[1]&0xffff
	if !(s1 == 1 && s2 == 1 || s1 == 2 && (s2 == 1 || s2 == 2)) {
		c.PSW.CC = 3
		return
	}
	if a&0xfff != 0 {
		c.program(pgmSpecification)
	}
	b4 := make([]byte, 256)
	seq := fmt.Sprintf("%016X", c.M.cfg.CPUSerial)
	put := func(off int, text string, n int) { copy(b4[off:], ebcdicPad(text, n)) }
	switch {
	case s1 == 1:
		put(32, "IBM", 16)
		put(48, fmt.Sprintf("%04X", c.M.cfg.CPUModel), 4)
		put(64, "R16", 16)
		put(80, seq, 16)
		put(96, "02", 4)
	case s2 == 1:
		put(80, seq, 16)
		put(96, "02", 4)
		be.PutUint16(b4[102:], c.Addr)
	default:
		be.PutUint32(b4[32:], 1000) // CPU capability
		n := uint16(len(c.M.CPUs))
		be.PutUint16(b4[36:], n)
		be.PutUint16(b4[38:], n)
		for i := 1; i < int(n); i++ {
			be.PutUint16(b4[44+2*(i-1):], 100) // adjustment factors
		}
	}
	c.checkStore(a, 4096, b)
	for i, x := range b4 {
		c.storeByte(a+uint32(i), b, x)
	}
	c.PSW.CC = 0
}

// cuutf is CONVERT UNICODE TO UTF-8 (R1 target, R2 source; address in
// the even register, length in the odd). Surrogate pairs become 4-byte
// sequences. CC 0: source exhausted, 1: target full.
func (c *CPU) cuutf(r1, r2 int) {
	c.even(r1)
	c.even(r2)
	d, dl := c.GR[r1]&c.amask, c.GR[r1+1]
	s, sl := c.GR[r2]&c.amask, c.GR[r2+1]
	defer func() {
		c.GR[r1], c.GR[r1+1] = c.GR[r1]&^c.amask|d&c.amask, dl
		c.GR[r2], c.GR[r2+1] = c.GR[r2]&^c.amask|s&c.amask, sl
	}()
	for {
		if sl < 2 {
			c.PSW.CC = 0
			return
		}
		u := uint32(c.fetchHalf(s, r2))
		used := uint32(2)
		var out []byte
		switch {
		case u < 0x80:
			out = []byte{byte(u)}
		case u < 0x800:
			out = []byte{0xc0 | byte(u>>6), 0x80 | byte(u&0x3f)}
		case u >= 0xd800 && u <= 0xdbff:
			if sl < 4 {
				c.PSW.CC = 0
				return
			}
			lo := uint32(c.fetchHalf(s+2, r2))
			cp := 0x10000 + (u-0xd800)<<10 + (lo & 0x3ff)
			out = []byte{0xf0 | byte(cp>>18), 0x80 | byte(cp>>12&0x3f), 0x80 | byte(cp>>6&0x3f), 0x80 | byte(cp&0x3f)}
			used = 4
		default:
			out = []byte{0xe0 | byte(u>>12), 0x80 | byte(u>>6&0x3f), 0x80 | byte(u&0x3f)}
		}
		if dl < uint32(len(out)) {
			c.PSW.CC = 1
			return
		}
		for i, x := range out {
			c.storeByte(d+uint32(i), r1, x)
		}
		d, dl = d+uint32(len(out)), dl-uint32(len(out))
		s, sl = s+used, sl-used
	}
}

// cutfu is CONVERT UTF-8 TO UNICODE. CC 0: source exhausted (an
// incomplete final character is left unprocessed), 1: target full,
// 2: invalid UTF-8 first byte.
func (c *CPU) cutfu(r1, r2 int) {
	c.even(r1)
	c.even(r2)
	d, dl := c.GR[r1]&c.amask, c.GR[r1+1]
	s, sl := c.GR[r2]&c.amask, c.GR[r2+1]
	defer func() {
		c.GR[r1], c.GR[r1+1] = c.GR[r1]&^c.amask|d&c.amask, dl
		c.GR[r2], c.GR[r2+1] = c.GR[r2]&^c.amask|s&c.amask, sl
	}()
	for {
		if sl == 0 {
			c.PSW.CC = 0
			return
		}
		b0 := uint32(c.fetchByte(s, r2))
		var n uint32
		switch {
		case b0 < 0x80:
			n = 1
		case b0 >= 0xc0 && b0 < 0xe0:
			n = 2
		case b0 >= 0xe0 && b0 < 0xf0:
			n = 3
		case b0 >= 0xf0 && b0 < 0xf8:
			n = 4
		default:
			c.PSW.CC = 2
			return
		}
		if sl < n {
			c.PSW.CC = 0
			return
		}
		cp := b0
		switch n {
		case 2:
			cp = b0 & 0x1f
		case 3:
			cp = b0 & 0x0f
		case 4:
			cp = b0 & 0x07
		}
		for i := uint32(1); i < n; i++ {
			cp = cp<<6 | uint32(c.fetchByte(s+i, r2))&0x3f
		}
		var units []uint16
		if n == 4 {
			cp -= 0x10000
			units = []uint16{uint16(0xd800 + cp>>10), uint16(0xdc00 + cp&0x3ff)}
		} else {
			units = []uint16{uint16(cp)}
		}
		if dl < uint32(2*len(units)) {
			c.PSW.CC = 1
			return
		}
		for i, u := range units {
			c.storeHalf(d+uint32(2*i), r1, u)
		}
		d, dl = d+uint32(2*len(units)), dl-uint32(2*len(units))
		s, sl = s+n, sl-n
	}
}
