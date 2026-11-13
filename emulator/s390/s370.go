package s390

import "fmt"

// System/370 architecture mode: basic-control and extended-control PSWs,
// System/370 dynamic address translation with 2K or 4K pages and 64K or 1M
// segments, channel I/O through START I/O and the CSW, the interval timer,
// and storage keys per 2K block.

// encode370 returns the System/370 BC- or EC-mode PSW.
func (p PSW) encode370() uint64 {
	var b [8]byte
	ctl := p.Key<<4 | b2(p.MC)<<2 | b2(p.Wait)<<1 | b2(p.Problem)
	if p.BC {
		b[0] = p.SysMask
		b[1] = ctl
		b[2], b[3] = byte(p.IntCode>>8), byte(p.IntCode)
		b[4] = p.ILC<<6 | (p.CC&3)<<4 | p.ProgMask&0xf
	} else {
		b[0] = b2(p.PER)<<6 | b2(p.DAT)<<2 | b2(p.IO)<<1 | b2(p.Ext)
		b[1] = ctl | 0x08
		b[2] = (p.CC&3)<<4 | p.ProgMask&0xf
		if p.AS == 2 {
			b[2] |= 0x80 // secondary-space mode
		}
	}
	b[5], b[6], b[7] = byte(p.IA>>16), byte(p.IA>>8), byte(p.IA)
	return be.Uint64(b[:])
}

func b2(v bool) byte {
	if v {
		return 1
	}
	return 0
}

// decode370 decodes a System/370 PSW; ok is false for an EC-mode PSW with
// nonzero reserved bits.
func decode370(x uint64) (p PSW, ok bool) {
	var b [8]byte
	be.PutUint64(b[:], x)
	p.S370 = true
	p.Key = b[1] >> 4
	p.MC = b[1]&0x04 != 0
	p.Wait = b[1]&0x02 != 0
	p.Problem = b[1]&0x01 != 0
	p.IA = uint32(b[5])<<16 | uint32(b[6])<<8 | uint32(b[7])
	ok = true
	if b[1]&0x08 == 0 {
		p.BC = true
		p.SysMask = b[0]
		p.IO = b[0]&0xfe != 0
		p.Ext = b[0]&0x01 != 0
		p.IntCode = uint16(b[2])<<8 | uint16(b[3])
		p.ILC = b[4] >> 6
		p.CC = b[4] >> 4 & 3
		p.ProgMask = b[4] & 0xf
		return p, true
	}
	p.PER = b[0]&0x40 != 0
	p.DAT = b[0]&0x04 != 0
	p.IO = b[0]&0x02 != 0
	p.Ext = b[0]&0x01 != 0
	if b[2]&0x80 != 0 {
		p.AS = 2
	}
	p.CC = b[2] >> 4 & 3
	p.ProgMask = b[2] & 0xf
	if b[0]&0xb8 != 0 || b[2]&0x40 != 0 || b[3] != 0 || b[4] != 0 {
		ok = false
	}
	return p, ok
}

// decodePSW decodes a PSW in the machine's architecture.
func (c *CPU) decodePSW(x uint64) (PSW, bool) {
	if c.M.S370 {
		return decode370(x)
	}
	return DecodePSW(x)
}

// ---- Interval timer ----

// Interval-timer units (bit 31) per TOD unit: the timer's bit 23 counts
// 1/300 s, so bit 31 counts 1/76800 s; a TOD unit is 1/4096 microsecond.
const itNum, itDen = 3, 160000

// intervalTimer decrements the timer word at real location 80 for elapsed
// time and reports whether its interruption is pending.
func (c *CPU) intervalTimer() bool {
	units := (c.M.tod - c.itBase) * itNum / itDen
	if d := units - c.itDone; d > 0 {
		a := c.realToAbs(0x50)
		old := int64(int32(be.Uint32(c.S.Mem[a:])))
		v := old - int64(d)
		be.PutUint32(c.S.Mem[a:], uint32(v))
		if old >= 0 && v < 0 {
			c.itPending = true
		}
		c.itDone = units
	}
	return c.itPending
}

// intervalDeadline returns the TOD value at which the timer next goes from
// positive to negative.
func (c *CPU) intervalDeadline() (uint64, bool) {
	if c.intervalTimer() {
		return 0, false
	}
	v := int32(be.Uint32(c.S.Mem[c.realToAbs(0x50):]))
	if v < 0 {
		return 0, false
	}
	target := c.itDone + uint64(v) + 1
	return c.itBase + (target*itDen+itNum-1)/itNum, true
}

// ---- Dynamic address translation ----

// dat370 walks the System/370 translation tables. It returns the real
// address, or a nonzero exception code with the table-entry real address.
func (c *CPU) dat370(v uint32) (real uint32, segProt bool, code uint16, entry uint32, lengthViolation bool) {
	v &= 0x00ffffff
	cr0 := c.CR[0]
	var pshift, sshift uint
	switch cr0 >> 22 & 3 {
	case 1:
		pshift = 11
	case 2:
		pshift = 12
	default:
		return 0, false, pgmTranslationSpec, 0, false
	}
	switch cr0 >> 19 & 3 {
	case 0:
		sshift = 16
	case 2:
		sshift = 20
	default:
		return 0, false, pgmTranslationSpec, 0, false
	}
	if cr0&0x00200000 != 0 { // bit 10 must be zero
		return 0, false, pgmTranslationSpec, 0, false
	}
	std := c.CR[1]
	stl := std >> 24
	sto := std & 0x00ffffc0
	sx := v >> sshift
	steAddr := sto + sx*4
	if sx>>4 > stl {
		return 0, false, pgmSegment, steAddr, true
	}
	ste := c.readRealWord(steAddr)
	if ste&1 != 0 {
		return 0, false, pgmSegment, steAddr, false
	}
	ptl := ste >> 28
	pto := ste & 0x00fffff8
	width := sshift - pshift
	px := v >> pshift & (1<<width - 1)
	pteAddr := pto + px*2
	if px>>(width-4) > ptl {
		return 0, false, pgmPage, pteAddr, true
	}
	pte := uint32(be.Uint16(c.S.Mem[c.realAbs(pteAddr, accFetch):]))
	if pshift == 12 {
		if pte&0x0008 != 0 {
			return 0, false, pgmPage, pteAddr, false
		}
		// Bit 15 is not examined (MVS sets it).
		real = pte>>4<<12 | (pte>>1&3)<<24 | v&0xfff
	} else {
		if pte&0x0004 != 0 {
			return 0, false, pgmPage, pteAddr, false
		}
		real = pte>>3<<11 | v&0x7ff
	}
	return real, ste&0x4 != 0, 0, 0, false
}

// translate370 maps a virtual address through System/370 DAT with the TLB.
func (c *CPU) translate370(v uint32, acc access) (uint32, bool) {
	v &= 0x00ffffff
	std := c.CR[1]
	vpage := v >> 11
	i := (vpage ^ (std >> 11)) & (tlbSize - 1)
	e := &c.tlb[i]
	if e.valid && e.vpage == vpage && e.std == std {
		return e.real | v&0x7ff, e.prot
	}
	real, prot, code, _, _ := c.dat370(v)
	if code != 0 {
		c.excAddr = v
		c.program(code)
	}
	*e = tlbEntry{std: std, vpage: vpage, real: real &^ 0x7ff, prot: prot, valid: true}
	return real, prot
}

// lra370 is LOAD REAL ADDRESS in System/370 mode.
func (c *CPU) lra370(r1 int, a uint32) {
	real, _, code, entry, length := c.dat370(a)
	switch {
	case code == pgmTranslationSpec:
		c.program(code)
	case length:
		c.GR[r1] = entry
		c.PSW.CC = 3
	case code == pgmSegment:
		c.GR[r1] = entry
		c.PSW.CC = 1
	case code == pgmPage:
		c.GR[r1] = entry
		c.PSW.CC = 2
	default:
		c.GR[r1] = real
		c.PSW.CC = 0
	}
}

// ---- Storage keys (2K blocks) ----

// ssk370 is SET STORAGE KEY; isk370 is INSERT STORAGE KEY.
func (c *CPU) ssk370(r1, r2 int) {
	c.privileged()
	a := c.GR[r2] & 0x00fffff0
	if c.GR[r2]&0xf != 0 {
		c.program(pgmSpecification)
	}
	abs := c.realAbs(a, accFetch)
	*c.S.key(abs) = byte(c.GR[r1]) & 0xfe
}

func (c *CPU) isk370(r1, r2 int) {
	c.privileged()
	a := c.GR[r2] & 0x00fffff0
	if c.GR[r2]&0xf != 0 {
		c.program(pgmSpecification)
	}
	k := *c.S.key(c.realAbs(a, accFetch))
	mask := byte(0xfe)
	if c.PSW.BC {
		mask = 0xf8
	}
	c.GR[r1] = c.GR[r1]&^0xff | uint32(k&mask)
}

// rrb370 is RESET REFERENCE BIT.
func (c *CPU) rrb370(a uint32) {
	c.privileged()
	k := c.S.key(c.realAbs(a&0x00ffffff, accFetch))
	c.PSW.CC = 0
	if *k&keyRef != 0 {
		c.PSW.CC |= 2
	}
	if *k&keyChg != 0 {
		c.PSW.CC |= 1
	}
	*k &^= keyRef
}

// ---- Channel I/O ----

// csw returns the channel-status word for a subchannel's status.
func (x *Subchannel) csw() uint64 {
	return uint64(x.key&0xf)<<60 | uint64(x.ccwaddr&0x00ffffff)<<32 |
		uint64(x.devStatus)<<24 | uint64(x.schStatus)<<16 | uint64(x.residual)
}

func (c *CPU) storeCSW(x *Subchannel) {
	c.setLowDouble(0x40, x.csw())
}

// accept370 clears status the program has received and presents an
// attention held while it was pending.
func (s *ChannelSubsystem) accept370(x *Subchannel) {
	x.pending, x.irq = false, false
	if x.attnHold {
		x.attnHold = false
		s.Unsolicited(x.devno, usAttention)
	}
}

// channelEnabled reports whether I/O interruptions from a channel are
// enabled by the PSW and, in EC mode, control register 2.
func (c *CPU) channelEnabled(ch uint16) bool {
	if c.PSW.BC {
		if ch < 6 {
			return c.PSW.SysMask&(0x80>>ch) != 0
		}
		return c.PSW.SysMask&0x02 != 0
	}
	return c.PSW.IO && ch < 32 && c.CR[2]&(0x80000000>>ch) != 0
}

// takeIO370 takes a pending I/O interruption: the CSW is stored and the
// device address identifies the source.
func (c *CPU) takeIO370() bool {
	for _, x := range c.M.CSS.subs {
		if x.pciIRQ && c.channelEnabled(x.devno>>8) {
			// Program-controlled interruption: the channel program is
			// still working; the CSW identifies the next CCW.
			c.PSW.Wait = false
			x.pciIRQ = false
			x.pciAt = c.Instructions
			c.setLowDouble(0x40, uint64(x.key&0xf)<<60|uint64(x.blockAddr&0x00ffffff)<<32|uint64(scsPCI)<<16)
			if c.PSW.BC {
				c.PSW.IntCode = x.devno
			} else {
				c.setLowHalf(0xba, x.devno)
			}
			c.M.Interrupts["io-pci"]++
			c.swap(pswIOOld, pswIONew)
			return true
		}
		if !x.pending || !x.irq || !c.channelEnabled(x.devno>>8) {
			continue
		}
		c.PSW.Wait = false
		c.storeCSW(x)
		c.M.CSS.accept370(x)
		if c.PSW.BC {
			c.PSW.IntCode = x.devno
		} else {
			c.setLowHalf(0xba, x.devno)
		}
		c.M.Interrupts["io"]++
		c.swap(pswIOOld, pswIONew)
		return true
	}
	return false
}

// io370 executes START I/O, TEST I/O, HALT I/O and TEST CHANNEL.
func (c *CPU) io370(op []byte, a uint32) {
	c.privileged()
	devno := uint16(a)
	css := c.M.CSS
	if op[0] == 0x9f { // TCH
		ch := devno >> 8
		c.PSW.CC = 3
		for _, x := range css.subs {
			if x.devno>>8 == ch {
				if c.PSW.CC == 3 {
					c.PSW.CC = 0
				}
				if x.pending {
					c.PSW.CC = 1
				}
			}
		}
		return
	}
	x := css.bydev[devno]
	if x == nil {
		c.PSW.CC = 3
		return
	}
	if x.blocked {
		switch op[0] {
		case 0x9e: // HIO: terminate the waiting operation
			x.blocked = false
			x.devStatus, x.schStatus = usCE|usDE, 0
			x.ccwaddr = x.blockAddr + 8
			c.storeCSW(x)
			c.PSW.CC = 1
		default:
			c.PSW.CC = 2 // busy
		}
		return
	}
	switch op[0] {
	case 0x9c: // SIO, SIOF
		if x.pending {
			c.storeCSW(x)
			c.setLowByte(0x44, x.devStatus|usBusy)
			css.accept370(x)
			c.PSW.CC = 1
			return
		}
		caw := c.lowWord(0x48)
		x.key = byte(caw >> 28)
		x.ccwaddr, x.devStatus, x.schStatus, x.residual = 0, 0, 0, 0
		if caw&0x0f000007 != 0 {
			x.schStatus = scsProgramCheck
			c.storeCSW(x)
			c.PSW.CC = 1
			return
		}
		if ce, ok := x.dev.(ChainEnd); ok {
			ce.StartChain()
		}
		css.trace = css.trace[:0]
		css.run(x, caw&0x00fffff8, false, 0, x.key)
		c.PSW.CC = 0
		if x.blocked {
			return // continues when the device or program is ready
		}
		if ce, ok := x.dev.(ChainEnd); ok {
			ce.EndChain()
		}
		if c.M.TraceIO {
			c.M.event("io", c, fmt.Sprintf("SIO %04X caw %08X cmds %s -> dev %02X ch %02X ccw %06X resid %d", devno, caw, css.traceString(), x.devStatus, x.schStatus, x.ccwaddr, x.residual))
		}
		x.pending, x.irq = true, true
		c.PSW.CC = 0
	case 0x9d: // TIO, CLRIO
		if x.pending {
			c.storeCSW(x)
			css.accept370(x)
			c.PSW.CC = 1
			return
		}
		c.PSW.CC = 0
	case 0x9e: // HIO, HDV
		c.PSW.CC = 0
	}
}

// stidc is STORE CHANNEL ID: channel 0 is a byte multiplexer, others are
// block multiplexers.
func (c *CPU) stidc(a uint32) {
	c.privileged()
	ch := uint16(a) >> 8
	for _, x := range c.M.CSS.subs {
		if x.devno>>8 == ch {
			id := uint32(0x20000000)
			if ch == 0 {
				id = 0x10000000
			}
			c.setLowWord(0xa8, id)
			c.PSW.CC = 0
			return
		}
	}
	c.PSW.CC = 3
}
