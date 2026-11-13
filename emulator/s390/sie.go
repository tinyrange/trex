package s390

import "fmt"

// START INTERPRETIVE EXECUTION for ESA/390 (XA-mode) guests.
//
// State-description layout (offsets):
//
//	00 intervention requests  01 state controls  02 machine mode  03 mode
//	04 guest prefix           08 main-storage origin  0A extent (64K units)
//	10 guest GR14  14 guest GR15  18 guest PSW  28 CPU timer  30 clock comparator
//	38 epoch       40 SVC interception controls  44 LCTL controls  46 CPU address
//	48 interception controls  4C execution controls
//	50 interception code  51 interception status  52 last host CPU
//	56 IPA  58 IPB  5C IPC  80 guest CR0-CR15  C0 interruption parameters
//	(an image of PSA locations 80-B3)
//
// Guest general registers 0-13, access and floating-point registers are the
// host's registers. Guest storage is a host address space: guest absolute
// address g is host virtual address g+origin, translated with the host's
// primary segment-table designation at entry (or used as host real for V=R).

const (
	sieCodeNone      = 0
	sieCodeInst      = 4
	sieCodePgm       = 8
	sieCodePgmInst   = 12
	sieCodeExtReq    = 16
	sieCodeExtInt    = 20
	sieCodeIOReq     = 24
	sieCodeWait      = 28
	sieCodeValidity  = 32
	sieCodeStopReq   = 40
	sieCodeOperation = 44
)

type gmapEntry struct {
	vpage uint32
	abs   uint32
	prot  bool
	valid bool
}

type sieState struct {
	sd    uint32 // absolute address of the state description
	sieIA uint32 // address of the SIE instruction

	host           PSW
	hostCR         [16]uint32
	hostPrefix     uint32
	hostGR14       uint32
	hostGR15       uint32
	hostTimerValue int64
	hostTimerRef   uint64
	hostCKC        uint64

	hostSTD uint32
	hostCR0 uint32
	mso     uint32
	mse     uint32 // first guest absolute address beyond the extent
	vr      bool
	m, mx   byte
	ic      [4]byte
	ec      [4]byte
	lctl    uint16
	svc     [4]byte
	cpuad   uint16
	epoch   uint64

	gmap [512]gmapEntry
}

// sieExitRequest unwinds instruction execution to leave interpretive
// execution with an interception code.
type sieExitRequest struct {
	code byte
}

// hostCheck is a host program exception raised while running a guest.
type hostCheck struct {
	code uint16
	addr uint32
}

func (c *CPU) sdByte(off uint32) byte   { return c.S.Mem[c.sie.sd+off] }
func (c *CPU) sdHalf(off uint32) uint16 { return be.Uint16(c.S.Mem[c.sie.sd+off:]) }
func (c *CPU) sdWord(off uint32) uint32 { return be.Uint32(c.S.Mem[c.sie.sd+off:]) }
func (c *CPU) sdDouble(off uint32) uint64 {
	return be.Uint64(c.S.Mem[c.sie.sd+off:])
}

// tod returns the TOD clock as seen by the current (host or guest) program.
func (c *CPU) tod() uint64 {
	if c.sie != nil {
		return c.M.tod + c.sie.epoch
	}
	return c.M.tod
}

// sieEnter is START INTERPRETIVE EXECUTION.
func (c *CPU) sieEnter(a uint32, b int) {
	if c.sie != nil {
		c.program(pgmOperation)
	}
	if a&7 != 0 {
		c.program(pgmSpecification)
	}
	sd := c.realToAbs(a & 0x7ffffff8)
	if !c.S.valid(sd, 256) {
		c.program(pgmAddressing)
	}
	m := c.S.Mem[sd:]
	st := &sieState{sd: sd, sieIA: c.ia}
	st.m = m[3]
	st.mx = m[2]
	if st.m&0x20 == 0 || st.mx&0x08 != 0 {
		// Only ESA/390 (XA-mode) guests are supported: validity intercept.
		m[0x50] = sieCodeValidity
		be.PutUint16(m[0x56:], 0x0001)
		c.M.event("sie", c, fmt.Sprintf("validity: mode %02X mx %02X", st.m, st.mx))
		return
	}
	st.host = c.PSW
	st.host.IA = c.next
	st.hostCR = c.CR
	st.hostPrefix = c.Prefix
	st.hostGR14, st.hostGR15 = c.GR[14], c.GR[15]
	st.hostTimerValue, st.hostTimerRef = c.timerValue, c.timerRef
	st.hostCKC = c.ClockComparator
	st.hostSTD = c.CR[1]
	st.hostCR0 = c.CR[0]
	st.vr = st.m&0x08 != 0
	st.mso = uint32(be.Uint16(m[8:])) << 16
	st.mse = (uint32(be.Uint16(m[10:])) + 1) << 16
	copy(st.ic[:], m[0x48:0x4c])
	copy(st.ec[:], m[0x4c:0x50])
	copy(st.svc[:], m[0x40:0x44])
	st.lctl = be.Uint16(m[0x44:])
	st.cpuad = be.Uint16(m[0x46:])
	st.epoch = be.Uint64(m[0x38:])

	c.sie = st
	c.SIEEntries++
	gpsw := be.Uint64(m[0x18:])
	c.GR[14] = be.Uint32(m[0x10:])
	c.GR[15] = be.Uint32(m[0x14:])
	for i := 0; i < 16; i++ {
		c.CR[i] = be.Uint32(m[0x80+4*i:])
	}
	c.Prefix = be.Uint32(m[4:]) & 0x7ffff000
	c.setCPUTimer(int64(be.Uint64(m[0x28:])))
	c.ClockComparator = be.Uint64(m[0x30:])
	m[0x50] = 0
	m[0x51] = 0
	if !c.loadPSW(gpsw) {
		c.earlySpec = true
	}
	c.next = c.PSW.IA
	c.purgeTLB()
	c.ipageValid = false
	c.pswChanged = true
}

// sieExit leaves interpretive execution. The guest PSW is stored as it
// stands; hostIA is the host instruction address to resume at.
func (c *CPU) sieExit(code byte, hostIA uint32) {
	st := c.sie
	m := c.S.Mem[st.sd:]
	be.PutUint64(m[0x18:], c.PSW.Encode())
	be.PutUint32(m[0x10:], c.GR[14])
	be.PutUint32(m[0x14:], c.GR[15])
	for i := 0; i < 16; i++ {
		be.PutUint32(m[0x80+4*i:], c.CR[i])
	}
	be.PutUint32(m[4:], c.Prefix)
	be.PutUint64(m[0x28:], uint64(c.cpuTimer()))
	be.PutUint64(m[0x30:], c.ClockComparator)
	if code != sieCodeNone {
		m[0x50] = code
	}
	be.PutUint16(m[0x52:], c.Addr)
	*c.S.key(st.sd) |= keyRef | keyChg

	c.sie = nil
	c.PSW = st.host
	c.PSW.IA = hostIA
	c.setAmode()
	c.CR = st.hostCR
	c.Prefix = st.hostPrefix
	c.GR[14], c.GR[15] = st.hostGR14, st.hostGR15
	c.timerValue, c.timerRef = st.hostTimerValue, st.hostTimerRef
	c.ClockComparator = st.hostCKC
	c.next = hostIA
	c.purgeTLB()
	c.ipageValid = false
	c.pswChanged = true
	c.exAddr = false
	c.SIEExits[code]++
	if c.SIEExits[code] <= 8 {
		c.M.event("sie-exit", c, fmt.Sprintf("code %d guest %016X ipa %04X ipb %08X", code, be.Uint64(m[0x18:]), be.Uint16(m[0x56:]), be.Uint32(m[0x58:])))
	}
}

// sieInstructionExit leaves for an instruction interception of the current
// instruction. The guest PSW designates the next sequential instruction;
// IPA/IPB hold the intercepted instruction (the EX target, as modified, when
// the interception status EX bit is set).
func (c *CPU) sieInstructionExit(code byte) {
	ia := c.next
	if c.exAddr {
		ia = c.exIA + 4
		c.S.Mem[c.sie.sd+0x51] |= 0x01
	}
	op := c.op
	c.PSW.IA = ia & c.amask
	m := c.S.Mem[c.sie.sd:]
	be.PutUint16(m[0x56:], uint16(op[0])<<8|uint16(op[1]))
	be.PutUint32(m[0x58:], uint32(op[2])<<24|uint32(op[3])<<16|uint32(op[4])<<8|uint32(op[5]))
	c.sieExit(code, c.sie.sieIA+4)
}

// sieInterceptCheck is called by privileged instructions in guest
// supervisor state; it leaves interpretive execution for instructions the
// host simulates.
func (c *CPU) sieInterceptCheck() {
	st := c.sie
	op := c.op
	intercept := false
	switch op[0] {
	case 0x83, 0xae, 0x99: // DIAGNOSE, SIGP, TRACE (explicit tracing is host-managed)
		intercept = op[0] != 0x99
	case 0x82: // LPSW
		intercept = st.ic[1]&0x40 != 0
	case 0x80: // SSM
		intercept = st.ic[1]&0x10 != 0
	case 0xac:
		intercept = st.ic[1]&0x02 != 0
	case 0xad:
		intercept = st.ic[1]&0x01 != 0
	case 0xb6:
		intercept = st.ic[1]&0x04 != 0
	case 0xb7: // LCTL
		r1, r3 := int(op[1]>>4), int(op[1]&0xf)
		for r := r1; ; r = (r + 1) & 15 {
			if st.lctl&(0x8000>>r) != 0 {
				intercept = true
			}
			if r == r3 {
				break
			}
		}
	case 0xb1: // LRA
	case 0xe5: // TPROT, MVCSK, MVCDK
		if op[1] == 0x01 {
			intercept = st.ic[2]&0x02 != 0
		}
	case 0xb2:
		switch op[1] {
		case 0x0a, 0x0b, 0x10, 0x11, 0x12, 0x19, 0x24, 0x25, 0x26, 0x27, 0x46, 0x4b, 0x79, 0x0d:
			// SPKA IPK SPX STPX STAP SAC IAC SSAR EPAR ESAR STURA LURA SACF PTLB
			if op[1] == 0x0d {
				intercept = st.ic[1]&0x20 != 0
			}
		case 0x06, 0x07:
			intercept = st.ic[3]&0x20 != 0
		case 0x08, 0x09:
			intercept = st.ic[3]&0x40 != 0
		case 0x21, 0x50: // IPTE, CSP
			intercept = st.ic[0]&0x01 != 0 || st.ec[0]&0x01 == 0 && op[1] == 0x21
		case 0x54: // MVPG
			intercept = st.ec[0]&0x01 == 0
		default:
			// STIDP, SCK, SIE, SERVC, I/O instructions, keys, TB, PGIN/PGOUT
			// and everything else privileged are simulated by the host.
			intercept = true
		}
	default:
		intercept = true
	}
	if intercept {
		panic(sieExitRequest{code: sieCodeInst})
	}
}

// sieRealAbs converts a guest absolute address to a host absolute address.
func (c *CPU) sieHost(gabs uint32, acc access) uint32 {
	st := c.sie
	if gabs >= st.mse {
		c.program(pgmAddressing)
	}
	hv := gabs + st.mso
	page := hv >> 12
	e := &st.gmap[page&511]
	if e.valid && e.vpage == page {
		if acc == accStore && e.prot {
			panic(hostCheck{code: pgmProtection, addr: hv})
		}
		return e.abs | hv&0xfff
	}
	var real uint32
	prot := false
	if st.vr {
		real = hv
	} else {
		real, prot = c.hostTranslate(hv)
		real |= hv & 0xfff
	}
	abs := real
	if real < 0x1000 {
		abs = real + st.hostPrefix
	} else if real&^0xfff == st.hostPrefix {
		abs = real - st.hostPrefix
	}
	if !c.S.valid(abs, 1) {
		panic(hostCheck{code: pgmAddressing, addr: hv})
	}
	*e = gmapEntry{vpage: page, abs: abs &^ 0xfff, prot: prot, valid: true}
	if acc == accStore && prot {
		panic(hostCheck{code: pgmProtection, addr: hv})
	}
	return abs
}

func (c *CPU) hostReal(r uint32) uint32 {
	st := c.sie
	if r < 0x1000 {
		r += st.hostPrefix
	} else if r&^0xfff == st.hostPrefix {
		r -= st.hostPrefix
	}
	if !c.S.valid(r, 4) {
		panic(hostCheck{code: pgmAddressing, addr: r})
	}
	return r
}

// hostTranslate translates a host virtual address through the host's
// primary space as it was at SIE entry.
func (c *CPU) hostTranslate(v uint32) (uint32, bool) {
	st := c.sie
	std := st.hostSTD
	sto := std & 0x7ffff000
	stl := std & 0x7f
	sx := v >> 20 & 0x7ff
	if sx>>4 > stl {
		panic(hostCheck{code: pgmSegment, addr: v})
	}
	ste := be.Uint32(c.S.Mem[c.hostReal((sto+sx*4)&0x7fffffff):])
	if ste&0x20 != 0 {
		panic(hostCheck{code: pgmSegment, addr: v})
	}
	pto := ste & 0x7fffffc0
	ptl := ste & 0xf
	px := v >> 12 & 0xff
	if px>>4 > ptl {
		panic(hostCheck{code: pgmPage, addr: v})
	}
	pte := be.Uint32(c.S.Mem[c.hostReal((pto+px*4)&0x7fffffff):])
	if pte&0x400 != 0 {
		panic(hostCheck{code: pgmPage, addr: v})
	}
	return pte & 0x7ffff000, pte&0x200 != 0
}

// sieHostInterrupt reports whether a host interruption is pending and
// enabled while a guest runs.
func (c *CPU) sieHostInterrupt() bool {
	st := c.sie
	h := st.host
	if h.Ext {
		now := c.M.tod
		cr0 := st.hostCR[0]
		if cr0&(1<<11) != 0 && now > st.hostCKC {
			return true
		}
		if cr0&(1<<10) != 0 && st.hostTimerValue-int64(now-st.hostTimerRef) < 0 {
			return true
		}
		if cr0&(1<<9) != 0 && c.M.serviceSignal && c.Addr == 0 {
			return true
		}
		p := c.extPending
		if p&extEmergency != 0 && cr0&(1<<14) != 0 || p&extExternalCall != 0 && cr0&(1<<13) != 0 ||
			p&extMalfunction != 0 && cr0&(1<<15) != 0 || p&extInterruptKey != 0 && cr0&(1<<6) != 0 {
			return true
		}
	}
	if h.IO && c.M.CSS.pendingInterrupt(st.hostCR[6]) != nil {
		return true
	}
	return false
}

// sieInterrupts handles interruption conditions while a guest runs. It
// reports whether execution state changed.
func (c *CPU) sieInterrupts() bool {
	if c.sieHostInterrupt() {
		c.sieExit(sieCodeNone, c.sie.sieIA)
		return true
	}
	v := c.sdByte(0)
	if v&0x04 != 0 { // stop request
		c.sieExit(sieCodeStopReq, c.sie.sieIA+4)
		return true
	}
	if v&0x02 != 0 && c.PSW.IO {
		c.sieExit(sieCodeIOReq, c.sie.sieIA+4)
		return true
	}
	if v&0x01 != 0 && c.PSW.Ext {
		c.sieExit(sieCodeExtReq, c.sie.sieIA+4)
		return true
	}
	if c.PSW.Ext {
		if bit := c.pendingExternal(); bit != 0 {
			c.PSW.Wait = false
			c.deliverGuest(func() { c.takeExternal(bit) })
			return true
		}
	}
	if c.PSW.Wait {
		c.sieExit(sieCodeWait, c.sie.sieIA+4)
		return true
	}
	return false
}

// deliverGuest runs a guest interruption, converting a host exception on
// the guest's PSA into a host program interruption.
func (c *CPU) deliverGuest(f func()) {
	defer func() {
		if r := recover(); r != nil {
			c.handleCheck(r)
		}
	}()
	f()
}

// guestProgram presents a program interruption raised by a guest
// instruction: to the host by interception or to the guest.
func (c *CPU) guestProgram(code uint16, nullify bool) {
	st := c.sie
	if code == pgmOperation && st.ic[0]&0x80 != 0 {
		c.sieInstructionExit(sieCodeOperation)
		return
	}
	if st.ic[0]&0x20 != 0 {
		// Program interruption interception: the guest PSW is the old PSW
		// and the interruption parameters go to the state description.
		ia := c.next
		ilc := c.ilc
		if nullify {
			ia = c.ia
		}
		if c.exAddr {
			ia, ilc = c.exIA+4, 4
			if nullify {
				ia = c.exIA
			}
			c.exAddr = false
		}
		c.PSW.IA = ia & c.amask
		m := c.S.Mem[st.sd:]
		m[0xc0+0x0d] = byte(ilc)
		be.PutUint16(m[0xc0+0x0e:], code)
		be.PutUint32(m[0xc0+0x10:], c.excAddr&0x7ffff000)
		c.sieExit(sieCodePgm, st.sieIA+4)
		return
	}
	c.deliverGuest(func() { c.takeProgramDirect(code, nullify) })
}

// handleCheck dispatches a recovered panic from instruction execution.
func (c *CPU) handleCheck(r any) {
	switch x := r.(type) {
	case programCheck:
		if c.sie != nil {
			c.guestProgram(x.code, x.nullify)
			return
		}
		c.takeProgram(x.code, x.nullify)
	case sieExitRequest:
		c.sieInstructionExit(x.code)
	case hostCheck:
		// Leave the guest with its instruction nullified and present the
		// exception to the host at the SIE instruction.
		ia := c.ia
		if c.exAddr {
			ia = c.exIA
		}
		c.PSW.IA = ia & c.amask
		sieIA := c.sie.sieIA
		std := c.sie.hostSTD
		c.sieExit(sieCodeNone, sieIA)
		c.ia, c.ilc, c.next = sieIA, 4, sieIA+4
		c.excAddr, c.excSpace = x.addr, std
		c.excAR = 0
		c.takeProgram(x.code, true)
	default:
		panic(r)
	}
}

// sieSVCIntercepted reports whether the state description asks for the
// guest's SVC to be intercepted.
func (c *CPU) sieSVCIntercepted(code byte) bool {
	s := c.sie.svc
	return s[0]&0x80 != 0 || s[0]&0x40 != 0 && s[1] == code || s[0]&0x20 != 0 && s[2] == code || s[0]&0x10 != 0 && s[3] == code
}
