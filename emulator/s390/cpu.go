package s390

import "fmt"

// PSW is the ESA/390 program-status word in decoded form.
type PSW struct {
	PER, DAT, IO, Ext bool
	Key               byte
	MC, Wait, Problem bool
	AS                byte // address-space control: 0 primary, 1 AR, 2 secondary, 3 home
	CC                byte
	ProgMask          byte
	Amode31           bool
	IA                uint32

	// System/370 forms. S370 selects the System/370 encoding; BC selects
	// basic-control mode, where SysMask holds the channel masks (bits 0-5),
	// the I/O mask for channels 6 and up (bit 6) and the external mask, and
	// the interruption code and ILC are part of the PSW.
	S370, BC bool
	SysMask  byte
	IntCode  uint16
	ILC      byte
}

// Encode returns the 8-byte form of the PSW.
func (p PSW) Encode() uint64 {
	if p.S370 {
		return p.encode370()
	}
	var w0 uint32 = 1 << 19
	if p.PER {
		w0 |= 1 << 30
	}
	if p.DAT {
		w0 |= 1 << 26
	}
	if p.IO {
		w0 |= 1 << 25
	}
	if p.Ext {
		w0 |= 1 << 24
	}
	w0 |= uint32(p.Key&0xf) << 20
	if p.MC {
		w0 |= 1 << 18
	}
	if p.Wait {
		w0 |= 1 << 17
	}
	if p.Problem {
		w0 |= 1 << 16
	}
	w0 |= uint32(p.AS&3) << 14
	w0 |= uint32(p.CC&3) << 12
	w0 |= uint32(p.ProgMask&0xf) << 8
	w1 := p.IA
	if p.Amode31 {
		w1 = 1<<31 | p.IA&0x7fffffff
	} else {
		w1 = p.IA & 0x00ffffff
	}
	return uint64(w0)<<32 | uint64(w1)
}

// DecodePSW decodes an ESA/390 PSW. ok is false when the PSW has bits that
// cause an early specification exception.
func DecodePSW(x uint64) (p PSW, ok bool) {
	w0, w1 := uint32(x>>32), uint32(x)
	p.PER = w0&(1<<30) != 0
	p.DAT = w0&(1<<26) != 0
	p.IO = w0&(1<<25) != 0
	p.Ext = w0&(1<<24) != 0
	p.Key = byte(w0>>20) & 0xf
	p.MC = w0&(1<<18) != 0
	p.Wait = w0&(1<<17) != 0
	p.Problem = w0&(1<<16) != 0
	p.AS = byte(w0>>14) & 3
	p.CC = byte(w0>>12) & 3
	p.ProgMask = byte(w0>>8) & 0xf
	p.Amode31 = w1&0x80000000 != 0
	p.IA = w1 & 0x7fffffff
	ok = w0&0xb80800ff == 0x00080000
	if !p.Amode31 && p.IA&0x7f000000 != 0 {
		ok = false
	}
	return p, ok
}

func (p PSW) String() string {
	x := p.Encode()
	return fmt.Sprintf("%08X %08X", uint32(x>>32), uint32(x))
}

// CPU is one ESA/390 processor.
type CPU struct {
	M      *Machine
	S      *Storage
	Addr   uint16 // CPU address
	GR     [16]uint32
	AR     [16]uint32
	CR     [16]uint32
	FPR    [16]uint64
	FPC    uint32
	PSW    PSW
	Prefix uint32

	ClockComparator uint64

	amask  uint32
	pgMask uint32 // page-crossing granularity: 4K, or 2K for System/370
	ia     uint32 // address of the current instruction
	ilc    uint32 // length of the current instruction
	next   uint32 // address of the next sequential instruction
	exAddr bool   // executing the target of EXECUTE
	exIA   uint32

	excAddr    uint32
	excSpace   uint32
	excDATProt bool
	// excMode is the address-space mode of the last operand translation
	// (TEID bits 30-31); spaceOverride, when nonzero, is 4|mode for operand
	// accesses of MVCP and MVCS without changing the PSW.
	excMode       byte
	spaceOverride byte
	// System/370 interval timer: units already decremented since itBase.
	itBase, itDone uint64
	itPending      bool
	excAR          byte
	dxc            byte // data-exception code for the next data exception

	tlb    [tlbSize]tlbEntry
	icache icache
	// dtlb caches operand translations that passed every check, tagged
	// by page, STD, PSW key and access; dtlbGen and Machine.keyGen
	// invalidate it.
	dtlb    [dtlbSize]dtlbEntry
	dtlbGen uint64

	Stopped     bool
	Check       bool // check-stop
	checkReason string
	hitBreak    bool

	extPending  uint32 // pending external interruption conditions (extXxx bits)
	emergency   uint64 // CPU addresses that signalled emergency
	extCallFrom uint16

	op         [6]byte
	stores     uint64 // operand stores and clock reads, for spin detection
	quiet      int    // consecutive interruption checks without a store
	quietGR    [16]uint32
	pswChanged bool
	earlySpec  bool
	ipageValid bool
	ipageV     uint32
	ipageA     uint32
	timerValue int64  // CPU timer value at timerRef
	timerRef   uint64 // TOD value when timerValue was set

	SIEEntries uint64
	SIEExits   map[byte]uint64

	Instructions uint64
	Unknown      map[uint16]uint64
	sie          *sieState
}

func (c *CPU) setAmode() {
	if c.PSW.Amode31 {
		c.amask = 0x7fffffff
	} else {
		c.amask = 0x00ffffff
	}
}

// LoadPSW installs a new PSW. A PSW with invalid bits is installed and
// recognised as a specification exception before the next instruction.
func (c *CPU) loadPSW(x uint64) bool {
	p, ok := c.decodePSW(x)
	c.PSW = p
	c.setAmode()
	return ok
}

// Reset performs a CPU reset; clear additionally zeroes registers.
func (c *CPU) Reset(clear bool) {
	c.PSW = PSW{}
	c.setAmode()
	c.Stopped = true
	c.extPending = 0
	c.emergency = 0
	c.purgeTLB()
	if clear {
		c.GR = [16]uint32{}
		c.AR = [16]uint32{}
		c.FPR = [16]uint64{}
		c.FPC = 0
		c.Prefix = 0
		c.setCPUTimer(0)
		c.ClockComparator = 0
	}
	c.CR = [16]uint32{}
	c.CR[0] = 0x000000e0
	c.CR[2] = 0x00000000
	c.CR[14] = 0xc2000000
	if c.M.S370 {
		c.CR[2] = 0xffffffff // channel masks
		c.PSW.S370, c.PSW.BC = true, true
		c.itBase, c.itDone, c.itPending = c.M.tod, 0, false
	}
}

// Interruption classes in PSA offsets.
const (
	pswRestartNew = 0x00
	pswRestartOld = 0x08
	pswExtOld     = 0x18
	pswSVCOld     = 0x20
	pswPgmOld     = 0x28
	pswMCOld      = 0x30
	pswIOOld      = 0x38
	pswExtNew     = 0x58
	pswSVCNew     = 0x60
	pswPgmNew     = 0x68
	pswMCNew      = 0x70
	pswIONew      = 0x78
)

// swap stores the current PSW at old and loads new.
func (c *CPU) swap(old, new uint32) {
	c.setLowDouble(old, c.PSW.Encode())
	c.PSW.IntCode, c.PSW.ILC = 0, 0
	if !c.loadPSW(c.lowDouble(new)) {
		// Early specification exception on the new PSW: architecture
		// recognises it as a program interruption before execution.
		c.earlySpec = true
	}
	c.next = c.PSW.IA
	c.pswChanged = true
	c.ipageValid = false
}

// takeProgram performs a program interruption in the current state.
func (c *CPU) takeProgram(code uint16, nullify bool) { c.takeProgramDirect(code, nullify) }

// takeProgramDirect stores the interruption in the current PSA (the guest's
// while interpreting) and loads the program new PSW.
func (c *CPU) takeProgramDirect(code uint16, nullify bool) {
	ia := c.next
	ilc := c.ilc
	if nullify {
		ia = c.ia
	}
	if c.exAddr {
		ia = c.exIA + 4
		if nullify {
			ia = c.exIA
		}
		ilc = 4
	}
	c.exAddr = false
	c.PSW.IA = ia & c.amask
	switch code &^ pgmPER {
	case pgmSegment, pgmPage:
		if c.M.S370 {
			c.setLowWord(0x90, c.excAddr&0x00ffffff)
			break
		}
		sp := c.excSpaceBits()
		c.setLowWord(0x90, c.excAddr&0x7ffff000|sp)
		if sp == 1 {
			c.setLowByte(0xa0, c.excAR)
		}
	case pgmProtection:
		if c.M.S370 {
			break
		}
		// Suppression on protection: DAT protection identifies the page
		// and address space (bit 29 set); other protection stores zero.
		teid := uint32(0)
		if c.excDATProt {
			sp := c.excSpaceBits()
			teid = c.excAddr&0x7ffff000 | 4 | sp
			if sp == 1 {
				c.setLowByte(0xa0, c.excAR)
			}
		}
		c.setLowWord(0x90, teid)
		c.excDATProt = false
	case pgmALETSpecification, pgmALENTranslation, pgmALESequence, pgmASTEValidity, pgmASTESequence, pgmExtendedAuthority:
		c.setLowByte(0xa0, c.excAR)
	case pgmData:
		if !c.M.S370 {
			c.setLowByte(0x93, c.dxc)
		}
		c.dxc = 0
	}
	if c.PSW.BC {
		c.PSW.IntCode, c.PSW.ILC = code, byte(ilc/2)
	} else {
		c.setLowByte(0x8c, 0)
		c.setLowByte(0x8d, byte(ilc))
		c.setLowHalf(0x8e, code)
	}
	c.swap(pswPgmOld, pswPgmNew)
	c.M.noteProgram(c, code)
}

// excSpaceBits identifies the address space of a translation or DAT
// protection exception (TEID bits 30-31).
func (c *CPU) excSpaceBits() uint32 {
	return uint32(c.excMode)
}

// noteGuestExit records SIE exits for observation.

// External interruption condition bits held in extPending.
const (
	extClockComparator = 1 << iota
	extCPUTimer
	extInterruptKey
	extEmergency
	extExternalCall
	extServiceSignal
	extMalfunction
	extIntervalTimer
)

// CR0 subclass masks for external interruptions.
func (c *CPU) extEnabled(bit uint32) bool {
	switch bit {
	case extEmergency:
		return c.CR[0]&(1<<14) != 0
	case extExternalCall:
		return c.CR[0]&(1<<13) != 0
	case extClockComparator:
		return c.CR[0]&(1<<11) != 0
	case extCPUTimer:
		return c.CR[0]&(1<<10) != 0
	case extServiceSignal:
		return c.CR[0]&(1<<9) != 0
	case extInterruptKey:
		return c.CR[0]&(1<<6) != 0
	case extMalfunction:
		return c.CR[0]&(1<<15) != 0
	case extIntervalTimer:
		return c.CR[0]&(1<<7) != 0
	}
	return false
}

// pendingExternal returns the highest-priority enabled external condition.
func (c *CPU) pendingExternal() uint32 {
	p := c.extPending
	now := c.tod()
	if c.sie != nil {
		p = 0 // emergency signals and external calls are host conditions
	}
	if now > c.ClockComparator {
		p |= extClockComparator
	}
	if c.cpuTimer() < 0 {
		p |= extCPUTimer
	}
	if c.M.serviceSignal && c.Addr == 0 && c.sie == nil {
		p |= extServiceSignal
	}
	if c.M.S370 && c.intervalTimer() {
		p |= extIntervalTimer
	}
	for _, bit := range []uint32{extMalfunction, extEmergency, extExternalCall, extClockComparator, extCPUTimer, extServiceSignal, extIntervalTimer, extInterruptKey} {
		if p&bit != 0 && c.extEnabled(bit) {
			return bit
		}
	}
	return 0
}

func (c *CPU) takeExternal(bit uint32) {
	var code uint16
	// In System/370 BC mode the interruption code is only in the old PSW;
	// the PSA locations are ordinary storage.
	bc := c.PSW.BC
	if !bc {
		c.setLowHalf(0x84, c.Addr)
	}
	switch bit {
	case extClockComparator:
		code = 0x1004
	case extCPUTimer:
		code = 0x1005
	case extInterruptKey:
		code = 0x0040
		c.extPending &^= bit
	case extEmergency:
		code = 0x1201
		for a := uint16(0); a < 64; a++ {
			if c.emergency&(1<<a) != 0 {
				c.emergency &^= 1 << a
				if !bc {
					c.setLowHalf(0x84, a)
				}
				break
			}
		}
		if c.emergency == 0 {
			c.extPending &^= bit
		}
	case extExternalCall:
		code = 0x1202
		if !bc {
			c.setLowHalf(0x84, c.extCallFrom)
		}
		c.extPending &^= bit
	case extServiceSignal:
		code = 0x2401
		c.setLowWord(0x80, c.M.serviceParam)
		c.M.serviceSignal = false
	case extMalfunction:
		code = 0x1200
		c.extPending &^= bit
	case extIntervalTimer:
		code = 0x0080
		c.itPending = false
	}
	if bc {
		c.PSW.IntCode = code
	} else {
		c.setLowHalf(0x86, code)
	}
	c.M.Interrupts[fmt.Sprintf("ext %04X", code)]++
	c.swap(pswExtOld, pswExtNew)
}

// takeIO performs an I/O interruption for a subchannel.
func (c *CPU) takeIO(sid uint32, intparm uint32) {
	c.setLowWord(0xb8, sid)
	c.setLowWord(0xbc, intparm)
	c.M.Interrupts["io"]++
	c.swap(pswIOOld, pswIONew)
}

// takeSVC performs a supervisor-call interruption.
func (c *CPU) takeSVC(code byte) {
	if c.sie != nil && c.sieSVCIntercepted(code) {
		panic(sieExitRequest{code: sieCodeInst})
	}
	c.PSW.IA = c.next & c.amask
	ilc := c.ilc
	if c.exAddr {
		ilc = 4
		c.PSW.IA = (c.exIA + 4) & c.amask
		c.exAddr = false
	}
	if c.PSW.BC {
		c.PSW.IntCode, c.PSW.ILC = uint16(code), byte(ilc/2)
	} else {
		c.setLowByte(0x88, 0)
		c.setLowByte(0x89, byte(ilc))
		c.setLowHalf(0x8a, uint16(code))
	}
	c.M.Interrupts["svc"]++
	if c.M.Interrupts["svc"] <= 64 {
		c.M.event("svc", c, fmt.Sprintf("code %d at %08X", code, c.ia))
	}
	c.swap(pswSVCOld, pswSVCNew)
}

// Restart performs a restart interruption (the operator RESTART function).
func (c *CPU) Restart() {
	c.Stopped = false
	c.swap(pswRestartOld, pswRestartNew)
}

// cpuTimer returns the current CPU-timer value; it decrements with the TOD
// clock and is negative once it has passed zero.
func (c *CPU) cpuTimer() int64 { return c.timerValue - int64(c.M.tod-c.timerRef) }

func (c *CPU) setCPUTimer(v int64) {
	c.timerValue = v
	c.timerRef = c.M.tod
}
