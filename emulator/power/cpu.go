// Package power emulates a 64-bit big-endian Power ISA server processor in
// guest-partition (supervisor) mode. The hypervisor is not emulated in
// hypervisor state: hypervisor calls (sc 1) are delivered to a host handler,
// and the partition's hashed page table is a host-owned structure that the
// handler maintains. Instructions the core does not implement are offered to
// an extension handler before raising an illegal-instruction interrupt, so
// processor-specific extensions can be supplied by callers.
package power

import "fmt"

// POWER9 User's Manual 4.6.3.3: all load-reserve/store-conditional sizes
// share a 128-byte reservation granule per hardware thread.
const reservationGranule = uint64(128)

// MSR bits (bit 0 is the most significant).
const (
	MSRSF  = uint64(1) << 63
	MSRTA  = uint64(1) << 62 // PowerPC AS tags-active mode
	MSRHV  = uint64(1) << 60
	MSRVEC = uint64(1) << 25
	MSRVSX = uint64(1) << 23
	MSREE  = uint64(1) << 15
	MSRPR  = uint64(1) << 14
	MSRFP  = uint64(1) << 13
	MSRME  = uint64(1) << 12
	MSRFE0 = uint64(1) << 11
	MSRFE1 = uint64(1) << 8
	MSRIR  = uint64(1) << 5
	MSRDR  = uint64(1) << 4
	MSRRI  = uint64(1) << 1
	MSRLE  = uint64(1) << 0
)

const (
	MSRPRShift = 14
	MSRIRShift = 5
)

// XER bits.
const (
	XERSO   = uint64(1) << 31
	XEROV   = uint64(1) << 30
	XERCA   = uint64(1) << 29
	XEROV32 = uint64(1) << 19
	XERCA32 = uint64(1) << 18
	XERT02  = uint64(1) << 22
	XERT07  = uint64(1) << 21
	XERTAG  = uint64(1) << 20
)

// Interrupt vectors.
const (
	VecSystemReset   = 0x100
	VecMachineCheck  = 0x200
	VecDataStorage   = 0x300
	VecDataSegment   = 0x380
	VecInstrStorage  = 0x400
	VecInstrSegment  = 0x480
	VecExternal      = 0x500
	VecAlignment     = 0x600
	VecProgram       = 0x700
	VecFPUnavailable = 0x800
	VecDecrementer   = 0x900
	VecSystemCall    = 0xc00
	VecVecUnavail    = 0xf20
	VecVSXUnavail    = 0xf40
)

// Program interrupt SRR1 reasons.
const (
	ProgFP         = uint64(1) << 20
	ProgIllegal    = uint64(1) << 19
	ProgPrivileged = uint64(1) << 18
	ProgTrap       = uint64(1) << 17
)

// SLBEntry is one segment lookaside buffer entry as written by slbmte.
type SLBEntry struct {
	implicit bool // synthesized by the partition identity policy
	Valid    bool
	ESID     uint64 // effective segment id (EA >> 28 or EA >> 40)
	VSID     uint64
	B        uint8  // 0: 256MB segment, 1: 1TB segment
	Flags    uint64 // RS bits 52:63 (Ks Kp N L C LP)
}

// PageShift returns the base page size selected by the entry's L/LP bits.
func (e SLBEntry) PageShift() uint {
	if e.Flags&0x100 == 0 {
		return 12
	}
	if (e.Flags>>4)&3 == 1 {
		return 16
	}
	return 24
}

func (e SLBEntry) segmentShift() uint {
	if e.B == 1 {
		return 40
	}
	return 28
}

// CPU is one hardware thread.
type CPU struct {
	m     *Machine
	Index int

	GPR [32]uint64
	FPR [32]uint64
	VSR [64][2]uint64
	CR  uint32
	LR  uint64
	CTR uint64
	XER uint64
	PC  uint64
	MSR uint64

	FPSCR uint64
	VSCR  uint32

	SRR0, SRR1 uint64
	DAR        uint64
	DSISR      uint32
	SPRG       [4]uint64
	SPR        map[int]uint64 // SPRs without dedicated fields
	// Frequently read SPRs kept in fields, readable by native blocks:
	// CTRL (152, read as 136), and the offsets of IC (848), VTB (849),
	// PURR (309) and SPURR (308) from their underlying counters.
	ctrl, icOffset, vtbOffset, purrOffset, spurrOffset uint64
	decAt                                              int64 // time base value at which DEC becomes negative

	SLB      [64]SLBEntry
	slbNext  uint64
	slbHint  uint8
	slbValid uint64 // bit i: SLB[i].Valid (maintained by setSLB)
	resValid bool
	resAddr  uint64
	resSize  int

	Instructions uint64
	// Parked CPUs retain registers but do not execute in Machine.Run until
	// their backend releases them (for example, a firmware CPU-start call).
	Parked      bool
	Waiting     bool
	wakePending bool
	external    bool // level presented by the backend interrupt controller
	yielded     bool
	nextPC      uint64
	fault       bool // an interrupt was raised by the current instruction
	stop        *StopReason

	tlb    [tlbSize]tlbEntry
	itlb   [tlbSize]tlbEntry
	tlbGen uint64

	// sync ends the current run of instructions without interrupt checks:
	// it is set by anything that can change interrupt enablement, timer
	// deadlines, interrupt inputs or scheduling (MSR writes, SPR writes,
	// interrupts, hypervisor calls and extension callbacks).
	sync bool
	// fetchPage caches the instruction page translation: the effective page
	// number plus one, its real base and the translation generation.
	fetchPage, fetchReal, fetchGen uint64
	fetchSlot                      uint64
	fetchSlotVer                   uint32
	// jitCache maps effective PCs to native blocks; it is host state and
	// is not part of checkpoints.
	jitCache *[jitCacheSize]jitCacheEntry
	jitInd   *[jitIndirectSize]jitIndirect
	lastWord uint32 // the word step last executed (0 after a fetch fault)
}

// readVSR returns the architectural register: FPRs alias doubleword0 of
// VSR0..31. FPR is the canonical storage for that shared doubleword.
func (c *CPU) readVSR(index uint32) [2]uint64 {
	value := c.VSR[index]
	if index < 32 {
		value[0] = c.FPR[index]
	}
	return value
}

func (c *CPU) writeVSR(index uint32, value [2]uint64) {
	c.VSR[index] = value
	if index < 32 {
		c.FPR[index] = value[0]
	}
}

type tlbEntry struct {
	tag     uint64 // see tlbTag; zero is invalid
	gen     uint64
	real    uint64
	slot    uint64  // HPTE slot+1; zero for real/window mappings
	verPtr  uintptr // &Machine.slotVer[slot-1], or &jitZeroVersion, for native checks
	slotVer uint32  // Machine.slotVer[slot-1] when filled
	ok      uint8   // 1 read, 2 write, 4 execute
}

func (c *CPU) String() string { return fmt.Sprintf("<power cpu %d pc=%016x>", c.Index, c.PC) }

// Yield ends the current scheduling quantum after the executing instruction.
// Firmware backends may use this for cooperative processor-yield calls.
func (c *CPU) Yield() { c.yielded, c.sync = true, true }

// WaitForInterrupt suspends instruction execution until an interrupt or
// backend wake event. A decrementer deadline remains live while waiting.
func (c *CPU) WaitForInterrupt() {
	c.sync = true
	if c.wakePending {
		c.wakePending = false
		return
	}
	c.Waiting = true
}

// Wake makes a waiting CPU runnable without inventing an interrupt vector.
func (c *CPU) Wake() {
	c.sync = true
	if c.Waiting {
		c.Waiting = false
	} else {
		// Latch a wake which races with entry into the wait state.
		c.wakePending = true
	}
}

// SetExternalInterrupt sets the external interrupt input. An asserted level
// remains pending across MSR[EE] masking and interrupt entry until the backend
// withdraws it (typically when its interrupt controller is acknowledged).
func (c *CPU) SetExternalInterrupt(asserted bool) { c.external, c.sync = asserted, true }

// SetDEC writes the decrementer.
func (c *CPU) SetDEC(v uint64) {
	c.decAt = int64(c.m.TB()) + int64(int32(uint32(v)))
	c.sync = true
}

// DEC reads the decrementer.
func (c *CPU) DEC() uint64 { return uint64(uint32(int32(c.decAt - int64(c.m.TB())))) }

// CRBit returns condition register bit n (0 is the most significant).
func (c *CPU) CRBit(n uint) bool { return c.CR&(1<<(31-n)) != 0 }

// SetCRBit sets condition register bit n.
func (c *CPU) SetCRBit(n uint, v bool) {
	if v {
		c.CR |= 1 << (31 - n)
	} else {
		c.CR &^= 1 << (31 - n)
	}
}

// SetCRField writes the four-bit field f (0..7).
func (c *CPU) SetCRField(f uint, v uint32) {
	shift := 28 - 4*f
	c.CR = c.CR&^(0xf<<shift) | (v&0xf)<<shift
}

func (c *CPU) compareField(f uint, a, b int64) {
	v := uint32(2)
	if a < b {
		v = 8
	} else if a > b {
		v = 4
	}
	if c.m.as {
		// AS compares also record LT/GT/EQ/IC in XER[36:39], even
		// when BF is nonzero. Ordinary integer compares clear IC.
		c.XER = c.XER&^(uint64(15)<<24) | uint64(v)<<24
	}
	if c.XER&XERSO != 0 {
		v |= 1
	}
	c.SetCRField(f, v)
}

func (c *CPU) compareFieldU(f uint, a, b uint64) {
	v := uint32(2)
	if a < b {
		v = 8
	} else if a > b {
		v = 4
	}
	if c.m.as {
		// AS compares also record LT/GT/EQ/IC in XER[36:39], even
		// when BF is nonzero. Ordinary integer compares clear IC.
		c.XER = c.XER&^(uint64(15)<<24) | uint64(v)<<24
	}
	if c.XER&XERSO != 0 {
		v |= 1
	}
	c.SetCRField(f, v)
}

func (c *CPU) setCR0(v uint64) {
	if c.MSR&MSRSF == 0 {
		c.compareField(0, int64(int32(v)), 0)
		return
	}
	c.compareField(0, int64(v), 0)
}

// Interrupt raises an interrupt now: SRR0/SRR1 are saved and execution
// continues at the vector in real mode. srr0 is the address to resume at.
func (c *CPU) Interrupt(vector, srr0, srr1 uint64) {
	c.Waiting = false
	const set = 0x0000_0000_783f_0000 // SRR1 bits 33:36 and 42:47
	c.SRR0 = srr0
	c.SRR1 = c.MSR&^set | srr1&set
	keep := MSRHV | MSRME
	if c.m.as {
		// AS Book III Figure30: interrupt delivery does not change TA.
		keep |= MSRTA
	}
	c.MSR = MSRSF | c.MSR&keep
	c.PC = vector
	c.nextPC = vector
	c.fault = true
	c.sync = true
	c.resValid = false
	c.m.noteInterrupt(c, vector)
}

func (c *CPU) program(reason uint64) { c.Interrupt(VecProgram, c.PC, reason) }

func (c *CPU) privileged() bool {
	if c.MSR&MSRPR != 0 {
		c.program(ProgPrivileged)
		return false
	}
	return true
}

// Stop ends the current Run after this instruction with the given reason.
func (c *CPU) Stop(kind, detail string) {
	c.stop = &StopReason{Kind: kind, Detail: detail, CPU: c.Index}
	c.sync = true
}

// reserve establishes a load reservation on real address r.
func (c *CPU) reserve(r uint64, n int) {
	c.resValid, c.resAddr, c.resSize = true, r, n
	c.m.reservations = true
}

// Reservation reports the active load-and-reserve address, if any.
func (c *CPU) Reservation() (uint64, bool) { return c.resAddr, c.resValid }

func (c *CPU) mask(ea uint64) uint64 {
	if c.MSR&MSRSF == 0 {
		return ea & 0xffffffff
	}
	return ea
}

func (c *CPU) setMSR(v uint64) {
	// The partition cannot enter hypervisor state; HV and ME are preserved.
	v = v&^(MSRHV|MSRME) | c.MSR&(MSRHV|MSRME)
	if v&MSRPR != 0 {
		v |= MSREE | MSRIR | MSRDR
	}
	c.MSR = v
	c.sync = true
}
