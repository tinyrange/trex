package power

import (
	"encoding/binary"
	"unsafe"

	"golang.org/x/sys/cpu"
)

// Native block register assignment (see jit_amd64.s):
//
//	R15 *CPU   R14 &Mem[0]   R13 *jitCtx   R12 translation generation
//
// RAX, RCX, RDX, RSI, RDI, R8-R11 are scratch. Blocks use no stack.
const (
	regCPU = r15
	regMem = r14
	regCtx = r13
	regGen = r12
	// RBX holds tlbHash (= jitIndirectHash) for the hashed cache indexes.
	regHash = rBX
)

// jitCtx is shared with native code; field offsets are fixed below.
type jitCtx struct {
	left      uint64  // instructions the native run may still retire
	memLen    uint64  // len(Mem)
	codePages uintptr // &Machine.codePages[0]
	tags      uintptr // &Machine.tags[0], or 0
	storeSlow uint64  // 1: stores take the interpreter path; 2: those touching resGranule do
	gen       uint64  // translation generation for TLB hits
	reserved  uint64  // out: the block established a reservation
	slotVer   uintptr // &Machine.slotVer[0], or 0
	exit      uint64  // out: nonzero after a side exit
	// Counter bases: the machine's and the CPU's instruction counts plus
	// the run's initial left, so count = base - left - (unretired part of
	// the current block).
	instrBase, cpuInstrBase uint64
	tbOffset                uint64
	indirect                uintptr // &CPU.jitInd[0]
	htab                    uintptr // &Machine.HTAB.Entries[0], or 0
	resGranule              uint64  // storeSlow 2: the one other reservation's real address / 128
	ret                     uint64  // out: why the run returned without a side exit (jitReturn)
}

const (
	ctxLeft       = 0
	ctxMemLen     = 8
	ctxCodePages  = 16
	ctxTags       = 24
	ctxStoreSlow  = 32
	ctxGen        = 40
	ctxReserved   = 48
	ctxSlotVer    = 56
	ctxExit       = 64
	ctxInstrBase  = 72
	ctxCPUBase    = 80
	ctxTBOffset   = 88
	ctxIndirect   = 96
	ctxHTAB       = 104
	ctxResGranule = 112
	ctxRet        = 120
)

// jitReturn records why a native run returned to the dispatcher without a
// side exit (JITStats.Returns).
type jitReturn uint8

const (
	retBudget   jitReturn = 1 + iota // a block's prologue found too few instructions left
	retUnlinked                      // a direct jump in the page to code not compiled (yet)
	retLeave                         // an end outside the chaining rules
	retSync                          // mtmsrd/rfid/rfscv/DEC write: interrupts are checked
	retIndirect                      // an indirect or cross-page target missed the branch cache
	jitReturns
)

var jitReturnNames = [jitReturns]string{"", "budget", "unlinked", "leave", "sync", "indirect"}

var (
	offGPR      = int32(unsafe.Offsetof(CPU{}.GPR))
	offCR       = int32(unsafe.Offsetof(CPU{}.CR))
	offLR       = int32(unsafe.Offsetof(CPU{}.LR))
	offCTR      = int32(unsafe.Offsetof(CPU{}.CTR))
	offXER      = int32(unsafe.Offsetof(CPU{}.XER))
	offPC       = int32(unsafe.Offsetof(CPU{}.PC))
	offTLB      = int32(unsafe.Offsetof(CPU{}.tlb))
	offSPRG     = int32(unsafe.Offsetof(CPU{}.SPRG))
	offResValid = int32(unsafe.Offsetof(CPU{}.resValid))
	offResAddr  = int32(unsafe.Offsetof(CPU{}.resAddr))
	offResSize  = int32(unsafe.Offsetof(CPU{}.resSize))
	offMSR      = int32(unsafe.Offsetof(CPU{}.MSR))
	offSRR0     = int32(unsafe.Offsetof(CPU{}.SRR0))
	offSRR1     = int32(unsafe.Offsetof(CPU{}.SRR1))
	offDAR      = int32(unsafe.Offsetof(CPU{}.DAR))
	offDSISR    = int32(unsafe.Offsetof(CPU{}.DSISR))
	offCtrl     = int32(unsafe.Offsetof(CPU{}.ctrl))
	offDecAt    = int32(unsafe.Offsetof(CPU{}.decAt))
	offSync     = int32(unsafe.Offsetof(CPU{}.sync))
	offFPR      = int32(unsafe.Offsetof(CPU{}.FPR))
	offIC       = int32(unsafe.Offsetof(CPU{}.icOffset))
	offVTB      = int32(unsafe.Offsetof(CPU{}.vtbOffset))
	offPURR     = int32(unsafe.Offsetof(CPU{}.purrOffset))
	offSPURR    = int32(unsafe.Offsetof(CPU{}.spurrOffset))
)

// The native hash register's constant must match both cache hashes.
var _ = [1]struct{}{}[tlbHash^jitIndirectHash]

// jitPopcnt reports host POPCNT support.
var jitPopcnt = cpu.X86.HasPOPCNT

// The native TLB probe assumes this entry layout.
var jitLayoutOK = unsafe.Sizeof(tlbEntry{}) == 48 && unsafe.Offsetof(tlbEntry{}.gen) == 8 &&
	unsafe.Offsetof(tlbEntry{}.real) == 16 && unsafe.Offsetof(tlbEntry{}.slot) == 24 &&
	unsafe.Offsetof(tlbEntry{}.verPtr) == 32 && unsafe.Offsetof(tlbEntry{}.slotVer) == 40 &&
	unsafe.Offsetof(tlbEntry{}.ok) == 44 &&
	unsafe.Offsetof(jitCtx{}.slotVer) == ctxSlotVer && unsafe.Offsetof(jitCtx{}.exit) == ctxExit &&
	unsafe.Offsetof(jitCtx{}.instrBase) == ctxInstrBase && unsafe.Offsetof(jitCtx{}.cpuInstrBase) == ctxCPUBase &&
	unsafe.Offsetof(jitCtx{}.tbOffset) == ctxTBOffset && unsafe.Sizeof(CPU{}.DSISR) == 4 &&
	unsafe.Offsetof(jitCtx{}.indirect) == ctxIndirect && unsafe.Sizeof(jitIndirect{}) == 56 &&
	unsafe.Offsetof(jitCtx{}.htab) == ctxHTAB &&
	unsafe.Offsetof(jitIndirect{}.gen) == 8 && unsafe.Offsetof(jitIndirect{}.mode) == 16 &&
	unsafe.Offsetof(jitIndirect{}.slot) == 24 && unsafe.Offsetof(jitIndirect{}.code) == 32 &&
	unsafe.Offsetof(jitIndirect{}.slotVer) == 48 &&
	unsafe.Offsetof(jitCtx{}.gen) == ctxGen && unsafe.Offsetof(jitCtx{}.storeSlow) == ctxStoreSlow &&
	unsafe.Offsetof(jitCtx{}.reserved) == ctxReserved && unsafe.Sizeof(CPU{}.resSize) == 8 &&
	unsafe.Offsetof(jitCtx{}.resGranule) == ctxResGranule && reservationGranule == 128 &&
	unsafe.Offsetof(jitCtx{}.ret) == ctxRet

// jitMode is the MSR state a block is compiled under.
const jitModeMask = MSRSF | MSRTA | MSRIR | MSRDR | MSRPR

// jitMaxInstructions bounds a block.
const jitMaxInstructions = 256

type jitExit struct {
	label   int
	pc      uint64
	retired int
	reason  jitExitReason
}

// jitExitReason records why a block side-exited (JITStats.ExitReasons).
type jitExitReason uint8

const (
	exitOther      jitExitReason = 1 + iota // instruction-specific: traps, FP unavailable, long strings
	exitStoreSlow                           // every store interpreted (a watch or several reservations)
	exitRealBounds                          // real-mode access beyond memory
	exitTLBTag                              // no TLB entry for the page and state
	exitTLBGen                              // entry from an older translation generation
	exitTLBSlot                             // the entry's HPTE slot changed
	exitTLBAccess                           // entry not filled for this access kind
	exitPageCross                           // access crosses a page
	exitReserved                            // store to another CPU's reservation granule
	exitCodePage                            // store to a page holding blocks
	exitAlign                               // misaligned AS quadword
	exitReasons
)

var jitExitReasonNames = [exitReasons]string{"", "other", "store_slow", "real_bounds", "tlb_tag", "tlb_gen", "tlb_slot",
	"tlb_access", "page_cross", "reserved", "code_page", "align"}

// jitSite is a direct jump to another block in the same page: the rel32 at
// off initially leaves the block for target, and is patched to enter the
// target block once it is compiled.
type jitSite struct {
	off    int
	target uint64 // effective address
	stub   int    // label of the leaving code
}

type jitCompiler struct {
	a     asm
	m     *Machine
	mode  uint64
	sf    bool
	page  uint64 // effective page of the block
	chain bool
	exits []jitExit
	sites []jitSite
	// counts are imm32 positions to patch with the instructions of the
	// block after the one at index (the unretired part, see count).
	counts []jitExit
	// per instruction
	pc uint64
	i  int
}

func gpr(n uint32) mem { return at(regCPU, offGPR+8*int32(n)) }

var (
	memCR  = at(regCPU, offCR)
	memLR  = at(regCPU, offLR)
	memCTR = at(regCPU, offCTR)
	memXER = at(regCPU, offXER)
	memPC  = at(regCPU, offPC)
)

// jitCompile translates the instructions at real address real (effective
// address ea) under mode. It returns the code, the number of instructions
// the block retires when it runs to its end (zero when the first
// instruction is not compiled natively) and its direct jumps.
//
// A block's entry reserves its length from ctx.left, leaving for the
// dispatcher with PC at the block when too few remain; a side exit returns
// the unretired part. Retirement is therefore the decrease in ctx.left over
// a run of chained blocks.
func (m *Machine) jitCompile(ea, real, mode uint64, chain bool) ([]byte, int, []jitSite) {
	// The compiler and its buffers are reused; the returned code and
	// sites are valid until the next compilation.
	j := &m.jit.compiler
	*j = jitCompiler{a: j.a, exits: j.exits[:0], sites: j.sites[:0], counts: j.counts[:0], m: m, mode: mode, sf: mode&MSRSF != 0, chain: chain}
	j.a.reset()
	j.page = j.mask(ea) >> 12
	a := &j.a
	noRoom := a.newLabel()
	a.opRM(true, []byte{0x81}, aluCmp, at(regCtx, ctxLeft), false)
	lenAt := len(a.b)
	a.imm32(0)
	a.jcc(ccB, noRoom)
	a.opRM(true, []byte{0x81}, aluSub, at(regCtx, ctxLeft), false)
	lenAt2 := len(a.b)
	a.imm32(0)
	limit := int((0x1000 - real&0xfff) / 4)
	limit = min(limit, jitMaxInstructions)
	n := 0
	ended := false
	for n < limit {
		w := binary.BigEndian.Uint32(m.Mem[real+uint64(4*n):])
		j.pc, j.i = j.mask(ea+uint64(4*n)), n
		if n > 0 && len(m.Breakpoints) != 0 && m.Breakpoints[j.pc] {
			break // the dispatcher stops before a breakpoint
		}
		mark, exits, sites, counts := len(j.a.b), len(j.exits), len(j.sites), len(j.counts)
		fixups, labels := len(j.a.fixups), len(j.a.labels)
		ok, branch := j.inst(w)
		if !ok {
			// Discard everything the instruction emitted.
			j.a.b, j.exits, j.sites, j.counts = j.a.b[:mark], j.exits[:exits], j.sites[:sites], j.counts[:counts]
			j.a.fixups, j.a.labels = j.a.fixups[:fixups], j.a.labels[:labels]
			break
		}
		n++
		if branch {
			ended = true
			break
		}
	}
	if n == 0 {
		return nil, 0, nil
	}
	if !ended {
		// Fall through to the next instruction (an uncompiled one, the next
		// page or the length bound).
		j.i = n - 1
		j.endAt(j.mask(ea+uint64(4*n)), n)
	}
	for _, c := range j.counts {
		binary.LittleEndian.PutUint32(a.b[c.label:], uint32(n-c.retired-1))
	}
	binary.LittleEndian.PutUint32(a.b[lenAt:], uint32(n))
	binary.LittleEndian.PutUint32(a.b[lenAt2:], uint32(n))
	a.bind(noRoom)
	j.leaveFor(j.mask(ea), retBudget)
	for _, e := range j.exits {
		a.bind(e.label)
		a.aluMI(aluAdd, at(regCtx, ctxLeft), int32(n-e.retired))
		a.storeImm64(at(regCtx, ctxExit), uint64(e.reason), rAX)
		j.leave(e.pc)
	}
	for _, s := range j.sites {
		a.bind(s.stub)
		j.leaveFor(s.target, retUnlinked)
	}
	a.finish()
	return a.b, n, j.sites
}

func (j *jitCompiler) mask(v uint64) uint64 {
	if !j.sf {
		return v & 0xffffffff
	}
	return v
}

// endAt ends the block at pc after the current instruction: a direct jump
// when pc is a chainable address in the same page, else a return to the
// dispatcher.
func (j *jitCompiler) endAt(pc uint64, _ int) {
	if j.chain && pc>>12 == j.page && pc&3 == 0 {
		a := &j.a
		stub := a.newLabel()
		a.byte1(0xe9)
		j.sites = append(j.sites, jitSite{off: len(a.b), target: pc, stub: stub})
		a.rel32(stub)
		return
	}
	if j.chain && pc&3 == 0 {
		// Another page may translate differently: enter its block through
		// the validated indirect-branch cache.
		j.a.movImm(rSI, pc)
		j.endWithPCReg(rSI)
		return
	}
	j.leave(pc)
}

// leave returns to the dispatcher with PC = pc.
func (j *jitCompiler) leave(pc uint64) { j.leaveFor(pc, retLeave) }

// leaveFor is leave recording why the run returned.
func (j *jitCompiler) leaveFor(pc uint64, why jitReturn) {
	j.a.storeImm64(memPC, pc, rAX)
	j.a.storeImm64(at(regCtx, ctxRet), uint64(why), rAX)
	j.a.ret()
}

// sideExit returns a label that leaves the block before the current
// instruction, which the interpreter then executes.
func (j *jitCompiler) sideExit() int { return j.sideExitFor(exitOther) }

// sideExitFor is sideExit recording reason.
func (j *jitCompiler) sideExitFor(reason jitExitReason) int {
	l := j.a.newLabel()
	j.exits = append(j.exits, jitExit{label: l, pc: j.pc, retired: j.i, reason: reason})
	return l
}

// endBranch ends the block after the current instruction at the target in
// RAX (already masked) or, when taken is false at compile time, nowhere.
func (j *jitCompiler) endWithPCReg(reg int) {
	a := &j.a
	if j.chain {
		// Probe the CPU's indirect-branch cache (see jitIndirect): the
		// entry must name this target, translation generation, mode and
		// current HPTE slot version. The target block checks the budget.
		miss := a.newLabel()
		a.movRR(rAX, reg)
		a.shiftRI(shShr, rAX, 2)
		a.imulRR(rAX, regHash)
		a.shiftRI(shShr, rAX, 64-jitIndirectBits)
		a.lea(rDX, atIndex(rAX, rAX, 8, 0)) // no base: rax + rax*8 = 9i
		a.aluRR(aluSub, rDX, rAX)
		a.aluRR(aluSub, rDX, rAX) // 7i
		a.load64(rDI, at(regCtx, ctxIndirect))
		a.lea(rDI, atIndex(rDI, rDX, 8, 0)) // entry
		a.aluRM(aluCmp, reg, at(rDI, 0))
		a.jcc(ccNE, miss)
		a.aluRM(aluCmp, regGen, at(rDI, 8))
		a.jcc(ccNE, miss)
		a.movImm(rCX, j.mode)
		a.aluRM(aluCmp, rCX, at(rDI, 16))
		a.jcc(ccNE, miss)
		if j.m.HTAB != nil {
			current := a.newLabel()
			a.load64(rCX, at(rDI, 24))
			a.testRR(rCX, rCX)
			a.jcc(ccE, current)
			a.load64(rDX, at(regCtx, ctxSlotVer))
			a.load32(rDX, atIndex(rDX, rCX, 4, -4))
			a.opRM(false, []byte{0x3b}, rDX, at(rDI, 48), false)
			a.jcc(ccNE, miss)
			a.bind(current)
		}
		a.store64(memPC, reg)                              // the target's prologue may leave at its start
		a.opRM(false, []byte{0xff}, 4, at(rDI, 32), false) // jmp [rdi+32]
		a.bind(miss)
	}
	a.store64(memPC, reg)
	a.storeImm64(at(regCtx, ctxRet), uint64(retIndirect), rAX)
	a.ret()
}

func (j *jitCompiler) loadRA0(reg int, ra uint32) {
	if ra == 0 {
		j.a.movImm(reg, 0)
		return
	}
	j.a.load64(reg, gpr(ra))
}

// eaD leaves ra0(ra)+d in RSI. Like the interpreter, update forms store
// this unmasked sum; access masks it for 32-bit mode.
func (j *jitCompiler) eaD(ra uint32, d int64) {
	if ra == 0 {
		j.a.movImm(rSI, uint64(d))
		return
	}
	j.a.load64(rSI, gpr(ra))
	if d != 0 {
		j.a.aluRI(aluAdd, rSI, int32(d))
	}
}

// eaX leaves ra0(ra)+GPR[rb] in RSI.
func (j *jitCompiler) eaX(ra, rb uint32) {
	j.loadRA0(rSI, ra)
	j.a.aluRM(aluAdd, rSI, gpr(rb))
}

// access translates the effective address in RSI for an n-byte access,
// leaving the real address in RAX or side-exiting to the interpreter (TLB
// miss, page crossing, code page, watched or reserved storage). RSI is
// preserved and, with translation on, RDI addresses the TLB entry.
func (j *jitCompiler) access(n int, write bool) {
	a := &j.a
	exit := j.sideExitFor
	if write {
		a.aluMI(aluCmp, at(regCtx, ctxStoreSlow), 1)
		a.jcc(ccE, exit(exitStoreSlow))
	}
	ea := rSI
	if !j.sf {
		a.movRR32(r10, rSI)
		ea = r10
	}
	if j.mode&MSRDR == 0 {
		a.load64(rDX, at(regCtx, ctxMemLen))
		a.aluRI(aluSub, rDX, int32(n))
		a.aluRR(aluCmp, ea, rDX)
		a.jcc(ccA, exit(exitRealBounds))
		a.movRR(rAX, ea)
	} else {
		a.movRR(rAX, ea)
		a.shiftRI(shShr, rAX, 12)
		a.movRR(rDX, rAX)
		// CPU.tlbIndex: (vpn<<1 | PR) * tlbHash >> (64 - tlbBits); entries
		// are 48 bytes.
		a.shiftRI(shShl, rAX, 1)
		if j.mode&MSRPR != 0 {
			a.aluRI(aluOr, rAX, 1)
		}
		a.imulRR(rAX, regHash)
		a.shiftRI(shShr, rAX, 64-tlbBits)
		a.lea(rDI, atIndex(rAX, rAX, 2, 0))
		a.shiftRI(shShl, rDI, 4)
		a.shiftRI(shShl, rDX, 3)
		a.aluRI(aluOr, rDX, int32((j.mode>>MSRPRShift&1)<<2|1))
		a.aluRM(aluCmp, rDX, atIndex(regCPU, rDI, 1, offTLB))
		a.jcc(ccNE, exit(exitTLBTag))
		a.aluRM(aluCmp, regGen, atIndex(regCPU, rDI, 1, offTLB+8))
		a.jcc(ccNE, exit(exitTLBGen))
		// A translation through an HPTE slot is current while the slot's
		// version is unchanged (Machine.slotCurrent).
		a.load64(rCX, atIndex(regCPU, rDI, 1, offTLB+32))
		a.load32(rCX, at(rCX, 0))
		a.opRM(false, []byte{0x3b}, rCX, atIndex(regCPU, rDI, 1, offTLB+40), false)
		a.jcc(ccNE, exit(exitTLBSlot))
		bit := uint8(accessRead)
		if write {
			bit = accessWrite
		}
		a.testMI8(atIndex(regCPU, rDI, 1, offTLB+44), bit)
		a.jcc(ccE, exit(exitTLBAccess))
		a.movRR32(rAX, ea)
		a.aluRI32(aluAnd, rAX, 0xfff)
		if n > 1 {
			a.aluRI32(aluCmp, rAX, int32(0x1000-n))
			a.jcc(ccA, exit(exitPageCross))
		}
		a.aluRM(aluOr, rAX, atIndex(regCPU, rDI, 1, offTLB+16))
	}
	if write {
		// Another CPU's reservation is cancelled by the interpreter's
		// store when the stored bytes (at most two granules) overlap it.
		unreserved := a.newLabel()
		a.aluMI(aluCmp, at(regCtx, ctxStoreSlow), 2)
		a.jcc(ccNE, unreserved)
		a.movRR(rDX, rAX)
		a.shiftRI(shShr, rDX, 7)
		reserved := exit(exitReserved)
		a.aluRM(aluCmp, rDX, at(regCtx, ctxResGranule))
		a.jcc(ccE, reserved)
		a.lea(rDX, at(rAX, int32(n-1)))
		a.shiftRI(shShr, rDX, 7)
		a.aluRM(aluCmp, rDX, at(regCtx, ctxResGranule))
		a.jcc(ccE, reserved)
		a.bind(unreserved)
		// R11, so RDI keeps addressing the TLB entry.
		a.movRR(rDX, rAX)
		a.shiftRI(shShr, rDX, 12)
		a.load64(r11, at(regCtx, ctxCodePages))
		a.cmpMI8(atIndex(r11, rDX, 1, 0), 0)
		a.jcc(ccNE, exit(exitCodePage))
	}
}

// load reads n bytes at the real address in RAX into RCX, zero-extended
// (or sign-extended when signed).
func (j *jitCompiler) load(n int, signed bool) {
	a := &j.a
	m := atIndex(regMem, rAX, 1, 0)
	switch n {
	case 1:
		a.loadU8(rCX, m)
	case 2:
		a.loadU16(rCX, m)
		a.rol16by8(rCX)
		if signed {
			a.movsx16(rCX, rCX)
		}
	case 4:
		a.load32(rCX, m)
		a.bswap32(rCX)
		if signed {
			a.movsx32(rCX, rCX)
		}
	default:
		a.load64(rCX, m)
		a.bswap64(rCX)
	}
}

// store writes the low n bytes of RCX (big-endian) at the real address in
// RAX and clears the stored quadwords' pointer tags.
func (j *jitCompiler) store(n int) {
	a := &j.a
	m := atIndex(regMem, rAX, 1, 0)
	switch n {
	case 1:
		a.store8(m, rCX)
	case 2:
		a.rol16by8(rCX)
		a.store16(m, rCX)
	case 4:
		a.bswap32(rCX)
		a.store32(m, rCX)
	default:
		a.bswap64(rCX)
		a.store64(m, rCX)
	}
	if j.m.tags != nil {
		a.load64(r9, at(regCtx, ctxTags))
		j.clearTag(at(rAX, 0))
		if n > 1 {
			j.clearTag(at(rAX, int32(n-1)))
		}
	}
}

// clearTag clears the tag bit of the quadword containing lea(m).
func (j *jitCompiler) clearTag(m mem) {
	a := &j.a
	a.lea(rDX, m)
	a.shiftRI(shShr, rDX, 4)
	a.movRR32(rCX, rDX)
	a.aluRI32(aluAnd, rCX, 63)
	a.shiftRI(shShr, rDX, 6)
	a.movImm(r8, ^uint64(1))
	a.opRR(true, []byte{0xd3}, shRol, r8, false) // rol r8, cl
	a.opRM(true, []byte{0x21}, r8, atIndex(r9, rDX, 8, 0), false)
}

// count leaves in RAX the instruction count the interpreter has while
// executing the current instruction (it counts an instruction before
// executing it), from base (ctxInstrBase or ctxCPUBase).
func (j *jitCompiler) count(base int32) {
	a := &j.a
	a.load64(rAX, at(regCtx, base))
	a.aluRM(aluSub, rAX, at(regCtx, ctxLeft))
	a.opRR(true, []byte{0x81}, aluSub, rAX, false)
	j.counts = append(j.counts, jitExit{label: len(a.b), retired: j.i})
	a.imm32(0)
}

// scaleToTB converts the count in RAX to time-base ticks.
func (j *jitCompiler) scaleToTB() {
	a := &j.a
	a.shiftRI(shShl, rAX, 9)
	a.movImm(rDX, 0)
	a.movImm(rCX, uint64(j.m.cfg.MIPS))
	a.opRR(true, []byte{0xf7}, 6, rCX, false) // div rcx
}

// timeBase leaves Machine.TB() in RAX.
func (j *jitCompiler) timeBase() {
	j.count(ctxInstrBase)
	j.scaleToTB()
	j.a.aluRM(aluAdd, rAX, at(regCtx, ctxTBOffset))
}

// readSPR loads mfspr n into RAX, as CPU.mfspr; false leaves it to the
// interpreter.
func (j *jitCompiler) readSPR(n uint32) bool {
	a := &j.a
	if n&0x10 != 0 && j.mode&MSRPR != 0 && !userReadableSPR(int(n)) {
		return false // privileged
	}
	switch n {
	case 1:
		a.load64(rAX, memXER)
	case 8:
		a.load64(rAX, memLR)
	case 9:
		a.load64(rAX, memCTR)
	case 18:
		a.load32(rAX, at(regCPU, offDSISR))
	case 19:
		a.load64(rAX, at(regCPU, offDAR))
	case 26:
		a.load64(rAX, at(regCPU, offSRR0))
	case 27:
		a.load64(rAX, at(regCPU, offSRR1))
	case 272, 273, 274, 275:
		a.load64(rAX, at(regCPU, offSPRG+8*int32(n-272)))
	case 259:
		a.load64(rAX, at(regCPU, offSPRG+8*3))
	case 136, 152:
		a.load64(rAX, at(regCPU, offCtrl))
	case 22: // DEC: the low word of decAt - TB, as CPU.DEC
		j.timeBase()
		a.load64(rCX, at(regCPU, offDecAt))
		a.aluRR(aluSub, rCX, rAX)
		a.movRR32(rAX, rCX)
	case 268, 269:
		j.timeBase()
		if n == 269 {
			a.shiftRI(shShr, rAX, 32)
		}
	case 849:
		j.timeBase()
		a.aluRM(aluAdd, rAX, at(regCPU, offVTB))
	case 848:
		j.count(ctxCPUBase)
		a.aluRM(aluAdd, rAX, at(regCPU, offIC))
	case 308, 309:
		j.count(ctxCPUBase)
		j.scaleToTB()
		off := offPURR
		if n == 308 {
			off = offSPURR
		}
		a.aluRM(aluAdd, rAX, at(regCPU, off))
	default:
		return false
	}
	return true
}

// addCarry computes RAX = RAX + RCX + carry-in (0, 1, or XER[CA] for -1)
// and sets XER[CA] and XER[CA32] as add3 and setCA.
func (j *jitCompiler) addCarry(ci int) {
	a := &j.a
	// CA32: carry out of the low words.
	a.movRR32(r8, rAX)
	a.movRR32(r9, rCX)
	a.aluRR(aluAdd, r8, r9)
	a.load64(rDX, memXER)
	switch ci {
	case 1:
		a.aluRI(aluAdd, r8, 1)
		a.byte1(0xf9) // stc
		a.aluRR(aluAdc, rAX, rCX)
	case 0:
		a.aluRR(aluAdd, rAX, rCX)
	default:
		a.movRR(r10, rDX)
		a.shiftRI(shShr, r10, 29)
		a.aluRI32(aluAnd, r10, 1)
		a.aluRR(aluAdd, r8, r10)
		a.opRR(true, []byte{0x0f, 0xba}, 4, rDX, false) // bt rdx, 29: CF = CA
		a.byte1(29)
		a.aluRR(aluAdc, rAX, rCX)
	}
	a.setcc(ccB, r9) // CF
	a.movzx8(r9, r9)
	a.shiftRI(shShr, r8, 32)
	j.setCA(r9, r8)
}

// setCA writes XER[CA] and XER[CA32] from 0/1 registers (clobbers RDX).
func (j *jitCompiler) setCA(ca, ca32 int) {
	a := &j.a
	a.load64(rDX, memXER)
	a.aluRI(aluAnd, rDX, ^int32(XERCA|XERCA32))
	a.shiftRI(shShl, ca, 29)
	a.aluRR(aluOr, rDX, ca)
	a.shiftRI(shShl, ca32, 18)
	a.aluRR(aluOr, rDX, ca32)
	a.store64(memXER, rDX)
}

// shiftAlgebraic mirrors shiftRightAlgebraic: RAX holds the sign-extended
// operand, RCX the shift count (already limited to width).
func (j *jitCompiler) shiftAlgebraic(ra uint32, width uint, rc bool) {
	a := &j.a
	big, done := a.newLabel(), a.newLabel()
	a.movRR(rSI, rAX) // v
	a.aluRI32(aluCmp, rCX, int32(width))
	a.jcc(ccAE, big)
	a.shiftRCL(shSar, rAX)
	a.movImm(r8, 1)
	a.shiftRCL(shShl, r8)
	a.aluRI(aluSub, r8, 1)
	a.aluRR(aluAnd, r8, rSI) // lost bits
	a.jmp(done)
	a.bind(big)
	a.shiftRI(shSar, rAX, 63)
	a.movRR(r8, rSI)
	a.bind(done)
	// CA = v < 0 && lost != 0
	a.testRR(r8, r8)
	a.setcc(ccNE, r8)
	a.testRR(rSI, rSI)
	a.setcc(ccS, r9)
	a.aluRR32(aluAnd, r8, r9)
	a.movzx8(r8, r8)
	a.movRR(r9, r8)
	j.setCA(r8, r9)
	j.result(ra, rc)
}

// trap side-exits (so the interpreter raises the trap) when trapCondition
// holds for RAX against RCX.
func (j *jitCompiler) trap(to uint32) {
	a := &j.a
	exit := j.sideExit()
	a.aluRR(aluCmp, rAX, rCX)
	for _, t := range []struct {
		bit uint32
		cc  int
	}{{16, ccL}, {8, ccG}, {4, ccE}, {2, ccB}, {1, ccA}} {
		if to&t.bit != 0 {
			a.jcc(t.cc, exit)
		}
	}
}

// trapRegion side-exits when the AS Trap Doubleword address-region
// condition (TO 28, 29 on POWER9, 30; see CPU.exec) holds for RAX (RA)
// against RCX (RB).
func (j *jitCompiler) trapRegion(to uint32) {
	a := &j.a
	exit := j.sideExit()
	done := a.newLabel()
	segments := func() { // RA>>24 != RB>>24 traps
		a.movRR(r8, rAX)
		a.shiftRI(shShr, r8, 24)
		a.movRR(r9, rCX)
		a.shiftRI(shShr, r9, 24)
		a.aluRR(aluCmp, r8, r9)
		a.jcc(ccNE, exit)
	}
	switch to {
	case 28:
		a.movRR(r8, rAX)
		a.shiftRI(shShr, r8, 48)
		a.movRR(r9, rCX)
		a.shiftRI(shShr, r9, 48)
		a.aluRR(aluCmp, r8, r9)
		a.jcc(ccNE, exit)
		a.testRR(r8, r8)
		a.jcc(ccE, done)
		segments()
		a.aluRR(aluCmp, rAX, rCX)
		a.jcc(ccL, exit)
	case 29:
		nonzero := a.newLabel()
		a.testRR(rCX, rCX)
		a.jcc(ccE, nonzero)
		a.movRR(r9, rCX)
		a.shiftRI(shShr, r9, 48)
		a.testRR(r9, r9)
		a.jcc(ccE, exit)
		a.bind(nonzero)
		segments()
		a.aluRR(aluCmp, rAX, rCX)
		a.jcc(ccB, exit)
	case 30:
		segments()
		a.aluRR(aluCmp, rAX, rCX)
		a.jcc(ccL, exit)
		a.jcc(ccB, exit)
	}
	a.bind(done)
}

// crField writes the comparison value in EAX (LT=8, GT=4, EQ=2) into CR
// field f, recording it in XER for AS and adding XER[SO], as compareField.
func (j *jitCompiler) crField(f uint32) {
	a := &j.a
	a.load64(rCX, memXER)
	if j.m.as {
		a.aluRI(aluAnd, rCX, ^int32(15<<24))
		a.movRR32(rDX, rAX)
		a.shiftRI(shShl, rDX, 24)
		a.aluRR(aluOr, rCX, rDX)
		a.store64(memXER, rCX)
	}
	a.shiftRI32(shShr, rCX, 31)
	a.aluRR32(aluOr, rAX, rCX)
	shift := uint8(28 - 4*f)
	a.load32(rCX, memCR)
	a.aluRI32(aluAnd, rCX, ^int32(0xf<<shift))
	a.shiftRI32(shShl, rAX, shift)
	a.aluRR32(aluOr, rCX, rAX)
	a.store32(memCR, rCX)
}

// crFromFlags converts the flags of a completed cmp into CR field f.
func (j *jitCompiler) crFromFlags(f uint32, signed bool) {
	a := &j.a
	lt, gt := ccB, ccA
	if signed {
		lt, gt = ccL, ccG
	}
	// EQ unless LT or GT; mov leaves the flags intact.
	a.byte1(0xb8, 2, 0, 0, 0) // mov eax, 2
	a.byte1(0xb9, 8, 0, 0, 0) // mov ecx, 8
	a.cmov(lt, rAX, rCX)
	a.byte1(0xb9, 4, 0, 0, 0) // mov ecx, 4
	a.cmov(gt, rAX, rCX)
	j.crField(f)
}

// cr0 sets CR0 from the result in reg, as setCR0.
func (j *jitCompiler) cr0(reg int) {
	if j.sf {
		j.a.testRR(reg, reg)
	} else {
		j.a.testRR32(reg, reg)
	}
	j.crFromFlags(0, true)
}

// result stores RAX to GPR[rt] and optionally records CR0.
func (j *jitCompiler) result(rt uint32, rc bool) {
	j.a.store64(gpr(rt), rAX)
	if rc {
		j.cr0(rAX)
	}
}

// inst compiles one instruction. ok is false when it must be interpreted;
// branch is true when it ends the block.
func (j *jitCompiler) inst(w uint32) (ok, branch bool) {
	a := &j.a
	po := w >> 26
	rt, ra, rb := (w>>21)&31, (w>>16)&31, (w>>11)&31
	si := int64(int16(w))
	ui := uint64(w & 0xffff)
	switch po {
	case 2, 3: // tdi, twi
		a.load64(rCX, gpr(ra))
		if po == 3 {
			a.movsx32(rAX, rCX)
		} else {
			a.movRR(rAX, rCX)
		}
		a.movImm(rCX, uint64(si))
		j.trap(rt)
	case 8: // subfic
		a.load64(rAX, gpr(ra))
		a.notR(rAX)
		a.movImm(rCX, uint64(si))
		j.addCarry(1)
		a.store64(gpr(rt), rAX)
	case 12, 13: // addic, addic.
		if j.m.as && j.mode&MSRTA != 0 {
			return false, false // AS offset carry
		}
		a.load64(rAX, gpr(ra))
		a.movImm(rCX, uint64(si))
		j.addCarry(0)
		j.result(rt, po == 13)
	case 7: // mulli
		a.load64(rAX, gpr(ra))
		a.movImm(rCX, uint64(si))
		a.imulRR(rAX, rCX)
		a.store64(gpr(rt), rAX)
	case 10, 11: // cmpli, cmpi
		bf := rt >> 2
		if po == 11 {
			if rt&1 != 0 {
				a.load64(rAX, gpr(ra))
				a.aluRI(aluCmp, rAX, int32(si))
			} else {
				a.load32(rAX, gpr(ra))
				a.aluRI32(aluCmp, rAX, int32(si))
			}
			j.crFromFlags(bf, true)
		} else {
			if rt&1 != 0 {
				a.load64(rAX, gpr(ra))
				a.aluRI(aluCmp, rAX, int32(ui))
			} else {
				a.load32(rAX, gpr(ra))
				a.aluRI32(aluCmp, rAX, int32(ui))
			}
			j.crFromFlags(bf, false)
		}
	case 14, 15: // addi, addis
		d := si
		if po == 15 {
			d = si << 16
		}
		if ra == 0 {
			a.movImm(rAX, uint64(d))
		} else {
			a.load64(rAX, gpr(ra))
			if d != 0 {
				a.aluRI(aluAdd, rAX, int32(d))
			}
		}
		a.store64(gpr(rt), rAX)
	case 16: // bc
		return j.branchCond(w, rt, ra, 0), true
	case 18: // b
		d := uint64(int64(int32(w&0x03fffffc<<6) >> 6))
		if w&1 != 0 {
			a.storeImm64(memLR, j.mask(j.pc+4), rAX)
		}
		target := j.pc + d
		if w&2 != 0 {
			target = d
		}
		j.endAt(j.mask(target), j.i+1)
		return true, true
	case 19:
		switch (w >> 1) & 0x3ff {
		case 16: // bclr
			return j.branchCond(w, rt, ra, 1), true
		case 528: // bcctr
			return j.branchCond(w, rt, ra, 2), true
		case 18: // rfid
			return j.rfid(offSRR1, offSRR0, ^uint64(0)), true
		case 82: // AS rfscv: MSR from CTR, PC from LR
			if !j.m.as || j.mode&MSRTA == 0 {
				return false, false
			}
			return j.rfid(offCTR, offLR, ^uint64(0x783f0000)), true
		case 150: // isync
		case 257, 449, 193, 225, 33, 289, 129, 417:
			j.crLogical(w)
		default:
			return false, false
		}
	case 20: // rlwimi
		sh, mb, me := uint(rb), uint((w>>6)&31), uint((w>>1)&31)
		msk := Mask(mb+32, me+32)
		j.rotl32(rt, sh)
		a.aluImm64(aluAnd, rAX, msk, rDX)
		a.load64(rCX, gpr(ra))
		a.aluImm64(aluAnd, rCX, ^msk, rDX)
		a.aluRR(aluOr, rAX, rCX)
		j.result(ra, w&1 != 0)
	case 21: // rlwinm
		sh, mb, me := uint(rb), uint((w>>6)&31), uint((w>>1)&31)
		msk := Mask(mb+32, me+32)
		if mb <= me {
			a.load32(rAX, gpr(rt))
			if sh != 0 {
				a.shiftRI32(shRol, rAX, uint8(sh))
			}
			if msk != 0xffffffff {
				a.aluRI32(aluAnd, rAX, int32(uint32(msk)))
			}
		} else {
			j.rotl32(rt, sh)
			a.aluImm64(aluAnd, rAX, msk, rDX)
		}
		j.result(ra, w&1 != 0)
	case 23: // rlwnm
		mb, me := uint((w>>6)&31), uint((w>>1)&31)
		msk := Mask(mb+32, me+32)
		a.load64(rCX, gpr(rb))
		a.aluRI32(aluAnd, rCX, 31)
		a.load32(rAX, gpr(rt))
		a.opRR(false, []byte{0xd3}, shRol, rAX, false) // rol eax, cl
		if mb > me {
			a.movRR32(rCX, rAX)
			a.shiftRI(shShl, rCX, 32)
			a.aluRR(aluOr, rAX, rCX)
		}
		a.aluImm64(aluAnd, rAX, msk, rDX)
		j.result(ra, w&1 != 0)
	case 24, 25, 26, 27: // ori oris xori xoris
		v := ui
		if po&1 != 0 {
			v <<= 16
		}
		op := aluOr
		if po >= 26 {
			op = aluXor
		}
		if v == 0 && rt == ra {
			break // nop
		}
		a.load64(rAX, gpr(rt))
		if v != 0 {
			a.aluImm64(op, rAX, v, rDX)
		}
		a.store64(gpr(ra), rAX)
	case 28, 29: // andi., andis.
		v := ui
		if po == 29 {
			v <<= 16
		}
		a.load64(rAX, gpr(rt))
		a.aluImm64(aluAnd, rAX, v, rDX)
		j.result(ra, true)
	case 30:
		return j.rotate64(w), false
	case 31:
		if (w>>1)&0x3ff == 178 {
			return j.mtmsrdEE(w), true
		}
		if (w>>1)&0x3ff == 467 && (w>>16)&31|(w>>11)&31<<5 == 22 {
			return j.mtDEC(w), true
		}
		return j.op31(w), false
	case 32, 33, 34, 35, 40, 41, 42, 43: // lwz lwzu lbz lbzu lhz lhzu lha lhau
		n := 4
		switch po &^ 1 {
		case 34:
			n = 1
		case 40, 42:
			n = 2
		}
		j.eaD(ra, si)
		j.access(n, false)
		j.load(n, po == 42 || po == 43)
		a.store64(gpr(rt), rCX)
		if po&1 != 0 {
			a.store64(gpr(ra), rSI)
		}
	case 36, 37, 38, 39, 44, 45: // stw stwu stb stbu sth sthu
		n := 4
		switch po &^ 1 {
		case 38:
			n = 1
		case 44:
			n = 2
		}
		j.eaD(ra, si)
		j.access(n, true)
		a.load64(rCX, gpr(rt))
		j.store(n)
		if po&1 != 0 {
			a.store64(gpr(ra), rSI)
		}
	case 50, 51, 54, 55: // lfd lfdu stfd stfdu: FPR doubleword moves
		a.testMI32(at(regCPU, offMSR), uint32(MSRFP))
		a.jcc(ccE, j.sideExit()) // the interpreter raises FP unavailable
		j.eaD(ra, si)
		fpr := at(regCPU, offFPR+8*int32(rt))
		if po < 54 {
			j.access(8, false)
			j.load(8, false)
			a.store64(fpr, rCX)
		} else {
			j.access(8, true)
			a.load64(rCX, fpr)
			j.store(8)
		}
		if po&1 != 0 {
			a.store64(gpr(ra), rSI)
		}
	case 56: // lq
		return j.loadQuad(w), false
	case 58:
		d := int64(int16(w & 0xfffc))
		switch w & 3 {
		case 3: // AS lmd
			if !j.m.as {
				return false, false
			}
			return j.multiple(rt, ra, d, true), false
		case 0, 1: // ld, ldu
			j.eaD(ra, d)
			j.access(8, false)
			j.load(8, false)
			a.store64(gpr(rt), rCX)
			if w&3 == 1 {
				a.store64(gpr(ra), rSI)
			}
		case 2: // lwa
			j.eaD(ra, d)
			j.access(4, false)
			j.load(4, true)
			a.store64(gpr(rt), rCX)
		default:
			return false, false
		}
	case 62:
		d := int64(int16(w & 0xfffc))
		switch w & 3 {
		case 0, 1: // std, stdu
			j.eaD(ra, d)
			j.access(8, true)
			a.load64(rCX, gpr(rt))
			j.store(8)
			if w&3 == 1 {
				a.store64(gpr(ra), rSI)
			}
		case 2: // stq
			return j.storeQuad(w), false
		default: // AS stmd
			if !j.m.as {
				return false, false
			}
			return j.multiple(rt, ra, d, false), false
		}
	default:
		return false, false
	}
	return true, false
}

// loadQuad mirrors lq, including the AS tag and pointer-type status.
func (j *jitCompiler) loadQuad(w uint32) bool {
	a := &j.a
	rt, ra := (w>>21)&31, (w>>16)&31
	if rt&1 != 0 || rt == ra {
		return false
	}
	j.eaD(ra, int64(int16(w&0xfff0)))
	if j.m.as {
		a.opRR(false, []byte{0xf7}, 0, rSI, false) // test esi, 15
		a.imm32(15)
		a.jcc(ccNE, j.sideExitFor(exitAlign)) // alignment interrupt
	}
	j.access(16, false)
	a.load64(rCX, atIndex(regMem, rAX, 1, 0))
	a.bswap64(rCX)
	a.load64(rDX, atIndex(regMem, rAX, 1, 8))
	a.bswap64(rDX)
	a.store64(gpr(rt), rCX)
	a.store64(gpr(rt+1), rDX)
	if !j.m.as {
		return true
	}
	pt := uint64(w & 15)
	// XER &^= T02|T07|TAG, then set from the quadword's tag.
	a.load64(r8, memXER)
	a.aluRI(aluAnd, r8, ^int32(XERT02|XERT07|XERTAG))
	done := a.newLabel()
	a.shiftRI(shShr, rAX, 4) // quadword index
	a.load64(r9, at(regCtx, ctxTags))
	a.opRM(true, []byte{0x0f, 0xa3}, rAX, at(r9, 0), false) // bt [r9], rax
	a.jcc(ccAE, done)
	a.aluRI(aluOr, r8, int32(XERTAG))
	// T02: hi bit 61 clear and (8 >> hi>>62) & PT.
	var types uint64
	for k := uint64(0); k < 4; k++ {
		if 8>>k&pt != 0 {
			types |= 1 << k
		}
	}
	noT02 := a.newLabel()
	a.opRR(true, []byte{0x0f, 0xba}, 4, rCX, false) // bt rcx, 61
	a.byte1(61)
	a.jcc(ccB, noT02)
	a.movRR(r10, rCX)
	a.shiftRI(shShr, r10, 62)
	a.movImm(r11, types)
	a.opRR(true, []byte{0x0f, 0xa3}, r10, r11, false) // bt r11, r10
	a.jcc(ccAE, noT02)
	a.aluRI(aluOr, r8, int32(XERT02))
	a.bind(noT02)
	// T07: hi>>56 == 0xa0|PT.
	a.movRR(r10, rCX)
	a.shiftRI(shShr, r10, 56)
	a.aluRI(aluCmp, r10, int32(0xa0|pt))
	a.jcc(ccNE, done)
	a.aluRI(aluOr, r8, int32(XERT07))
	a.bind(done)
	a.store64(memXER, r8)
	return true
}

// storeQuad mirrors stq: both doublewords clear the quadword tag, which a
// set XER[TAG] then sets, with the translating HPTE's TS bit.
func (j *jitCompiler) storeQuad(w uint32) bool {
	a := &j.a
	rt, ra := (w>>21)&31, (w>>16)&31
	if rt&1 != 0 {
		return false
	}
	j.eaD(ra, int64(int16(w&0xfffc)))
	if j.m.as {
		a.opRR(false, []byte{0xf7}, 0, rSI, false) // test esi, 15
		a.imm32(15)
		a.jcc(ccNE, j.sideExitFor(exitAlign))
	}
	j.access(16, true)
	a.load64(rCX, gpr(rt))
	a.bswap64(rCX)
	a.store64(atIndex(regMem, rAX, 1, 0), rCX)
	a.load64(rCX, gpr(rt+1))
	a.bswap64(rCX)
	a.store64(atIndex(regMem, rAX, 1, 8), rCX)
	if j.m.tags == nil {
		return true
	}
	a.load64(r9, at(regCtx, ctxTags))
	if !j.m.as {
		j.clearTag(at(rAX, 0))
		j.clearTag(at(rAX, 15))
		return true
	}
	// Aligned: one quadword. Its tag becomes XER[TAG].
	set, done := a.newLabel(), a.newLabel()
	a.movRR(rDX, rAX)
	a.shiftRI(shShr, rDX, 4)
	a.testMI32(memXER, uint32(XERTAG))
	a.jcc(ccNE, set)
	a.opRM(true, []byte{0x0f, 0xb3}, rDX, at(r9, 0), false) // btr [r9], rdx
	a.jmp(done)
	a.bind(set)
	a.opRM(true, []byte{0x0f, 0xab}, rDX, at(r9, 0), false) // bts [r9], rdx
	if j.mode&MSRDR != 0 && j.m.HTAB != nil {
		// RDI still addresses the TLB entry used by access.
		a.load64(rCX, atIndex(regCPU, rDI, 1, offTLB+24))
		a.testRR(rCX, rCX)
		a.jcc(ccE, done)
		a.shiftRI(shShl, rCX, 4)
		a.load64(rDX, at(regCtx, ctxHTAB))
		a.movImm(r8, hpteTagSet)
		a.opRM(true, []byte{0x09}, r8, atIndex(rDX, rCX, 1, -8), false) // or [rdx+rcx-8], r8
	}
	a.bind(done)
	return true
}

// multiple mirrors lmd/stmd when the registers' storage is in one page.
func (j *jitCompiler) multiple(rt, ra uint32, d int64, load bool) bool {
	a := &j.a
	n := int(32 - rt)
	if n*8 > 256 {
		return false
	}
	j.eaD(ra, d)
	j.access(8*n, !load)
	if load {
		// All loads complete before any register changes; a page fits
		// them all, so none can fault after the access check.
		for r := rt; r < 32; r++ {
			a.load64(rCX, atIndex(regMem, rAX, 1, int32(8*(r-rt))))
			a.bswap64(rCX)
			a.store64(gpr(r), rCX)
		}
		return true
	}
	a.movRR(rSI, rAX)
	for r := rt; r < 32; r++ {
		a.lea(rAX, at(rSI, int32(8*(r-rt))))
		a.load64(rCX, gpr(r))
		j.store(8)
	}
	return true
}

// rotl32 leaves rotl32(GPR[rs], sh) (the doubled word rotated) in RAX.
func (j *jitCompiler) rotl32(rs uint32, sh uint) {
	a := &j.a
	a.load32(rAX, gpr(rs))
	a.movRR(rCX, rAX)
	a.shiftRI(shShl, rCX, 32)
	a.aluRR(aluOr, rAX, rCX)
	if sh&63 != 0 {
		a.shiftRI(shRol, rAX, uint8(sh&63))
	}
}

func (j *jitCompiler) rotate64(w uint32) bool {
	a := &j.a
	rs, ra := (w>>21)&31, (w>>16)&31
	sh := uint((w>>11)&31) | uint((w>>1)&1)<<5
	mf := (w >> 5) & 63
	mb := uint(mf>>1 | (mf&1)<<5)
	var msk uint64
	insert := false
	switch (w >> 2) & 7 {
	case 0:
		msk = Mask(mb, 63)
	case 1:
		msk = Mask(0, mb)
	case 2:
		msk = Mask(mb, 63-sh)
	case 3:
		msk, insert = Mask(mb, 63-sh), true
	case 4:
		switch (w >> 1) & 0xf {
		case 8:
			msk = Mask(mb, 63)
		case 9:
			msk = Mask(0, mb)
		default:
			return false
		}
		a.load64(rCX, gpr((w>>11)&31))
		a.load64(rAX, gpr(rs))
		a.shiftRCL(shRol, rAX) // rotate count is masked to 6 bits
		a.aluImm64(aluAnd, rAX, msk, rDX)
		j.result(ra, w&1 != 0)
		return true
	case 6, 7:
		if !j.m.as {
			return false
		}
		return j.conditionalSelect(w)
	default:
		return false
	}
	a.load64(rAX, gpr(rs))
	if sh != 0 {
		a.shiftRI(shRol, rAX, uint8(sh))
	}
	if msk != ^uint64(0) {
		a.aluImm64(aluAnd, rAX, msk, rDX)
	}
	if insert {
		a.load64(rCX, gpr(ra))
		a.aluImm64(aluAnd, rCX, ^msk, rDX)
		a.aluRR(aluOr, rAX, rCX)
	}
	j.result(ra, w&1 != 0)
	return true
}

// conditionalSelect mirrors CPU.conditionalSelect.
func (j *jitCompiler) conditionalSelect(w uint32) bool {
	a := &j.a
	rs, ra, sh := (w>>21)&31, (w>>16)&31, (w>>11)&31
	xbi := (w >> 7) & 15
	if w&0x60 != 0 {
		return false
	}
	if (w>>2)&7 == 7 {
		a.load64(rAX, gpr(rs))
	} else {
		a.movImm(rAX, uint64(int64(int8(rs<<3)>>3)))
	}
	if (w>>1)&1 != 0 {
		a.load64(rCX, gpr(sh))
	} else {
		a.movImm(rCX, uint64(int64(int8(sh<<3)>>3)))
	}
	a.load64(rDX, memXER)
	a.opRR(true, []byte{0x0f, 0xba}, 4, rDX, false) // bt rdx, imm8
	a.byte1(byte(31 - xbi))
	a.cmov(ccAE, rAX, rCX) // CF clear: second
	j.result(ra, w&1 != 0)
	return true
}

// crLogical computes the CR bit operations of opcode 19.
func (j *jitCompiler) crLogical(w uint32) {
	a := &j.a
	bt, ba, bb := (w>>21)&31, (w>>16)&31, (w>>11)&31
	a.load32(rDX, memCR)
	a.movRR32(rAX, rDX)
	a.shiftRI32(shShr, rAX, uint8(31-ba))
	a.movRR32(rCX, rDX)
	a.shiftRI32(shShr, rCX, uint8(31-bb))
	switch (w >> 1) & 0x3ff {
	case 257: // crand
		a.aluRR32(aluAnd, rAX, rCX)
	case 449: // cror
		a.aluRR32(aluOr, rAX, rCX)
	case 193: // crxor
		a.aluRR32(aluXor, rAX, rCX)
	case 225: // crnand
		a.aluRR32(aluAnd, rAX, rCX)
		a.aluRI32(aluXor, rAX, 1)
	case 33: // crnor
		a.aluRR32(aluOr, rAX, rCX)
		a.aluRI32(aluXor, rAX, 1)
	case 289: // creqv
		a.aluRR32(aluXor, rAX, rCX)
		a.aluRI32(aluXor, rAX, 1)
	case 129: // crandc
		a.aluRI32(aluXor, rCX, 1)
		a.aluRR32(aluAnd, rAX, rCX)
	case 417: // crorc
		a.aluRI32(aluXor, rCX, 1)
		a.aluRR32(aluOr, rAX, rCX)
	}
	a.aluRI32(aluAnd, rAX, 1)
	a.shiftRI32(shShl, rAX, uint8(31-bt))
	a.aluRI32(aluAnd, rDX, ^int32(uint32(1)<<(31-bt)))
	a.aluRR32(aluOr, rDX, rAX)
	a.store32(memCR, rDX)
}

// branchCond compiles bc (kind 0), bclr (1) and bcctr (2), mirroring
// CPU.condition: the target is read before LR is updated.
func (j *jitCompiler) branchCond(w, bo, bi uint32, kind int) bool {
	a := &j.a
	next := j.mask(j.pc + 4)
	if kind == 2 && bo&4 == 0 {
		return false // bcctr with decrement is an invalid form; interpret it
	}
	var target uint64
	switch kind {
	case 0:
		d := uint64(int64(int16(w & 0xfffc)))
		target = j.mask(j.pc + d)
		if w&2 != 0 {
			target = j.mask(d)
		}
	case 1:
		a.load64(rSI, memLR)
		a.aluRI(aluAnd, rSI, ^int32(3))
	case 2:
		a.load64(rSI, memCTR)
		a.aluRI(aluAnd, rSI, ^int32(3))
	}
	if kind != 0 && !j.sf {
		a.movRR32(rSI, rSI)
	}
	if w&1 != 0 {
		a.storeImm64(memLR, next, rAX)
	}
	notTaken := a.newLabel()
	if bo&4 == 0 {
		a.aluMI(aluSub, memCTR, 1)
		a.load64(rAX, memCTR)
		if j.sf {
			a.testRR(rAX, rAX)
		} else {
			a.testRR32(rAX, rAX)
		}
		if bo&2 != 0 {
			a.jcc(ccNE, notTaken) // branch only if CTR == 0
		} else {
			a.jcc(ccE, notTaken)
		}
	}
	if bo&16 == 0 {
		a.testMI32(memCR, uint32(1)<<(31-bi))
		if bo&8 != 0 {
			a.jcc(ccE, notTaken)
		} else {
			a.jcc(ccNE, notTaken)
		}
	}
	if kind == 0 {
		j.endAt(target, j.i+1)
	} else {
		j.endWithPCReg(rSI)
	}
	a.bind(notTaken)
	j.endAt(next, j.i+1)
	return true
}

// op31 compiles the supported opcode-31 forms in CPU.exec31's precedence.
// mtmsrdEE compiles mtmsrd with L=1 (MSR[EE,RI] from RS) in privileged
// state, ending the block. Clearing EE cannot make an interrupt
// deliverable, so the block chains on; setting it returns to the dispatcher
// with CPU.sync set so the run loop delivers any pending interrupt before
// the next instruction, as the interpreter's setMSR does. MSR[EE,RI] are
// outside jitModeMask.
func (j *jitCompiler) mtmsrdEE(w uint32) bool {
	if j.mode&MSRPR != 0 || w&(1<<16) == 0 {
		return false
	}
	a := &j.a
	next := j.mask(j.pc + 4)
	a.load64(rAX, gpr((w>>21)&31))
	a.aluRI(aluAnd, rAX, int32(MSREE|MSRRI))
	a.load64(rCX, at(regCPU, offMSR))
	a.aluRI(aluAnd, rCX, ^int32(MSREE|MSRRI))
	a.aluRR(aluOr, rCX, rAX)
	a.store64(at(regCPU, offMSR), rCX)
	enabled := a.newLabel()
	a.aluRI(aluAnd, rAX, int32(MSREE))
	a.jcc(ccNE, enabled)
	j.endAt(next, j.i+1)
	a.bind(enabled)
	a.movImm(rAX, 1)
	a.store8(at(regCPU, offSync), rAX)
	j.leaveFor(next, retSync)
	return true
}

// rfid ends the block for rfid (MSR from SRR1, PC from SRR0) or AS rfscv
// (CTR and LR, without the bits keep clears): MSR as CPU.setMSR (HV and ME
// kept, problem state forcing EE, IR and DR), PC masked under the new
// MSR[SF], the reservation cleared, and CPU.sync set so the run loop
// delivers interrupts and finds the new mode's block.
func (j *jitCompiler) rfid(msrFrom, pcFrom int32, keep uint64) bool {
	if j.mode&MSRPR != 0 {
		return false
	}
	a := &j.a
	a.load64(rAX, at(regCPU, msrFrom))
	a.aluImm64(aluAnd, rAX, keep&^(MSRHV|MSRME), rDX)
	a.load64(rCX, at(regCPU, offMSR))
	a.aluImm64(aluAnd, rCX, MSRHV|MSRME, rDX)
	a.aluRR(aluOr, rAX, rCX)
	a.movRR(rCX, rAX)
	a.shiftRI(shShr, rCX, MSRPRShift)
	a.aluRI(aluAnd, rCX, 1)
	a.movImm(rDX, 0)
	a.aluRR(aluSub, rDX, rCX) // all ones in problem state
	a.aluRI(aluAnd, rDX, int32(MSREE|MSRIR|MSRDR))
	a.aluRR(aluOr, rAX, rDX)
	a.store64(at(regCPU, offMSR), rAX)
	a.load64(rCX, at(regCPU, pcFrom))
	a.aluRI(aluAnd, rCX, ^int32(3))
	a.movRR32(r8, rCX)
	a.testRR(rAX, rAX)
	a.cmov(ccNS, rCX, r8) // 32-bit mode: the low word
	a.store64(memPC, rCX)
	a.opRM(false, []byte{0xc6}, 0, at(regCPU, offResValid), false)
	a.byte1(0)
	a.movImm(rAX, 1)
	a.store8(at(regCPU, offSync), rAX)
	a.storeImm64(at(regCtx, ctxRet), uint64(retSync), rAX)
	a.ret()
	return true
}

// mtDEC compiles mtspr DEC as CPU.SetDEC (decAt = TB + the signed low
// word), ending the block with CPU.sync set for the new deadline.
func (j *jitCompiler) mtDEC(w uint32) bool {
	if j.mode&MSRPR != 0 {
		return false
	}
	a := &j.a
	j.timeBase()
	a.load64(rCX, gpr((w>>21)&31))
	a.movsx32(rCX, rCX)
	a.aluRR(aluAdd, rAX, rCX)
	a.store64(at(regCPU, offDecAt), rAX)
	a.movImm(rAX, 1)
	a.store8(at(regCPU, offSync), rAX)
	j.leaveFor(j.mask(j.pc+4), retSync)
	return true
}

func (j *jitCompiler) op31(w uint32) bool {
	a := &j.a
	if j.m.as && (w>>1)&63 == 36 { // AS TX-form trap on an XER bit
		to, xbi := (w>>21)&31, (w>>7)&15
		if to > 1 || w&1 != 0 {
			return false
		}
		a.load64(rAX, memXER)
		a.opRR(true, []byte{0x0f, 0xba}, 4, rAX, false) // bt rax, 31-xbi
		a.byte1(byte(31 - xbi))
		if to == 1 {
			a.jcc(ccB, j.sideExit())
		} else {
			a.jcc(ccAE, j.sideExit())
		}
		return true
	}
	rt, ra, rb := (w>>21)&31, (w>>16)&31, (w>>11)&31
	rc := w&1 != 0
	if (w>>1)&0x1f == 15 { // isel
		bc := (w >> 6) & 31
		j.loadRA0(rAX, ra)
		a.load64(rCX, gpr(rb))
		a.testMI32(memCR, uint32(1)<<(31-bc))
		a.cmov(ccE, rAX, rCX)
		a.store64(gpr(rt), rAX)
		return true
	}
	if (w>>2)&0x1ff == 413 { // sradi
		a.load64(rAX, gpr(rt))
		a.movImm(rCX, uint64(rb)|uint64((w>>1)&1)<<5)
		j.shiftAlgebraic(ra, 64, rc)
		return true
	}
	if xo := (w >> 1) & 0x1ff; xoForms[xo] {
		return j.xoForm(w, xo)
	}
	switch xo := (w >> 1) & 0x3ff; xo {
	case 0, 32: // cmp, cmpl
		bf, l := rt>>2, rt&1 != 0
		if l {
			a.load64(rAX, gpr(ra))
			a.aluRM(aluCmp, rAX, gpr(rb))
		} else {
			a.load32(rAX, gpr(ra))
			a.opRM(false, []byte{0x3b}, rAX, gpr(rb), false) // cmp eax, [rb]
		}
		j.crFromFlags(bf, xo == 0)
	case 19: // mfcr, mfocrf
		a.load32(rAX, memCR)
		if w&(1<<20) != 0 {
			fxm := (w >> 12) & 0xff
			var msk uint32
			for i := 0; i < 8; i++ {
				if fxm&(0x80>>i) != 0 {
					msk |= 0xf << (28 - 4*i)
				}
			}
			a.aluRI32(aluAnd, rAX, int32(msk))
		}
		a.store64(gpr(rt), rAX)
	case 499: // AS settag
		if !j.m.as || w != 0x7c0103e6 {
			return false
		}
		a.aluMI(aluOr, memXER, int32(XERTAG))
	case 64: // AS cmpla
		if !j.m.as || rt&3 != 1 || rc {
			return false
		}
		a.load64(rAX, gpr(ra))
		a.load64(rCX, gpr(rb))
		incomparable, store := a.newLabel(), a.newLabel()
		a.movRR(rDX, rAX)
		a.aluRR(aluXor, rDX, rCX)
		a.shiftRI(shShr, rDX, 48)
		a.jcc(ccNE, incomparable) // different high halfwords
		a.movRR(r8, rAX)
		a.shiftRI(shShr, r8, 48)
		compare := a.newLabel()
		a.jcc(ccE, compare) // both in segment 0
		a.movRR(rDX, rAX)
		a.aluRR(aluXor, rDX, rCX)
		a.shiftRI(shShr, rDX, 24)
		a.jcc(ccNE, incomparable)
		a.bind(compare)
		a.aluRR(aluCmp, rAX, rCX)
		a.setcc(ccB, rAX)
		a.setcc(ccA, rCX)
		a.setcc(ccE, rDX)
		a.movzx8(rAX, rAX)
		a.movzx8(rCX, rCX)
		a.movzx8(rDX, rDX)
		a.shiftRI32(shShl, rAX, 3)
		a.shiftRI32(shShl, rCX, 2)
		a.aluRR32(aluAdd, rDX, rDX)
		a.aluRR32(aluOr, rAX, rCX)
		a.aluRR32(aluOr, rAX, rDX)
		a.jmp(store)
		a.bind(incomparable)
		a.movImm(rAX, 1)
		a.bind(store)
		// CR field and FXCC, independent of XER[SO].
		shift := uint8(28 - 4*(rt>>2))
		a.load64(rCX, memXER)
		a.aluRI(aluAnd, rCX, ^int32(15<<24))
		a.movRR32(rDX, rAX)
		a.shiftRI(shShl, rDX, 24)
		a.aluRR(aluOr, rCX, rDX)
		a.store64(memXER, rCX)
		a.load32(rCX, memCR)
		a.aluRI32(aluAnd, rCX, ^int32(0xf<<shift))
		a.shiftRI32(shShl, rAX, shift)
		a.aluRR32(aluOr, rCX, rAX)
		a.store32(memCR, rCX)
	case 544: // AS mcrxrt
		if !j.m.as || j.mode&MSRTA == 0 || rt&3 != 0 || ra != 0 || rb != 0 || rc {
			return false
		}
		shift := uint8(28 - 4*(rt>>2))
		a.load64(rAX, memXER)
		a.shiftRI(shShr, rAX, 20)
		a.aluRI32(aluAnd, rAX, 7)
		a.load32(rCX, memCR)
		a.aluRI32(aluAnd, rCX, ^int32(0xf<<shift))
		a.shiftRI32(shShl, rAX, shift)
		a.aluRR32(aluOr, rCX, rAX)
		a.store32(memCR, rCX)
	case 83: // mfmsr
		if j.mode&MSRPR != 0 {
			return false
		}
		a.load64(rAX, at(regCPU, offMSR))
		a.store64(gpr(rt), rAX)
	case 4, 68: // tw, td
		ta := j.m.as && j.mode&MSRTA != 0
		if ta && xo == 4 && (rt == 28 || rt == 30) {
			return false // illegal under AS tags active
		}
		a.load64(rAX, gpr(ra))
		a.load64(rCX, gpr(rb))
		if xo == 4 {
			a.movsx32(rAX, rAX)
			a.movsx32(rCX, rCX)
		}
		if ta && xo == 68 && (rt == 28 || rt == 30 || rt == 29 && j.m.cfg.PVR>>16 == 0x004e) {
			j.trapRegion(rt)
		} else {
			j.trap(rt)
		}
	case 824, 792, 794: // srawi, sraw, srad
		if xo == 824 {
			a.movImm(rCX, uint64(rb))
		} else {
			a.load64(rCX, gpr(rb))
			mask, top := int32(63), int32(32)
			if xo == 794 {
				mask, top = 127, 64
			}
			a.aluRI32(aluAnd, rCX, mask)
			// n = min(n, width)
			a.movImm(rDX, uint64(top))
			a.aluRI32(aluCmp, rCX, top)
			a.opRR(false, []byte{0x0f, 0x47}, rCX, rDX, false) // cmova ecx, edx
		}
		a.load64(rAX, gpr(rt))
		width := uint(32)
		if xo == 794 {
			width = 64
		} else {
			a.movsx32(rAX, rAX)
		}
		j.shiftAlgebraic(ra, width, rc)
	case 506, 378: // popcntd, popcntw
		if !jitPopcnt {
			return false
		}
		a.load64(rCX, gpr(rt))
		if xo == 506 {
			a.byte1(0xf3)
			a.opRR(true, []byte{0x0f, 0xb8}, rAX, rCX, false)
		} else {
			a.byte1(0xf3)
			a.opRR(false, []byte{0x0f, 0xb8}, rAX, rCX, false) // low word
			a.shiftRI(shShr, rCX, 32)
			a.byte1(0xf3)
			a.opRR(false, []byte{0x0f, 0xb8}, rDX, rCX, false)
			a.shiftRI(shShl, rDX, 32)
			a.aluRR(aluOr, rAX, rDX)
		}
		a.store64(gpr(ra), rAX)
	case 144: // mtcrf
		fxm := (w >> 12) & 0xff
		var msk uint32
		for i := 0; i < 8; i++ {
			if fxm&(0x80>>i) != 0 {
				msk |= 0xf << (28 - 4*i)
			}
		}
		a.load32(rAX, gpr(rt))
		a.aluRI32(aluAnd, rAX, int32(msk))
		a.load32(rCX, memCR)
		a.aluRI32(aluAnd, rCX, int32(^msk))
		a.aluRR32(aluOr, rAX, rCX)
		a.store32(memCR, rAX)
	case 339, 371: // mfspr, mftb
		if !j.readSPR(rb<<5 | ra) {
			return false
		}
		a.store64(gpr(rt), rAX)
	case 467: // mtspr
		switch rb<<5 | ra {
		case 1:
			a.load64(rAX, gpr(rt))
			if j.m.as {
				a.aluImm64(aluAnd, rAX, 0x0000ffffffff007f, rDX)
			} else {
				a.aluImm64(aluAnd, rAX, XERSO|XEROV|XERCA|XEROV32|XERCA32|0x7f, rDX)
			}
			a.store64(memXER, rAX)
		case 8:
			a.load64(rAX, gpr(rt))
			a.store64(memLR, rAX)
		case 9:
			a.load64(rAX, gpr(rt))
			a.store64(memCTR, rAX)
		case 152: // CTRL (run latch): plain state
			if j.mode&MSRPR != 0 {
				return false
			}
			a.load64(rAX, gpr(rt))
			a.store64(at(regCPU, offCtrl), rAX)
		case 272, 273, 274, 275, 26, 27, 19:
			if j.mode&MSRPR != 0 {
				return false
			}
			dst := at(regCPU, offSRR0)
			switch rb<<5 | ra {
			case 27:
				dst = at(regCPU, offSRR1)
			case 19:
				dst = at(regCPU, offDAR)
			case 26:
			default:
				dst = at(regCPU, offSPRG+8*int32(rb<<5|ra-272))
			}
			a.load64(rAX, gpr(rt))
			a.store64(dst, rAX)
		default:
			return false
		}
	case 21, 53, 23, 55, 87, 119, 279, 311, 343, 375, 341, 373: // indexed loads
		n := int(accessSize31[xo])
		j.eaX(ra, rb)
		j.access(n, false)
		j.load(n, xo == 343 || xo == 375 || xo == 341 || xo == 373)
		a.store64(gpr(rt), rCX)
		if xo == 53 || xo == 55 || xo == 119 || xo == 311 || xo == 375 || xo == 373 {
			a.store64(gpr(ra), rSI)
		}
	case 149, 181, 151, 183, 215, 247, 407, 439: // indexed stores
		n := int(accessSize31[xo])
		j.eaX(ra, rb)
		j.access(n, true)
		a.load64(rCX, gpr(rt))
		j.store(n)
		if xo == 181 || xo == 183 || xo == 247 || xo == 439 {
			a.store64(gpr(ra), rSI)
		}
	case 24, 27, 536, 539: // slw sld srw srd
		a.load64(rCX, gpr(rb))
		a.load64(rAX, gpr(rt))
		zero := a.newLabel()
		done := a.newLabel()
		bit := int32(32)
		if xo == 27 || xo == 539 {
			bit = 64
		}
		a.opRR(true, []byte{0xf7}, 0, rCX, false) // test rcx, imm32
		a.imm32(bit)
		a.jcc(ccNE, zero)
		switch xo {
		case 24:
			a.opRR(false, []byte{0xd3}, shShl, rAX, false) // shl eax, cl (count & 31)
		case 27:
			a.shiftRCL(shShl, rAX)
		case 536:
			a.opRR(false, []byte{0xd3}, shShr, rAX, false)
		case 539:
			a.shiftRCL(shShr, rAX)
		}
		a.jmp(done)
		a.bind(zero)
		a.movImm(rAX, 0)
		a.bind(done)
		j.result(ra, rc)
	case 26: // cntlzw
		a.load32(rCX, gpr(rt))
		a.movImm(rAX, 32)
		zero := a.newLabel()
		a.testRR32(rCX, rCX)
		a.jcc(ccE, zero)
		a.bsr32(rAX, rCX)
		a.aluRI32(aluXor, rAX, 31)
		a.bind(zero)
		j.result(ra, rc)
	case 58: // cntlzd
		a.load64(rCX, gpr(rt))
		a.movImm(rAX, 64)
		zero := a.newLabel()
		a.testRR(rCX, rCX)
		a.jcc(ccE, zero)
		a.bsr(rAX, rCX)
		a.aluRI32(aluXor, rAX, 63)
		a.bind(zero)
		j.result(ra, rc)
	case 28, 60, 124, 284, 316, 412, 444, 476: // and andc nor eqv xor orc or nand
		a.load64(rAX, gpr(rt))
		if rt == rb && xo == 444 {
			// mr
		} else {
			a.load64(rCX, gpr(rb))
			switch xo {
			case 28:
				a.aluRR(aluAnd, rAX, rCX)
			case 60:
				a.notR(rCX)
				a.aluRR(aluAnd, rAX, rCX)
			case 124:
				a.aluRR(aluOr, rAX, rCX)
				a.notR(rAX)
			case 284:
				a.aluRR(aluXor, rAX, rCX)
				a.notR(rAX)
			case 316:
				a.aluRR(aluXor, rAX, rCX)
			case 412:
				a.notR(rCX)
				a.aluRR(aluOr, rAX, rCX)
			case 444:
				a.aluRR(aluOr, rAX, rCX)
			case 476:
				a.aluRR(aluAnd, rAX, rCX)
				a.notR(rAX)
			}
		}
		j.result(ra, rc)
	case 922, 954, 986: // extsh extsb extsw
		a.load64(rCX, gpr(rt))
		switch xo {
		case 922:
			a.movsx16(rAX, rCX)
		case 954:
			a.movsx8(rAX, rCX)
		default:
			a.movsx32(rAX, rCX)
		}
		j.result(ra, rc)
	case 20, 84: // lwarx, ldarx
		n := int(accessSize31[xo])
		j.eaX(ra, rb)
		j.access(n, false)
		j.load(n, false)
		a.store64(gpr(rt), rCX)
		a.opRM(false, []byte{0xc6}, 0, at(regCPU, offResValid), false) // mov byte, 1
		a.byte1(1)
		a.store64(at(regCPU, offResAddr), rAX)
		a.storeImm64(at(regCPU, offResSize), uint64(n), rDX)
		a.storeImm64(at(regCtx, ctxReserved), 1, rDX)
	case 150, 214: // stwcx., stdcx.
		if !rc {
			return false
		}
		n := int(accessSize31[xo])
		j.eaX(ra, rb)
		j.access(n, true)
		fail := a.newLabel()
		a.movImm(r11, 0)
		a.cmpMI8(at(regCPU, offResValid), 0)
		a.jcc(ccE, fail)
		a.movRR(rDX, rAX)
		a.aluRM(aluXor, rDX, at(regCPU, offResAddr))
		a.shiftRI(shShr, rDX, 7) // same 128-byte reservation granule
		a.jcc(ccNE, fail)
		a.load64(rCX, gpr(rt))
		j.store(n)
		a.movImm(r11, 2)
		a.bind(fail)
		a.opRM(false, []byte{0xc6}, 0, at(regCPU, offResValid), false)
		a.byte1(0)
		a.movRR32(rAX, r11)
		j.crField(0)
	case 565: // AS lsdx with XER length 0..8: one left-justified, zero-filled register
		if !j.m.as {
			return false
		}
		j.eaX(ra, rb)
		j.access(8, false) // longer strings and page ends are interpreted
		long := j.sideExit()
		done := a.newLabel()
		a.load64(rCX, memXER)
		a.aluRI32(aluAnd, rCX, 0x7f)
		a.jcc(ccE, done)
		a.aluRI32(aluCmp, rCX, 8)
		a.jcc(ccA, long)
		a.load64(r8, atIndex(regMem, rAX, 1, 0))
		a.bswap64(r8)
		a.shiftRI32(shShl, rCX, 3)
		a.movImm(r9, 64)
		a.aluRR(aluSub, r9, rCX)
		a.movRR(rCX, r9)
		a.movImm(rDX, ^uint64(0))
		a.shiftRCL(shShl, rDX)
		a.aluRR(aluAnd, r8, rDX)
		a.store64(gpr(rt), r8)
		a.bind(done)
	case 276: // lqarx: two doublewords, then a 16-byte reservation
		if rt == 31 {
			return false
		}
		j.eaX(ra, rb)
		j.access(16, false)
		a.load64(rCX, atIndex(regMem, rAX, 1, 0))
		a.bswap64(rCX)
		a.store64(gpr(rt), rCX)
		a.load64(rCX, atIndex(regMem, rAX, 1, 8))
		a.bswap64(rCX)
		a.store64(gpr(rt+1), rCX)
		a.opRM(false, []byte{0xc6}, 0, at(regCPU, offResValid), false) // mov byte, 1
		a.byte1(1)
		a.store64(at(regCPU, offResAddr), rAX)
		a.storeImm64(at(regCPU, offResSize), 16, rDX)
		a.storeImm64(at(regCtx, ctxReserved), 1, rDX)
	case 182: // stqcx.: as stdcx., storing RS and RS+1 as two doublewords
		if !rc || rt == 31 {
			return false
		}
		j.eaX(ra, rb)
		j.access(16, true)
		fail := a.newLabel()
		a.movImm(r11, 0)
		a.cmpMI8(at(regCPU, offResValid), 0)
		a.jcc(ccE, fail)
		a.movRR(rDX, rAX)
		a.aluRM(aluXor, rDX, at(regCPU, offResAddr))
		a.shiftRI(shShr, rDX, 7)
		a.jcc(ccNE, fail)
		a.load64(rCX, gpr(rt))
		j.store(8)
		a.aluRI(aluAdd, rAX, 8)
		a.load64(rCX, gpr(rt+1))
		j.store(8)
		a.movImm(r11, 2)
		a.bind(fail)
		a.opRM(false, []byte{0xc6}, 0, at(regCPU, offResValid), false)
		a.byte1(0)
		a.movRR32(rAX, r11)
		j.crField(0)
	case 1014: // dcbz
		j.loadRA0(rSI, ra)
		a.aluRM(aluAdd, rSI, gpr(rb))
		a.aluRI(aluAnd, rSI, ^int32(127))
		j.access(128, true)
		a.movImm(rCX, 0)
		for off := int32(0); off < 128; off += 8 {
			a.store64(atIndex(regMem, rAX, 1, off), rCX)
		}
		if j.m.tags != nil {
			// The block's eight quadword tags are one aligned tag byte.
			a.load64(r9, at(regCtx, ctxTags))
			a.shiftRI(shShr, rAX, 7)
			a.opRM(false, []byte{0xc6}, 0, atIndex(r9, rAX, 1, 0), false)
			a.byte1(0)
		}
	case 86, 54, 278, 246, 982, 598, 854: // dcbf dcbst dcbt dcbtst icbi sync eieio
	default:
		return false
	}
	return true
}

// xoForm compiles the XO-form arithmetic that sets no carry and cannot
// overflow into an architected interrupt.
func (j *jitCompiler) xoForm(w, xo uint32) bool {
	a := &j.a
	rt, ra, rb := (w>>21)&31, (w>>16)&31, (w>>11)&31
	oe, rc := w&(1<<10) != 0, w&1 != 0
	if oe && xo != 489 && xo != 457 && xo != 491 && xo != 459 {
		return false
	}
	asCarries := j.m.as && j.mode&MSRTA != 0
	switch xo {
	case 10, 8: // addc, subfc
		if asCarries {
			return false // AS decimal and offset carries
		}
		a.load64(rAX, gpr(ra))
		a.load64(rCX, gpr(rb))
		ci := 0
		if xo == 8 {
			a.notR(rAX)
			ci = 1
		}
		j.addCarry(ci)
	case 138, 136, 202, 200, 234, 232: // adde subfe addze subfze addme subfme
		a.load64(rAX, gpr(ra))
		if xo == 136 || xo == 200 || xo == 232 {
			a.notR(rAX)
		}
		switch xo {
		case 138, 136:
			a.load64(rCX, gpr(rb))
		case 202, 200:
			a.movImm(rCX, 0)
		default:
			a.movImm(rCX, ^uint64(0))
		}
		j.addCarry(-1)
	case 266: // add
		a.load64(rAX, gpr(ra))
		a.aluRM(aluAdd, rAX, gpr(rb))
	case 40: // subf
		a.load64(rAX, gpr(rb))
		a.aluRM(aluSub, rAX, gpr(ra))
	case 104: // neg
		a.load64(rAX, gpr(ra))
		a.negR(rAX)
	case 233: // mulld
		a.load64(rAX, gpr(ra))
		a.opRM(true, []byte{0x0f, 0xaf}, rAX, gpr(rb), false)
	case 235: // mullw
		a.load64(rCX, gpr(ra))
		a.movsx32(rAX, rCX)
		a.load64(rCX, gpr(rb))
		a.movsx32(rCX, rCX)
		a.imulRR(rAX, rCX)
	case 73, 9: // mulhd, mulhdu
		a.load64(rAX, gpr(ra))
		a.load64(rCX, gpr(rb))
		if xo == 73 {
			a.imulR(rCX)
		} else {
			a.mulR(rCX)
		}
		a.movRR(rAX, rDX)
	case 75: // mulhw
		a.load64(rCX, gpr(ra))
		a.movsx32(rAX, rCX)
		a.load64(rCX, gpr(rb))
		a.movsx32(rCX, rCX)
		a.imulRR(rAX, rCX)
		a.shiftRI(shShr, rAX, 32)
		a.movRR32(rAX, rAX)
	case 11: // mulhwu
		a.load32(rAX, gpr(ra))
		a.load32(rCX, gpr(rb))
		a.imulRR(rAX, rCX)
		a.shiftRI(shShr, rAX, 32)
	case 489, 457, 491, 459: // divd divdu divw divwu
		exit := j.sideExit()
		wide := xo == 489 || xo == 457
		signed := xo == 489 || xo == 491
		if wide {
			a.load64(rCX, gpr(rb))
			a.load64(rAX, gpr(ra))
			a.testRR(rCX, rCX)
		} else {
			a.load32(rCX, gpr(rb))
			a.load32(rAX, gpr(ra))
			a.testRR32(rCX, rCX)
		}
		a.jcc(ccE, exit) // zero divisor: interpreter result and OV
		if signed {
			// The one overflowing quotient also goes to the interpreter.
			minus := a.newLabel()
			if wide {
				a.aluRI(aluCmp, rCX, -1)
			} else {
				a.aluRI32(aluCmp, rCX, -1)
			}
			a.jcc(ccNE, minus)
			if wide {
				a.movImm(rDX, 1<<63)
				a.aluRR(aluCmp, rAX, rDX)
			} else {
				a.aluRI32(aluCmp, rAX, -1<<31)
			}
			a.jcc(ccE, exit)
			a.bind(minus)
			if wide {
				a.byte1(0x48, 0x99) // cqo
				a.opRR(true, []byte{0xf7}, 7, rCX, false)
			} else {
				a.byte1(0x99) // cdq
				a.opRR(false, []byte{0xf7}, 7, rCX, false)
				a.movRR32(rAX, rAX)
			}
		} else {
			a.movImm(rDX, 0)
			a.opRR(wide, []byte{0xf7}, 6, rCX, false)
		}
		if oe {
			a.aluMI(aluAnd, memXER, ^int32(XEROV|XEROV32))
		}
	default:
		return false
	}
	j.result(rt, rc)
	return true
}
