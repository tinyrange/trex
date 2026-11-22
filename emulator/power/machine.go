package power

import (
	"fmt"
	"maps"
	"math"
	"slices"
)

// Config describes a partition.
type Config struct {
	Memory int // bytes of real memory
	CPUs   int
	// MIPS is the nominal instruction rate; the 512 MHz time base advances
	// by 512/MIPS ticks per instruction.
	MIPS int
	// PVR is the processor version register value.
	PVR uint32
	// Extensions enables processor-specific instruction sets: "as" adds the
	// PowerPC AS load/store multiple doubleword and string doubleword forms.
	Extensions []string
}

// StopReason says why Run returned.
type StopReason struct {
	Kind   string // budget, breakpoint, interrupt, hcall, illegal, watch, machine-check, stopped
	Detail string
	CPU    int
}

func (r StopReason) String() string {
	if r.Detail == "" {
		return r.Kind
	}
	return r.Kind + ": " + r.Detail
}

// HypercallHandler services sc 1 from the partition. The handler reads its
// arguments from and writes results to the CPU's registers; execution resumes
// after the sc. Calling CPU.Stop ends Run after the call.
type HypercallHandler func(c *CPU) error

// ExtensionHandler is offered every instruction word the core does not
// implement. It returns true when it performed the instruction (advancing to
// the next word unless it changed PC); false raises an illegal-instruction
// program interrupt.
type ExtensionHandler func(c *CPU, word uint32) (bool, error)

// Event is a structured observation retained by the machine.
type Event struct {
	Kind         string
	CPU          int
	PC           uint64
	Detail       string
	Instructions uint64
}

// Machine is a partition: real memory, CPUs and the hypervisor-owned page table.
type Machine struct {
	// Mem is real memory. Once instructions have run, other writers must
	// use WriteReal (or the CPU store methods) so pointer tags,
	// reservations and compiled code observe the change.
	Mem  []byte
	CPUs []*CPU
	HPT  map[PageKey]PTE
	// HTAB, when set, is the slot-addressed table behind HPT.
	HTAB *HashedPageTable
	// IdentitySegments resolves segment misses in the hypervisor with
	// 256MB segments whose VSID equals the ESID instead of raising segment
	// interrupts (a partition whose virtual addresses are its effective
	// addresses).
	IdentitySegments bool
	guestSegments    []SegmentRange
	cfg              Config

	tces   map[uint64]*tceTable
	crqs   map[uint64]*commandResponseQueue
	hptGen uint64
	// slotVer versions each hashed page table slot. Replacing or removing
	// a valid entry advances its slot's version instead of hptGen, so only
	// translations through that slot are discarded.
	slotVer          []uint32
	hashProcessTable hashProcessTable
	windows          []TranslationWindow
	instructions     uint64
	tbOffset         uint64

	// Hypercalls dispatches sc 1 by the token in r3 before falling back to
	// Hypercall, so native implementations can replace scripted ones per call.
	Hypercalls map[uint64]HypercallHandler
	Hypercall  HypercallHandler

	nativeHypercalls map[uint64]*NativeHypercall
	hypercallCounts  map[uint64]uint64
	Extension        ExtensionHandler

	// StopInterrupts stops Run after an interrupt with one of these vectors
	// is delivered; StopAllInterrupts stops after any interrupt.
	StopInterrupts    map[uint64]bool
	StopAllInterrupts bool
	Breakpoints       map[uint64]bool
	watchLo, watchHi  uint64

	Events     []Event
	EventLimit int
	Interrupts map[uint64]uint64

	// reservations is set while any CPU may hold a load reservation.
	reservations bool

	as bool
	// tags holds the PowerPC AS tag bit of each 16-byte quadword of real
	// memory (extension "as"): set by a tag-carrying stq, cleared by any
	// other store.
	tags []uint64

	jit *jitState

	history    []HistoryEntry
	historyPos int
	err        error
}

// HistoryEntry is one executed instruction.
type HistoryEntry struct {
	PC   uint64
	Word uint32
	CPU  int
}

// NewMachine creates a partition with all CPUs at PC 0 in real mode.
func NewMachine(cfg Config) *Machine {
	if cfg.CPUs < 1 {
		cfg.CPUs = 1
	}
	if cfg.MIPS < 1 {
		cfg.MIPS = 100
	}
	if cfg.PVR == 0 {
		cfg.PVR = 0x004e1202 // POWER9 DD2.2
	}
	m := &Machine{Mem: make([]byte, cfg.Memory), HPT: map[PageKey]PTE{}, cfg: cfg,
		StopInterrupts: map[uint64]bool{}, Hypercalls: map[uint64]HypercallHandler{}, Breakpoints: map[uint64]bool{}, EventLimit: 10000, Interrupts: map[uint64]uint64{}, StopAllInterrupts: true}
	for _, e := range cfg.Extensions {
		if e == "as" {
			m.as = true
			m.tags = make([]uint64, (cfg.Memory/16+63)/64)
		}
	}
	for i := 0; i < cfg.CPUs; i++ {
		m.CPUs = append(m.CPUs, &CPU{m: m, Index: i, MSR: MSRSF | MSRME, SPR: map[int]uint64{}, decAt: math.MaxInt64})
	}
	m.jitInit()
	return m
}

// Config returns the machine's configuration.
func (m *Machine) Config() Config { return m.cfg }

// TB returns the time base.
func (m *Machine) TB() uint64 { return m.tbOffset + m.instructions*512/uint64(m.cfg.MIPS) }

// Instructions returns the total executed instruction count.
func (m *Machine) Instructions() uint64 { return m.instructions }

// eventRoom reports whether Event would record, so callers can skip
// formatting a detail that would be dropped.
func (m *Machine) eventRoom() bool { return len(m.Events) < m.EventLimit }

// Event records a structured observation.
func (m *Machine) Event(kind string, c *CPU, detail string) {
	if len(m.Events) >= m.EventLimit {
		return
	}
	e := Event{Kind: kind, Detail: detail, Instructions: m.instructions}
	if c != nil {
		e.CPU, e.PC = c.Index, c.PC
	}
	m.Events = append(m.Events, e)
}

func (m *Machine) noteInterrupt(c *CPU, vector uint64) {
	m.Interrupts[vector]++
	if m.StopAllInterrupts || m.StopInterrupts[vector] {
		c.Stop("interrupt", fmt.Sprintf("vector %x srr0 %016x srr1 %016x dar %016x dsisr %08x", vector, c.SRR0, c.SRR1, c.DAR, c.DSISR))
	}
}

// Watch stops Run after a store into real addresses [lo, hi).
func (m *Machine) Watch(lo, hi uint64) { m.watchLo, m.watchHi = lo, hi }

func (m *Machine) stored(c *CPU, r uint64, n int) {
	if n <= 0 {
		return
	}
	if m.tags != nil {
		for q := r >> 4; q <= (r+uint64(n)-1)>>4; q++ {
			m.tags[q>>6] &^= 1 << (q & 63)
		}
	}
	if r < m.watchHi && r+uint64(n) > m.watchLo && c != nil {
		c.Stop("watch", fmt.Sprintf("store to real %x (%d bytes) at pc %016x", r, n, c.PC))
	}
	if m.reservations {
		m.clearReservations(c, r, n)
	}
	if j := m.jit; j != nil {
		if p := r >> 12; p < uint64(len(j.codePages)) && j.codePages[p] != 0 || (r+uint64(n)-1)>>12 != p {
			m.jitInvalidate(r, n)
		}
	}
}

// clearReservations cancels other CPUs' reservations in the stored granules.
// reservations is a hint that some CPU may hold one.
func (m *Machine) clearReservations(c *CPU, r uint64, n int) {
	held := false
	for _, o := range m.CPUs {
		if !o.resValid {
			continue
		}
		base := o.resAddr &^ (reservationGranule - 1)
		if r < base+reservationGranule && r+uint64(n) > base && o != c {
			o.resValid = false
			continue
		}
		held = true
	}
	m.reservations = held
}

// WriteReal writes bytes supplied by a backend, such as device DMA or a
// firmware buffer operation. Like ordinary stores, this clears pointer tags
// and invalidates every CPU reservation in the affected granules.
func (m *Machine) WriteReal(address uint64, data []byte) error {
	size := uint64(len(m.Mem))
	if address > size || uint64(len(data)) > size-address {
		return fmt.Errorf("power: real write %x+%x outside memory", address, len(data))
	}
	copy(m.Mem[address:], data)
	m.stored(nil, address, len(data))
	return nil
}

// EnableHistory retains the last n executed instructions (0 disables).
func (m *Machine) EnableHistory(n int) {
	m.history, m.historyPos = nil, 0
	if n > 0 {
		m.history = make([]HistoryEntry, 0, n)
	}
}

// History returns retained instructions, oldest first.
func (m *Machine) History() []HistoryEntry {
	if len(m.history) < cap(m.history) {
		return slices.Clone(m.history)
	}
	return append(slices.Clone(m.history[m.historyPos:]), m.history[:m.historyPos]...)
}

func (m *Machine) record(c *CPU, word uint32) {
	e := HistoryEntry{PC: c.PC, Word: word, CPU: c.Index}
	if len(m.history) < cap(m.history) {
		m.history = append(m.history, e)
		return
	}
	m.history[m.historyPos] = e
	m.historyPos = (m.historyPos + 1) % len(m.history)
}

// Run executes up to budget instructions across all CPUs.
func (m *Machine) Run(budget uint64) (StopReason, error) {
	var done uint64
	first := true
	for done < budget {
		before := done
		for _, c := range m.CPUs {
			if c.Parked {
				continue
			}
			n := min(budget-done, 4096)
			ran := c.run(n, first)
			done += ran
			if m.err != nil {
				err := m.err
				m.err = nil
				return StopReason{Kind: "error", Detail: err.Error(), CPU: c.Index}, err
			}
			if c.stop != nil {
				r := *c.stop
				c.stop = nil
				return r, nil
			}
		}
		if done == before {
			// With no runnable CPU, advance the virtual clock directly to
			// the earliest enabled timer. No guest instructions are invented.
			next := int64(math.MaxInt64)
			for _, c := range m.CPUs {
				if !c.Parked && c.Waiting && c.MSR&MSREE != 0 {
					next = min(next, c.decAt)
				}
			}
			if next == math.MaxInt64 {
				return StopReason{Kind: "idle", Detail: "all CPUs parked or waiting without an enabled timer"}, nil
			}
			if next > int64(m.TB()) {
				m.tbOffset += uint64(next - int64(m.TB()))
			}
		}
		first = false
	}
	return StopReason{Kind: "budget"}, nil
}

func (c *CPU) run(n uint64, first bool) uint64 {
	m := c.m
	breaks := len(m.Breakpoints) != 0
	if m.history != nil || breaks && m.jit == nil {
		return c.runChecked(n, first)
	}
	if m.jit != nil {
		m.jitCheckBreakpoints()
	}
	var i uint64
	for i < n {
		if c.Parked {
			return i
		}
		if breaks {
			// As runChecked: a waiting CPU is not at a boundary, and the
			// breakpoint precedes interrupt delivery.
			if c.Waiting && !(c.MSR&MSREE != 0 && (c.external || int64(m.TB()) >= c.decAt)) {
				return i
			}
			if m.Breakpoints[c.PC] && !(first && i == 0) {
				c.Stop("breakpoint", fmt.Sprintf("pc %016x", c.PC))
				return i
			}
		}
		if !c.deliverPending() {
			return i
		}
		if c.stop != nil {
			return i
		}
		// Between instructions that cannot change interrupt state, the only
		// event is the decrementer deadline, so run up to it unchecked.
		limit := n - i
		if c.MSR&MSREE != 0 {
			limit = min(limit, m.instructionsUntil(c.decAt))
		}
		c.sync = false
		if m.jit != nil {
			i += c.runJIT(limit, breaks)
		} else {
			var j uint64
			for j < limit {
				c.step()
				j++
				if c.sync {
					break
				}
			}
			i += j
		}
		if c.yielded {
			c.yielded = false
			return i
		}
		if c.stop != nil {
			return i
		}
	}
	return i
}

// deliverPending takes an enabled external or decrementer interrupt at an
// instruction boundary. It reports false while the CPU waits.
func (c *CPU) deliverPending() bool {
	m := c.m
	if c.MSR&MSREE == 0 {
		return !c.Waiting
	}
	if c.external {
		c.fault = false
		c.Interrupt(VecExternal, c.PC, 0)
	} else if int64(m.TB()) >= c.decAt {
		c.fault = false
		c.Interrupt(VecDecrementer, c.PC, 0)
	}
	return !c.Waiting
}

// instructionsUntil returns how many instructions can retire before the time
// base reaches deadline (at least one).
func (m *Machine) instructionsUntil(deadline int64) uint64 {
	target := deadline - int64(m.tbOffset)
	mips := uint64(m.cfg.MIPS)
	if target <= 0 {
		return 1
	}
	if uint64(target) > math.MaxUint64/mips {
		return math.MaxUint64
	}
	// TB >= deadline exactly when instructions*512 >= target*MIPS.
	need := (uint64(target)*mips + 511) / 512
	if need <= m.instructions {
		return 1
	}
	return need - m.instructions
}

// runChecked is run with per-instruction breakpoint and history checks.
func (c *CPU) runChecked(n uint64, first bool) uint64 {
	m := c.m
	var i uint64
	for ; i < n; i++ {
		if c.Parked {
			return i
		}
		if c.Waiting && !(c.MSR&MSREE != 0 && (c.external || int64(m.TB()) >= c.decAt)) {
			return i
		}
		if m.Breakpoints[c.PC] && !(first && i == 0) {
			c.Stop("breakpoint", fmt.Sprintf("pc %016x", c.PC))
			return i
		}
		if c.MSR&MSREE != 0 && c.external {
			c.fault = false
			c.Interrupt(VecExternal, c.PC, 0)
			if c.stop != nil {
				return i
			}
		} else if c.MSR&MSREE != 0 && int64(m.TB()) >= c.decAt {
			c.fault = false
			c.Interrupt(VecDecrementer, c.PC, 0)
			if c.stop != nil {
				return i
			}
		}
		c.step()
		if c.yielded {
			c.yielded = false
			return i + 1
		}
		if c.stop != nil {
			return i + 1
		}
	}
	return i
}

// Step executes one instruction on the CPU and returns any stop reason.
func (c *CPU) Step() *StopReason {
	c.step()
	r := c.stop
	c.stop = nil
	return r
}

func (c *CPU) step() {
	m := c.m
	c.fault = false
	word, ok := c.fetch()
	m.instructions++
	c.Instructions++
	if !ok {
		c.lastWord = 0
		return
	}
	if m.history != nil {
		m.record(c, word)
	}
	c.lastWord = word
	c.nextPC = c.mask(c.PC + 4)
	c.exec(word)
	if !c.fault {
		c.PC = c.nextPC
	}
}

// illegal offers an unimplemented word to the extension handler.
func (c *CPU) illegal(word uint32) {
	if h := c.m.Extension; h != nil {
		c.sync = true
		pc := c.PC
		handled, err := h(c, word)
		if err != nil {
			c.m.err = err
			c.fault = true
			return
		}
		// A callback can take a storage interrupt through Load or Store.
		// Interrupt has already saved the instruction and selected its vector.
		if c.fault {
			return
		}
		if handled {
			if c.PC != pc {
				c.nextPC = c.PC
				c.PC = pc
			}
			return
		}
	}
	c.m.Event("illegal", c, fmt.Sprintf("%08x", word))
	c.program(ProgIllegal)
}

func (c *CPU) hypercall() {
	c.sync = true
	m := c.m
	if m.hypercallCounts == nil {
		m.hypercallCounts = map[uint64]uint64{}
	}
	m.hypercallCounts[c.GPR[3]]++
	if n := m.nativeHypercalls[c.GPR[3]]; n != nil && n.apply(c) {
		return
	}
	h := c.m.Hypercalls[c.GPR[3]]
	if h == nil {
		h = c.m.Hypercall
	}
	if h == nil {
		c.Stop("hcall", fmt.Sprintf("r3 %016x at pc %016x", c.GPR[3], c.PC))
		c.fault = true // leave PC at the sc
		return
	}
	pc := c.PC
	if err := h(c); err != nil {
		c.m.err = err
		c.fault = true
		return
	}
	if !c.fault && c.PC != pc {
		c.nextPC = c.PC
		c.PC = pc
	}
}

// Checkpoint is an in-memory copy of the machine's state.
type Checkpoint struct {
	pvr              uint32
	mips             int
	as               bool
	identitySegments bool
	guestSegments    []SegmentRange
	mem              checkpointMemory
	tags             []uint64
	windows          []TranslationWindow
	cpus             []CPU
	hpt              map[PageKey]PTE
	htab             *HashedPageTable
	tces             map[uint64]*tceTable
	crqs             map[uint64]*commandResponseQueue
	instr            uint64
	tbOffset         uint64
	hashProcessTable hashProcessTable
}

// Checkpoint captures memory, CPU state and the page table. Handlers,
// breakpoints and retained events are configuration and are not captured.
func (m *Machine) Checkpoint() *Checkpoint {
	cp := &Checkpoint{mem: captureMemory(m.Mem), hpt: maps.Clone(m.HPT), htab: m.HTAB.clone(), instr: m.instructions, tbOffset: m.tbOffset}
	cp.pvr, cp.mips, cp.as = m.cfg.PVR, m.cfg.MIPS, m.as
	cp.identitySegments = m.IdentitySegments
	cp.guestSegments = slices.Clone(m.guestSegments)
	cp.tces = cloneTCEs(m.tces)
	cp.crqs = cloneCRQs(m.crqs)
	cp.tags = slices.Clone(m.tags)
	cp.windows = slices.Clone(m.windows)
	cp.hashProcessTable = m.hashProcessTable
	for _, c := range m.CPUs {
		s := *c
		s.m = nil
		s.jitCache, s.jitInd = nil, nil
		s.SPR = maps.Clone(c.SPR)
		cp.cpus = append(cp.cpus, s)
	}
	return cp
}

// Restore returns the machine to a checkpoint taken from it.
func (m *Machine) Restore(cp *Checkpoint) error {
	if cp == nil || cp.mem.size != len(m.Mem) || len(cp.cpus) != len(m.CPUs) ||
		cp.pvr != m.cfg.PVR || cp.mips != m.cfg.MIPS || cp.as != m.as {
		return fmt.Errorf("power: checkpoint from a differently configured machine")
	}
	if err := cp.mem.restore(m.Mem); err != nil {
		return err
	}
	copy(m.tags, cp.tags)
	m.windows = slices.Clone(cp.windows)
	m.hashProcessTable = cp.hashProcessTable
	m.HPT = maps.Clone(cp.hpt)
	m.HTAB = cp.htab.clone()
	if m.HTAB != nil && len(m.slotVer) != len(m.HTAB.Entries) {
		m.slotVer = make([]uint32, len(m.HTAB.Entries))
	}
	m.IdentitySegments = cp.identitySegments
	m.guestSegments = slices.Clone(cp.guestSegments)
	m.tces = cloneTCEs(cp.tces)
	m.crqs = cloneCRQs(cp.crqs)
	m.hptGen++
	m.instructions = cp.instr
	m.tbOffset = cp.tbOffset
	m.reservations = true
	for i, c := range m.CPUs {
		s := cp.cpus[i]
		s.SPR = maps.Clone(s.SPR)
		s.m = m
		s.tlbGen = c.tlbGen + 1
		s.jitCache, s.jitInd = c.jitCache, c.jitInd
		*c = s
	}
	m.jitFlush()
	return nil
}
