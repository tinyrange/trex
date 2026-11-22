package power

import (
	"fmt"
	"sort"
)

// The block JIT translates runs of simple guest instructions into native
// code. It is exact: a block retires whole guest instructions with the
// interpreter's results, never raises an interrupt, and leaves the block
// (a side exit) before any instruction it cannot complete natively, such as
// a TLB miss, a store to a code page or an instruction it does not compile,
// which the interpreter then executes. Blocks never cross a 4 KiB page,
// so a block is keyed by the real address of its first instruction and the
// MSR bits it was compiled under. Stores to a real page holding blocks
// discard them before the stored bytes can execute.
//
// Blocks jump directly to blocks in their own page (patched in as targets
// are compiled; they die together), and through a per-CPU cache validated
// like a TLB entry for indirect and cross-page branches. Each block's
// entry reserves its length from the run's instruction allowance, so a
// chain stops exactly at budgets and timer deadlines.
//
// Native execution is available on linux/amd64; elsewhere, or after
// Machine.SetJIT(false), the interpreter runs every instruction.

// jitBlock is one compiled block.
type jitBlock struct {
	code  uintptr // native entry, 0 for an instruction the JIT leaves to the interpreter
	n     uint64  // instructions retired when the block runs to its end
	real  uint64
	mode  uint64
	alive bool
}

type jitKey struct{ real, mode uint64 }

// jitState is a machine's code cache.
type jitState struct {
	code   *jitArena
	blocks map[jitKey]*jitBlock
	pages  map[uint64][]*jitBlock // real page -> blocks
	// links holds, by real page, the unpatched direct jumps waiting for
	// each block. Jumps stay within a page, so they die with it.
	links map[uint64]map[jitKey][]uintptr
	// codePages[p] is nonzero while real page p holds blocks; native stores
	// side-exit on it.
	codePages []byte
	ctx       jitCtx
	stats     JITStats
	breakSig  uint64
	compiler  jitCompiler
	// interpreted counts the dispatcher's interpreted instructions by
	// jitOpcodeKey, with bit 17 set for side exits and bit 18 for blocks
	// longer than the remaining budget.
	interpreted [1 << 19]uint64
	exitReasons [exitReasons]uint64
	returns     [jitReturns]uint64
}

// JITStats counts code-cache activity.
type JITStats struct {
	Blocks, Compiled, Invalidated, Flushes uint64
	Native, NativeInstructions, SideExits  uint64
	// Interpreted lists the opcodes the dispatcher interpreted most often.
	Interpreted []JITOpcodeCount
	// ExitReasons counts side exits by cause (see jitExitReasonNames).
	ExitReasons map[string]uint64
	// Returns counts native runs that returned without a side exit, by
	// cause (see jitReturnNames).
	Returns map[string]uint64
}

// JITOpcodeCount is one opcode's interpreted count. SideExit reports
// instructions reached by leaving a native block (a TLB miss or other slow
// case); Budget reports a native block longer than the instructions left
// before the next interrupt check; otherwise the opcode had no native form
// at its address.
type JITOpcodeCount struct {
	Primary, Extended uint32 // Extended is the X/XL/XO/A-form field for 4, 19, 30, 31, 59 and 63
	SPR               int    // the SPR of mfspr/mtspr, else -1
	SideExit, Budget  bool
	Count             uint64
}

// jitOpcodeKey is the primary opcode and, for forms with an extended
// opcode, bits 1-10 of the word. mfspr/mtspr keys (bit 16) carry the SPR.
func jitOpcodeKey(w uint32) uint32 {
	op := w >> 26
	if xo := (w >> 1) & 0x3ff; op == 31 && (xo == 339 || xo == 467) {
		spr := (w>>16)&31 | (w>>11)&31<<5
		return 1<<16 | (xo>>7&1)<<10 | spr
	}
	switch op {
	case 4, 19, 31, 59, 63:
		return op<<10 | (w>>1)&0x3ff
	case 30:
		return op<<10 | (w>>1)&0xf
	}
	return op << 10
}

// The per-CPU block cache is direct-mapped by a multiplicative hash of the
// effective address; misses fall back to the machine's block map.
const (
	jitCacheBits = 15
	jitCacheSize = 1 << jitCacheBits
)

func jitCacheIndex(ea uint64) uint64 { return (ea >> 2) * jitIndirectHash >> (64 - jitCacheBits) }

// jitIndirect is one entry of a CPU's native branch-target cache, probed by
// blocks ending in bclr/bcctr or a branch to another page. It names only
// shared blocks on pages without breakpoints; entries for a page are
// cleared when its blocks die.
type jitIndirect struct {
	ea, gen, mode, slot uint64
	code                uintptr
	real                uint64 // real page of the block
	slotVer             uint32
}

const (
	jitIndirectBits = 12
	jitIndirectSize = 1 << jitIndirectBits
	jitIndirectHash = 0x9e3779b97f4a7c15
)

func jitIndirectIndex(ea uint64) uint64 { return (ea >> 2) * jitIndirectHash >> (64 - jitIndirectBits) }

type jitCacheEntry struct {
	ea, mode, gen uint64
	slot          uint64 // the instruction translation's HPTE slot+1
	slotVer       uint32
	brk           bool // a breakpoint is set at ea
	shared        bool // blk is the shared block (indirect branches may enter it)
	real          uint64
	blk           *jitBlock
}

func (m *Machine) jitInit() {
	if !jitAvailable || !jitLayoutOK {
		return
	}
	arena, err := newJITArena(1 << 30)
	if err != nil {
		return
	}
	j := &jitState{code: arena, blocks: map[jitKey]*jitBlock{}, pages: map[uint64][]*jitBlock{}, links: map[uint64]map[jitKey][]uintptr{},
		codePages: make([]byte, (len(m.Mem)+4095)/4096+1)}
	j.ctx.codePages = jitPointer(j.codePages)
	j.ctx.tags = jitPointer(m.tags)
	m.jit = j
}

// SetJIT enables or disables native block execution. Disabling discards
// compiled code. It reports whether native execution is enabled.
func (m *Machine) SetJIT(enabled bool) bool {
	if !enabled {
		if m.jit != nil {
			m.jit.code.release()
			m.jit = nil
		}
		return false
	}
	if m.jit == nil {
		m.jitInit()
	}
	return m.jit != nil
}

// JITStats returns code-cache counters (zero without native execution).
func (m *Machine) JITStats() JITStats {
	if m.jit == nil {
		return JITStats{}
	}
	s := m.jit.stats
	s.Blocks = uint64(len(m.jit.blocks))
	s.Returns = map[string]uint64{}
	for r, n := range m.jit.returns {
		if n != 0 {
			s.Returns[jitReturnNames[r]] = n
		}
	}
	s.ExitReasons = map[string]uint64{}
	for r, n := range m.jit.exitReasons {
		if n != 0 {
			s.ExitReasons[jitExitReasonNames[r]] = n
		}
	}
	for k, n := range m.jit.interpreted {
		if n != 0 {
			o := JITOpcodeCount{Primary: uint32(k) >> 10 & 63, Extended: uint32(k) & 0x3ff, SPR: -1, SideExit: k>>17&1 != 0, Budget: k>>18 != 0, Count: n}
			if k>>16&1 != 0 {
				o.Primary, o.Extended, o.SPR = 31, 339, k&0x3ff
				if k>>10&1 != 0 {
					o.Extended = 467
				}
			}
			s.Interpreted = append(s.Interpreted, o)
		}
	}
	sort.Slice(s.Interpreted, func(a, b int) bool { return s.Interpreted[a].Count > s.Interpreted[b].Count })
	return s
}

// jitFlush discards every block, for example after a checkpoint restore
// replaced memory.
func (m *Machine) jitFlush() {
	j := m.jit
	if j == nil {
		return
	}
	for _, list := range j.pages {
		for _, b := range list {
			b.alive = false
		}
	}
	for _, c := range m.CPUs {
		if c.jitInd != nil {
			clear(c.jitInd[:])
		}
	}
	j.blocks = map[jitKey]*jitBlock{}
	j.pages = map[uint64][]*jitBlock{}
	j.links = map[uint64]map[jitKey][]uintptr{}
	clear(j.codePages)
	j.code.reset()
	j.stats.Flushes++
}

// jitInvalidate discards blocks on the real pages written by [r, r+n).
func (m *Machine) jitInvalidate(r uint64, n int) {
	j := m.jit
	for p := r >> 12; p <= (r+uint64(n)-1)>>12 && p < uint64(len(j.codePages)); p++ {
		if j.codePages[p] == 0 {
			continue
		}
		for _, b := range j.pages[p] {
			if b.alive {
				b.alive = false
				k := jitKey{b.real, b.mode}
				if j.blocks[k] == b {
					delete(j.blocks, k)
				}
				j.stats.Invalidated++
			}
		}
		delete(j.links, p)
		for _, c := range m.CPUs {
			if c.jitInd == nil {
				continue
			}
			for i := range c.jitInd {
				if c.jitInd[i].code != 0 && c.jitInd[i].real == p {
					c.jitInd[i] = jitIndirect{}
				}
			}
		}
		delete(j.pages, p)
		j.codePages[p] = 0
	}
}

// jitLookup returns the cache entry for the block at the CPU's PC,
// compiling it if needed, or nil when the instruction must be interpreted
// (including any fetch that would raise an interrupt).
func (c *CPU) jitLookup() *jitCacheEntry {
	m := c.m
	ea := c.mask(c.PC)
	mode := c.MSR & jitModeMask
	gen := c.tlbGen ^ m.hptGen<<32
	if c.jitCache == nil {
		c.jitCache = new([jitCacheSize]jitCacheEntry)
		c.jitInd = new([jitIndirectSize]jitIndirect)
	}
	e := &c.jitCache[jitCacheIndex(ea)]
	if e.ea == ea && e.mode == mode && e.gen == gen && e.blk != nil && e.blk.alive && m.slotCurrent(e.slot, e.slotVer) {
		if e.shared {
			// Native code reaching ea through a branch it could not
			// resolve finds it next time.
			if ind := &c.jitInd[jitIndirectIndex(ea)]; ind.ea != ea || ind.code != e.blk.code || ind.gen != gen {
				*ind = jitIndirect{ea: ea, gen: gen, mode: mode, slot: e.slot, slotVer: e.slotVer, code: e.blk.code, real: e.real >> 12}
			}
		}
		return e
	}
	real := ea & (1<<60 - 1)
	slot := uint64(0)
	if c.MSR&MSRIR != 0 {
		t := &c.itlb[c.tlbIndex(ea)]
		if !(t.tag == c.tlbTag(ea, true) && t.gen == gen && m.slotCurrent(t.slot, t.slotVer)) {
			if _, err := c.Translate(ea, true, accessExec); err != nil {
				return nil
			}
			// Translate through the caches so the fetch sets the
			// reference bit exactly as the interpreter does.
			if _, ok := c.translate(ea, accessExec); !ok {
				return nil
			}
			if !(t.tag == c.tlbTag(ea, true) && t.gen == gen) {
				return nil // an uncached translation; interpret
			}
		}
		// The fill set the reference bit, as fetch would.
		real, slot = t.real|ea&0xfff, t.slot
	}
	if ea&3 != 0 || real&^0xfff+0x1000 > uint64(len(m.Mem)) {
		return nil
	}
	j := m.jit
	k := jitKey{real, mode}
	b := j.blocks[k]
	if len(m.Breakpoints) != 0 && m.breakpointInPage(ea) {
		// Shared blocks chain within their page without dispatcher
		// checks, so this page uses private blocks that stop before each
		// breakpoint.
		b = m.jitBuild(ea, real, mode, false)
	} else if b == nil {
		b = m.jitBuild(ea, real, mode, true)
	}
	if b == nil {
		return nil
	}
	shared := b.code != 0 && j.blocks[jitKey{real, mode}] == b
	*e = jitCacheEntry{ea: ea, mode: mode, gen: gen, slot: slot, slotVer: m.slotVersion(slot), blk: b,
		brk: len(m.Breakpoints) != 0 && m.Breakpoints[ea], shared: shared, real: real}
	if shared {
		c.jitInd[jitIndirectIndex(ea)] = jitIndirect{ea: ea, gen: gen, mode: mode, slot: slot, slotVer: e.slotVer, code: b.code, real: real >> 12}
	}
	return e
}

// jitBuild compiles a block. Shared blocks are found again by real address
// and chain to shared blocks in their page; a private block (for an alias
// whose page holds a breakpoint) leaves every direct branch to the
// dispatcher.
func (m *Machine) jitBuild(ea, real, mode uint64, shared bool) *jitBlock {
	j := m.jit
	code, n, sites := m.jitCompile(ea, real, mode, shared)
	b := &jitBlock{n: uint64(n), real: real, mode: mode, alive: true}
	if n > 0 {
		entry, ok := j.code.add(code)
		if !ok {
			m.jitFlush()
			if entry, ok = j.code.add(code); !ok {
				return nil
			}
		}
		b.code = entry
	}
	p := real >> 12
	if shared {
		k := jitKey{real, mode}
		j.blocks[k] = b
		for _, s := range sites {
			site := b.code + uintptr(s.off)
			tk := jitKey{real&^0xfff | s.target&0xfff, mode}
			if t := j.blocks[tk]; t != nil && t.alive && t.code != 0 {
				j.code.patch(site, t.code)
			} else {
				if j.links[p] == nil {
					j.links[p] = map[jitKey][]uintptr{}
				}
				j.links[p][tk] = append(j.links[p][tk], site)
			}
		}
		if waiting := j.links[p]; waiting != nil && b.code != 0 {
			for _, site := range waiting[k] {
				j.code.patch(site, b.code)
			}
			delete(waiting, k)
		}
	}
	j.pages[p] = append(j.pages[p], b)
	j.codePages[p] = 1
	j.stats.Compiled++
	return b
}

// breakpointInPage reports a breakpoint in ea's effective page.
func (m *Machine) breakpointInPage(ea uint64) bool {
	for a := range m.Breakpoints {
		if a>>12 == ea>>12 {
			return true
		}
	}
	return false
}

// jitCheckBreakpoints discards compiled code when the breakpoint set has
// changed, since blocks end before the breakpoints present when compiled.
func (m *Machine) jitCheckBreakpoints() {
	if len(m.Breakpoints) == 0 && m.jit.breakSig == 0 {
		return // the common case: no breakpoints, before or now
	}
	sig := uint64(len(m.Breakpoints))
	for a := range m.Breakpoints {
		sig += a*0x9e3779b97f4a7c15 ^ a>>29
	}
	if sig != m.jit.breakSig {
		m.jit.breakSig = sig
		m.jitFlush()
	}
}

// otherReservations returns the native store mode for CPU c: 0 when no
// other CPU holds a reservation, 2 and the granule (real address / 128)
// when exactly one does, else 1 (every store is interpreted).
func (m *Machine) otherReservations(c *CPU) (uint64, uint64) {
	mode, granule := uint64(0), uint64(0)
	for _, o := range m.CPUs {
		if o == c || !o.resValid {
			continue
		}
		if mode != 0 {
			return 1, 0
		}
		mode, granule = 2, o.resAddr/reservationGranule
	}
	return mode, granule
}

// runJIT executes up to limit instructions (none interrupt-relevant
// between checks, as run's inner loop) using native blocks where possible.
// It returns the number retired.
func (c *CPU) runJIT(limit uint64, breaks bool) uint64 {
	m := c.m
	j := m.jit
	var done uint64
	for done < limit {
		e := c.jitLookup()
		// run checked the first boundary before delivering interrupts.
		if breaks && done != 0 && (e != nil && e.brk || e == nil && m.Breakpoints[c.PC]) {
			c.Stop("breakpoint", fmt.Sprintf("pc %016x", c.PC))
			break
		}
		var b *jitBlock
		if e != nil {
			b = e.blk
		}
		side := uint32(0)
		if !breaks && b != nil && b.code != 0 && b.n > limit-done {
			// Fewer than a block's instructions (< jitMaxInstructions)
			// remain before the next interrupt check: interpret them
			// without a lookup (or a compile at each PC) per step.
			for done < limit {
				c.step()
				j.interpreted[4<<16|jitOpcodeKey(c.lastWord)]++
				done++
				if c.sync || c.stop != nil {
					break
				}
			}
			break
		}
		if b != nil && b.code != 0 && b.n <= limit-done {
			ctx := &j.ctx
			ctx.memLen = uint64(len(m.Mem))
			ctx.gen = c.tlbGen ^ m.hptGen<<32
			ctx.storeSlow = 0
			if m.watchHi > m.watchLo {
				ctx.storeSlow = 1 // every store may stop on the watch
			} else if m.reservations {
				// Stores must cancel other CPUs' reservations; this CPU's
				// own reservation survives them. Other CPUs do not run
				// during the native run, so their reservations are fixed.
				ctx.storeSlow, ctx.resGranule = m.otherReservations(c)
			}
			ctx.reserved = 0
			ctx.slotVer = jitPointer(m.slotVer)
			ctx.exit, ctx.ret = 0, 0
			ctx.left = limit - done
			ctx.instrBase = m.instructions + ctx.left
			ctx.cpuInstrBase = c.Instructions + ctx.left
			ctx.tbOffset = m.tbOffset
			if c.jitInd == nil {
				c.jitInd = new([jitIndirectSize]jitIndirect)
			}
			ctx.indirect = jitPointer(c.jitInd[:])
			ctx.htab = 0
			if m.HTAB != nil {
				ctx.htab = jitPointer(m.HTAB.Entries)
			}
			jitEnter(b.code, c, m, ctx)
			if ctx.reserved != 0 {
				m.reservations = true
			}
			ran := limit - done - ctx.left
			m.instructions += ran
			c.Instructions += ran
			done += ran
			j.stats.Native++
			j.stats.NativeInstructions += ran
			if ctx.exit == 0 {
				if ctx.ret < uint64(jitReturns) {
					j.returns[ctx.ret]++
				}
				if c.sync {
					break // a native mtmsrd enabled interrupts
				}
				continue
			}
			j.stats.SideExits++
			if ctx.exit < uint64(exitReasons) {
				j.exitReasons[ctx.exit]++
			}
			side = 1 << 16
		}
		c.step()
		j.interpreted[side<<1|jitOpcodeKey(c.lastWord)]++
		done++
		if c.sync {
			break
		}
	}
	return done
}
