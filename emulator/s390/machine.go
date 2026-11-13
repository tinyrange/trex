package s390

import (
	"fmt"
	"time"
)

// todEpoch is the TOD-clock value of 1970-01-01 00:00:00 UTC.
const todEpoch = 0x7d91048bca000000

// TOD units per microsecond (bit 51 is one microsecond).
const todMicro = 4096

// Config describes a machine.
type Config struct {
	Memory int // bytes of main storage
	CPUs   int
	// Start is the wall-clock time the TOD clock is set to at power on.
	Start time.Time
	// MIPS is the nominal instruction rate used to advance virtual time.
	MIPS int
	// CPUModel and CPUSerial are reported by STORE CPU ID.
	CPUModel  uint16
	CPUSerial uint32
	// NoIdleSkip disables advancing time across detected spin loops.
	NoIdleSkip bool
	// S370 selects the System/370 architecture instead of ESA/390.
	S370 bool
}

// Machine is an ESA/390 configuration: storage, CPUs, channel subsystem and
// devices. It is driven synchronously by Run; time is virtual and advances with
// executed instructions and, in enabled wait states, jumps to the next timer
// deadline.
type Machine struct {
	S    *Storage
	CPUs []*CPU
	CSS  *ChannelSubsystem
	cfg  Config

	tod             uint64 // current virtual TOD value
	todStep         uint64 // TOD units per instruction
	lastStck        uint64
	todProgrammable uint16

	serviceSignal bool
	serviceParam  uint32
	// S370 is set for a System/370 machine.
	S370 bool
	sclp *sclp

	Events []Event
	// BreakProgram stops Run (kind "program") when a program
	// interruption with one of these codes is taken; the general
	// registers still hold their values at the interruption.
	BreakProgram map[uint16]bool
	programHit   string

	// EventLimit bounds retained events.
	EventLimit int
	// keyGen changes whenever a storage key's access-control or fetch
	// bits may change, invalidating every CPU's operand cache.
	keyGen    uint64
	pgmCounts map[uint16]uint64
	inputWake bool

	Breakpoints map[uint32]bool
	// IdleSkip enables spin detection (see runBatch).
	IdleSkip    bool
	IdleSkips   uint64
	IdleSkipped uint64 // TOD units skipped
	skipCredit  uint64 // skipped time not yet charged to Run's budget
	// LoadParm is the 8-character load parameter reported by READ SCP INFO.
	LoadParm string
	// SCPConfig holds the configuration-characteristic bytes reported by
	// READ SCP INFO at SCCB offset 80.
	SCPConfig [6]byte
	// Facilities is the facility list STORE FACILITY LIST stores (bit 0 is
	// the leftmost bit of the word).
	Facilities uint32
	// SCPCPUFacilities is the 12-byte facility map of each CPU entry.
	SCPCPUFacilities [12]byte
	// TraceIO records an event for every START SUBCHANNEL.
	TraceIO bool
	// TraceIOSkip lists devices TraceIO leaves out.
	TraceIOSkip      map[uint16]bool
	watchLo, watchHi uint32
	watchHit         bool
	watchAddr        uint32
	// Profile, when non-nil, counts executed instructions per 256-byte block.
	Profile map[uint32]uint64
	// Interrupts counts interruptions taken by class.
	Interrupts map[string]uint64
	// History, when non-nil, holds the most recent instructions executed.
	History          []HistoryEntry
	HistoryGuestOnly bool
	historyPos       int
}

// HistoryEntry is one executed instruction.
type HistoryEntry struct {
	IA uint32
	Op [6]byte
	CC byte
}

// Watch stops Run after an instruction stores into [lo, hi) absolute.
func (m *Machine) Watch(lo, hi uint32) { m.watchLo, m.watchHi = lo, hi }

// EnableHistory keeps the last n instructions.
func (m *Machine) EnableHistory(n int) {
	m.History = make([]HistoryEntry, 0, n)
	m.historyPos = 0
}

// RecentHistory returns retained instructions, oldest first.
func (m *Machine) RecentHistory() []HistoryEntry {
	if len(m.History) < cap(m.History) {
		return append([]HistoryEntry(nil), m.History...)
	}
	out := append([]HistoryEntry(nil), m.History[m.historyPos:]...)
	return append(out, m.History[:m.historyPos]...)
}

func (m *Machine) record(c *CPU) {
	e := HistoryEntry{IA: c.ia, Op: c.op, CC: c.PSW.CC}
	if len(m.History) < cap(m.History) {
		m.History = append(m.History, e)
		return
	}
	m.History[m.historyPos] = e
	m.historyPos = (m.historyPos + 1) % cap(m.History)
}

// Event is a structured machine event for observation.
type Event struct {
	Kind   string
	TOD    uint64
	CPU    uint16
	PSW    string
	Detail string
}

func NewMachine(cfg Config) *Machine {
	if cfg.Memory == 0 {
		cfg.Memory = 64 << 20
	}
	if cfg.CPUs == 0 {
		cfg.CPUs = 1
	}
	if cfg.MIPS == 0 {
		cfg.MIPS = 50
	}
	if cfg.Start.IsZero() {
		cfg.Start = time.Now()
	}
	if cfg.CPUModel == 0 {
		cfg.CPUModel = 0x9672
	}
	if cfg.CPUSerial == 0 {
		cfg.CPUSerial = 0x012345
	}
	m := &Machine{S: NewStorage(cfg.Memory), cfg: cfg, EventLimit: 4096, pgmCounts: map[uint16]uint64{}, Interrupts: map[string]uint64{}, IdleSkip: !cfg.NoIdleSkip}
	m.tod = todEpoch + uint64(cfg.Start.UnixMicro())*todMicro
	m.todStep = todMicro / uint64(cfg.MIPS)
	if m.todStep == 0 {
		m.todStep = 1
	}
	m.CSS = newCSS(m)
	m.sclp = &sclp{m: m}
	if cfg.S370 {
		m.S370 = true
		m.S.setKeyBlock(11)
	}
	for i := 0; i < cfg.CPUs; i++ {
		c := &CPU{M: m, S: m.S, Addr: uint16(i), SIEExits: map[byte]uint64{}, pgMask: 0xfff}
		if m.S370 {
			c.pgMask = 0x7ff // 2K pages and key blocks
		}
		c.Reset(true)
		m.CPUs = append(m.CPUs, c)
	}
	return m
}

// TOD returns the current TOD-clock value.
func (m *Machine) TOD() uint64 { return m.tod }

// Time returns the wall-clock time represented by the TOD clock.
func (m *Machine) Time() time.Time {
	return time.UnixMicro(int64((m.tod - todEpoch) / todMicro)).UTC()
}

func (m *Machine) event(kind string, c *CPU, detail string) {
	if len(m.Events) >= m.EventLimit {
		// Drop the oldest quarter at once so a large limit stays cheap.
		drop := len(m.Events) - m.EventLimit + 1 + m.EventLimit/4
		if drop > len(m.Events) {
			drop = len(m.Events)
		}
		n := copy(m.Events, m.Events[drop:])
		m.Events = m.Events[:n]
	}
	e := Event{Kind: kind, TOD: m.tod, Detail: detail}
	if c != nil {
		e.CPU = c.Addr
		e.PSW = c.PSW.String()
	}
	m.Events = append(m.Events, e)
}

func (m *Machine) noteProgram(c *CPU, code uint16) {
	key := code
	kind := "program"
	if c.sie != nil {
		key |= 0x1000
		kind = "guest-program"
	}
	m.pgmCounts[key]++
	if m.BreakProgram[code] {
		c.hitBreak = true
		m.programHit = fmt.Sprintf("program %04X at %08X", code, c.ia)
	}
	if m.pgmCounts[key] <= 16 {
		m.event(kind, c, fmt.Sprintf("code %04X at %08X ilc %d op %X", code, c.ia, c.ilc, c.op[:ilen(c.op[0])]))
	}
}

// ProgramCounts reports program interruptions taken by code.
func (m *Machine) ProgramCounts() map[uint16]uint64 { return m.pgmCounts }

// StopReason describes why Run returned.
type StopReason struct {
	Kind   string // "budget", "disabled-wait", "idle", "stopped", "check-stop", "breakpoint", "deadline"
	Detail string
}

func (r StopReason) String() string {
	if r.Detail == "" {
		return r.Kind
	}
	return r.Kind + ": " + r.Detail
}

// IPL performs a CCW-type initial program load from the device.
func (m *Machine) IPL(devno uint16, clear bool) error {
	sch := m.CSS.byDevice(devno)
	if sch == nil {
		return fmt.Errorf("ipl: no device %04X", devno)
	}
	for _, c := range m.CPUs {
		c.Reset(clear)
	}
	if clear {
		for i := range m.S.Mem {
			m.S.Mem[i] = 0
		}
		for i := range m.S.Keys {
			m.S.Keys[i] = 0
		}
	}
	m.CSS.reset()
	c := m.CPUs[0]
	// Implied CCW: read IPL, 24 bytes to location 0, command chained.
	be.PutUint64(m.S.Mem[0:], 0x02000000_60000018)
	if err := m.CSS.iplChannelProgram(sch); err != nil {
		return err
	}
	// The IPL leaves the IPL subchannel enabled with interruption subclass 0.
	sch.enabled = true
	sch.isc = 0
	if m.S370 {
		// System/370 stores the I/O address in the interruption code of a
		// BC-mode IPL PSW, or at location 186 for an EC-mode one.
		if m.S.Mem[1]&0x08 == 0 {
			be.PutUint16(m.S.Mem[2:], devno)
		} else {
			be.PutUint16(m.S.Mem[0xba:], devno)
		}
	} else {
		be.PutUint32(m.S.Mem[0xb8:], 0x00010000|uint32(sch.num))
		be.PutUint32(m.S.Mem[0xbc:], 0)
	}
	if !c.loadPSW(be.Uint64(m.S.Mem[0:])) {
		return fmt.Errorf("ipl: invalid IPL PSW %016X", be.Uint64(m.S.Mem[0:]))
	}
	c.Stopped = false
	c.next = c.PSW.IA
	c.pswChanged = true
	m.event("ipl", c, fmt.Sprintf("device %04X", devno))
	return nil
}

// Image is data placed in absolute storage by Load.
type Image struct {
	Address uint32
	Data    []byte
}

// Load performs a load from storage-resident images, as the service
// processor's load from removable media or a server does: after a reset the
// images are placed at their absolute addresses and CPU 0 loads the PSW from
// absolute location 0. No IPL device is reported.
func (m *Machine) Load(images []Image, clear bool) error {
	for _, c := range m.CPUs {
		c.Reset(clear)
	}
	if clear {
		clear64(m.S.Mem)
		for i := range m.S.Keys {
			m.S.Keys[i] = 0
		}
	}
	m.CSS.reset()
	for _, im := range images {
		end := uint64(im.Address) + uint64(len(im.Data))
		if end > uint64(len(m.S.Mem)) {
			return fmt.Errorf("load: image at %08X (%d bytes) exceeds storage", im.Address, len(im.Data))
		}
		copy(m.S.Mem[im.Address:], im.Data)
	}
	c := m.CPUs[0]
	if !c.loadPSW(be.Uint64(m.S.Mem[0:])) {
		return fmt.Errorf("load: invalid PSW %016X at location 0", be.Uint64(m.S.Mem[0:]))
	}
	c.Stopped = false
	c.next = c.PSW.IA
	c.pswChanged = true
	m.event("ipl", c, fmt.Sprintf("load %d images", len(images)))
	return nil
}

func clear64(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Command queues an operator command on the hardware system console.
func (m *Machine) Command(text string) { m.sclp.Command(text) }

// ConsoleLines returns the operating-system message lines written through
// the service-call logical processor.
func (m *Machine) ConsoleLines() []string { return m.sclp.Lines }

// Run executes up to budget instructions across all CPUs.
func (m *Machine) Run(budget uint64) StopReason {
	var done uint64
	for done < budget {
		active := 0
		progressed := false
		for _, c := range m.CPUs {
			if c.Stopped || c.Check {
				continue
			}
			active++
			if c.PSW.Wait {
				continue
			}
			n := c.runBatch(int(min(budget-done, 4096)))
			done += uint64(n)
			// Time skipped across spin loops is charged to the budget at
			// the nominal instruction rate.
			done += m.skipCredit
			m.skipCredit = 0
			if n > 0 {
				progressed = true
			}
			if c.hitBreak {
				c.hitBreak = false
				if m.watchHit {
					m.watchHit = false
					return StopReason{Kind: "watch", Detail: fmt.Sprintf("store to %08X by instruction at %08X", m.watchAddr, c.ia)}
				}
				if m.programHit != "" {
					d := m.programHit
					m.programHit = ""
					return StopReason{Kind: "program", Detail: d}
				}
				return StopReason{Kind: "breakpoint", Detail: fmt.Sprintf("cpu %d at %08X", c.Addr, c.PSW.IA)}
			}
		}
		if active == 0 {
			for _, c := range m.CPUs {
				if c.Check {
					return StopReason{Kind: "check-stop", Detail: c.checkReason}
				}
			}
			return StopReason{Kind: "stopped"}
		}
		if progressed {
			continue
		}
		// Every running CPU is waiting.
		if m.CSS.tickPCI(true) {
			continue
		}
		for _, c := range m.CPUs {
			if c.Stopped || !c.PSW.Wait {
				continue
			}
			if c.takeInterrupt() {
				progressed = true
			}
		}
		if progressed {
			continue
		}
		allDisabled := true
		for _, c := range m.CPUs {
			if c.Stopped {
				continue
			}
			if c.PSW.IO || c.PSW.Ext || c.PSW.MC {
				allDisabled = false
			}
		}
		if allDisabled {
			c := m.CPUs[0]
			return StopReason{Kind: "disabled-wait", Detail: c.PSW.String()}
		}
		next, ok := m.nextDeadline()
		if !ok {
			return StopReason{Kind: "idle", Detail: m.CPUs[0].PSW.String()}
		}
		if next > m.tod {
			// Count skipped time against the budget at the nominal rate.
			skip := (next - m.tod) / m.todStep
			if skip > budget-done {
				// Do not run past the caller's time budget.
				m.tod += (budget - done) * m.todStep
				done = budget
				continue
			}
			m.tod = next
			done += skip
		}
	}
	return StopReason{Kind: "budget"}
}

// skipIdle advances the TOD clock to the next timer deadline, charging the
// skipped time to the running budget.
func (m *Machine) skipIdle() {
	if next, ok := m.nextDeadline(); ok && next > m.tod {
		m.IdleSkips++
		m.IdleSkipped += next - m.tod
		m.skipCredit += (next - m.tod) / m.todStep
		m.tod = next
	}
}

// nextDeadline returns the earliest TOD at which an enabled timer fires.
func (m *Machine) nextDeadline() (uint64, bool) {
	var best uint64
	ok := false
	for _, c := range m.CPUs {
		if c.Stopped || !c.PSW.Ext {
			continue
		}
		if c.extEnabled(extClockComparator) && c.ClockComparator != ^uint64(0) {
			t := c.ClockComparator + 1
			if !ok || t < best {
				best, ok = t, true
			}
		}
		if m.S370 && c.extEnabled(extIntervalTimer) {
			if t, has := c.intervalDeadline(); has && (!ok || t < best) {
				best, ok = t, true
			}
		}
		if c.extEnabled(extCPUTimer) {
			if cur := c.cpuTimer(); cur >= 0 && uint64(cur) < ^uint64(0)-m.tod {
				t := m.tod + uint64(cur) + 1
				if !ok || t < best {
					best, ok = t, true
				}
			}
		}
	}
	if d, has := m.CSS.nextDeadline(); has && (!ok || d < best) {
		best, ok = d, true
	}
	return best, ok
}

// takeInterrupt takes one pending, enabled interruption. It reports whether
// an interruption was taken.
func (c *CPU) takeInterrupt() bool {
	if c.earlySpec {
		c.earlySpec = false
		c.ilc = 0
		c.next = c.PSW.IA
		c.ia = c.PSW.IA
		c.takeProgram(pgmSpecification, false)
		if c.earlySpec {
			c.Check = true
			c.checkReason = "program interruption loop: invalid program new PSW"
			return false
		}
		return true
	}
	if c.PSW.Ext {
		if bit := c.pendingExternal(); bit != 0 {
			c.PSW.Wait = false
			c.takeExternal(bit)
			return true
		}
	}
	if c.M.S370 {
		if c.PSW.IO && c.takeIO370() {
			return true
		}
	} else if c.PSW.IO {
		if sch := c.M.CSS.pendingInterrupt(c.CR[6]); sch != nil {
			c.PSW.Wait = false
			sid, parm := sch.interruptCode()
			sch.irq = false
			c.takeIO(sid, parm)
			return true
		}
	}
	return false
}

// runBatch executes up to n instructions and returns how many completed or
// were interrupted.
func (c *CPU) runBatch(n int) (done int) {
	defer func() {
		if r := recover(); r != nil {
			done++
			c.handleCheck(r)
		}
	}()
	check := 0
	lastStores := c.stores
	for done < n {
		if c.pswChanged || check == 0 {
			c.pswChanged = false
			check = 64
			// Spin detection: a CPU enabled for interruptions that stores
			// nothing for a long run of instructions can only change state
			// through an interruption, so advance time to the next deadline.
			// The general registers must also be unchanged across the
			// window: a long search or copy loop stores nothing either,
			// but it advances its registers.
			if c.stores == lastStores && c.M.IdleSkip && c.sie == nil && (c.PSW.Ext || c.PSW.IO) && (c.quiet == 0 || c.GR == c.quietGR) {
				if c.quiet == 0 {
					c.quietGR = c.GR
				}
				c.quiet++
				if c.quiet >= 64 {
					c.quiet = 0
					c.M.skipIdle()
					if c.M.skipCredit > 0 {
						return done
					}
				}
			} else {
				c.quiet = 0
			}
			lastStores = c.stores
			if c.M.S370 {
				c.intervalTimer() // the timer runs whatever the masks
			}
			c.M.CSS.tickPCI(false)
			if c.sie != nil {
				if c.sieInterrupts() {
					continue
				}
			} else if c.takeInterrupt() {
				if c.Check {
					return done
				}
				continue
			}
		}
		check--
		if c.PSW.Wait {
			return done
		}
		c.step()
		done++
		c.Instructions++
		// The clock advances with each instruction, so a clock read or a
		// timer stored mid-batch sees the exact time.
		c.M.tod += c.M.todStep
		if c.M.watchHit || c.hitBreak {
			c.hitBreak = true
			return done
		}
		if c.M.Breakpoints != nil && c.M.Breakpoints[c.PSW.IA] {
			c.hitBreak = true
			return done
		}
	}
	return done
}

// step fetches and executes one instruction.
func (c *CPU) step() {
	ia := c.PSW.IA & c.amask
	c.ia = ia
	c.ilc = 0
	c.next = ia
	if ia&1 != 0 {
		c.program(pgmSpecification)
	}
	var p []byte
	if c.ipageValid && ia&^c.pgMask == c.ipageV {
		a := c.ipageA | ia&c.pgMask
		p = c.S.Mem[a:]
	} else {
		a := c.absolute(ia, accInstr, 0)
		c.ipageV = ia &^ c.pgMask
		c.ipageA = a &^ c.pgMask
		c.ipageValid = true
		p = c.S.Mem[a:]
	}
	n := ilen(p[0])
	if ia&c.pgMask+n > c.pgMask+1 {
		for i := uint32(0); i < n; i++ {
			c.op[i] = c.fetchInstrByte(ia + i)
		}
	} else if len(p) >= 6 {
		// A fixed-size copy; bytes past a shorter instruction are unused.
		c.op = [6]byte(p[:6])
	} else {
		copy(c.op[:n], p[:n])
	}
	c.ilc = n
	c.next = (ia + n) & c.amask
	if m := c.M; m.History != nil || m.Profile != nil {
		if m.History != nil && (!m.HistoryGuestOnly || c.sie != nil) {
			m.record(c)
		}
		if m.Profile != nil {
			m.Profile[ia>>8]++
		}
	}
	c.execute()
	c.PSW.IA = c.next
}

// TranslateVirtual returns the absolute address of a virtual address of
// CPU 0's primary address space.
func (m *Machine) TranslateVirtual(addr uint32) (uint32, error) {
	b, err := m.ReadVirtual(addr, 0)
	_ = b
	if err != nil {
		return 0, err
	}
	c := m.CPUs[0]
	var abs uint32
	err = func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				pc, ok := r.(programCheck)
				if !ok {
					panic(r)
				}
				err = fmt.Errorf("translate: %08X not addressable (program interruption %04X)", addr, pc.code)
			}
		}()
		real := addr & c.amask
		if c.PSW.DAT {
			real, _ = c.translate(real, c.CR[1], accFetch)
		}
		abs = c.realToAbs(real)
		return nil
	}()
	return abs, err
}

// ReadVirtual reads n bytes at a virtual address of CPU 0's primary
// address space (real addresses when DAT is off), for observation.
func (m *Machine) ReadVirtual(addr uint32, n int) (out []byte, err error) {
	if n < 0 || n > 1<<20 {
		return nil, fmt.Errorf("read: length must be 0..1M")
	}
	c := m.CPUs[0]
	defer func() {
		if r := recover(); r != nil {
			if pc, ok := r.(programCheck); ok {
				err = fmt.Errorf("read: %08X not addressable (program interruption %04X)", addr+uint32(len(out)), pc.code)
				return
			}
			panic(r)
		}
	}()
	for i := 0; i < n; i++ {
		v := (addr + uint32(i)) & c.amask
		real := v
		if c.PSW.DAT {
			real, _ = c.translate(v, c.CR[1], accFetch)
		}
		a := c.realToAbs(real)
		if !m.S.valid(a, 1) {
			return out, fmt.Errorf("read: %08X outside storage", v)
		}
		out = append(out, m.S.Mem[a])
	}
	return out, nil
}
