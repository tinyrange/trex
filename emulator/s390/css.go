package s390

import (
	"fmt"
	"sort"
)

// Unit (device) status bits.
const (
	usAttention  = 0x80
	usSM         = 0x40
	usCUE        = 0x20
	usBusy       = 0x10
	usCE         = 0x08
	usDE         = 0x04
	usUnitCheck  = 0x02
	usUnitExcept = 0x01
)

// Subchannel status bits.
const (
	scsPCI          = 0x80
	scsIncorrectLen = 0x40
	scsProgramCheck = 0x20
	scsProtection   = 0x10
	scsDataCheck    = 0x08
	scsControlCheck = 0x04
	scsIFCC         = 0x02
	scsChainCheck   = 0x01
)

// Device is a channel-attached I/O device.
type Device interface {
	// SenseID returns the SENSE ID response.
	SenseID() []byte
	// Exec executes one channel command. For read-type commands the device
	// returns the data it would transfer; for write and control commands
	// data holds the bytes available from storage and the device returns
	// how many it consumed in used. status holds the unit status presented
	// at the end of the command (CE|DE is normal completion; SM requests a
	// skip of the next CCW).
	Exec(cmd byte, data []byte, chained bool) (out []byte, used int, status byte)
	// Reset is called on system reset and clear subchannel.
	Reset()
}

// Blocking is implemented by devices whose commands may wait for an
// operator, such as a console read with no input typed yet. The channel
// program is suspended at that CCW and continues when Resume is called.
type Blocking interface {
	Blocked(cmd byte) bool
}

// Addressed is optionally implemented by devices whose responses
// include their device number (for example, the unit address in DASD
// configuration data). Attach reports the number.
type Addressed interface {
	SetDeviceNumber(devno uint16)
}

// ChainEnd is optionally implemented by devices that track the start and
// end of a channel program (for example, ECKD define-extent state).
type ChainEnd interface {
	StartChain()
	EndChain()
}

// Subchannel holds the path-management control word and status.
type Subchannel struct {
	num     uint16
	devno   uint16
	dev     Device
	intparm uint32
	isc     byte
	enabled bool
	lpm     byte
	mbi     uint16
	mm      byte
	limit   byte
	multip  bool
	timing  bool

	// SCSW
	key, ccwfmt byte
	flags       uint32 // SCSW word-0 flag bits (S, L, F, P, I, A, U, Z, E, N)
	fc, ac, sc  byte
	ccwaddr     uint32
	devStatus   byte
	schStatus   byte
	residual    uint16
	pending     bool // status pending
	irq         bool // interruption request not yet accepted
	ccDeferred  byte

	sense    []byte
	attnHold bool

	// A channel program waiting at a CCW for its device (see Blocking).
	blocked   bool
	blockAddr uint32
	blockFmt1 bool

	// System/370 program-controlled interruption: the channel program is
	// paused after a CCW with the PCI flag so the program can modify the
	// CCWs that follow, as it may while a real channel runs.
	pciWait bool   // paused at blockAddr after a PCI CCW
	pciIRQ  bool   // PCI interruption not yet taken
	pciAt   uint64 // CPU instruction count when paused or interrupted
}

const (
	fcStart = 4
	fcHalt  = 2
	fcClear = 1

	scAlert        = 0x10
	scIntermediate = 0x08
	scPrimary      = 0x04
	scSecondary    = 0x02
	scPending      = 0x01
)

type ioTrace struct {
	cmd    byte
	flags  byte
	count  uint32
	status byte
	in     []byte
	out    []byte
}

func (s *ChannelSubsystem) traceString() string {
	var b []byte
	for _, t := range s.trace {
		data := t.in
		if len(data) == 0 {
			data = t.out
		}
		if len(data) > 48 {
			data = data[:48]
		}
		f := ""
		if t.flags != 0 {
			f = fmt.Sprintf(" f=%02X", t.flags)
		}
		b = fmt.Appendf(b, "[%02X%s n=%d st=%02X %X]", t.cmd, f, t.count, t.status, data)
	}
	return string(b)
}

// ChannelSubsystem holds every subchannel.
type ChannelSubsystem struct {
	trace   []ioTrace
	m       *Machine
	subs    []*Subchannel
	bydev   map[uint16]*Subchannel
	crw     []uint32
	crwPend bool
}

func newCSS(m *Machine) *ChannelSubsystem {
	return &ChannelSubsystem{m: m, bydev: map[uint16]*Subchannel{}}
}

// Attach adds a device at a device number and returns its subchannel number.
func (s *ChannelSubsystem) Attach(devno uint16, d Device) (uint16, error) {
	if _, ok := s.bydev[devno]; ok {
		return 0, fmt.Errorf("device %04X already attached", devno)
	}
	if a, ok := d.(Addressed); ok {
		a.SetDeviceNumber(devno)
	}
	sch := &Subchannel{num: uint16(len(s.subs)), devno: devno, dev: d, lpm: 0x80, enabled: s.m.S370}
	s.subs = append(s.subs, sch)
	s.bydev[devno] = sch
	// Keep subchannel numbers in device-number order, as on a configured
	// system, so probes enumerating subchannels see a stable layout.
	sort.Slice(s.subs, func(i, j int) bool { return s.subs[i].devno < s.subs[j].devno })
	for i, x := range s.subs {
		x.num = uint16(i)
	}
	return sch.num, nil
}

func (s *ChannelSubsystem) byDevice(devno uint16) *Subchannel { return s.bydev[devno] }

func (s *ChannelSubsystem) reset() {
	for _, x := range s.subs {
		x.intparm, x.isc, x.enabled, x.mbi, x.mm, x.limit, x.multip, x.timing = 0, 0, s.m.S370, 0, 0, 0, false, false
		x.lpm = 0x80
		x.clearStatus()
		x.dev.Reset()
	}
	s.crw = nil
}

func (x *Subchannel) clearStatus() {
	x.fc, x.ac, x.sc = 0, 0, 0
	x.flags = 0
	x.ccwaddr, x.devStatus, x.schStatus, x.residual = 0, 0, 0, 0
	x.pending = false
	x.irq = false
}

// Device returns the attached device.
func (x *Subchannel) Device() Device { return x.dev }

func (x *Subchannel) interruptCode() (uint32, uint32) {
	return 0x00010000 | uint32(x.num), x.intparm
}

// pendingInterrupt returns a subchannel with an enabled pending interruption.
func (s *ChannelSubsystem) pendingInterrupt(cr6 uint32) *Subchannel {
	for _, x := range s.subs {
		if x.irq && x.pending && x.enabled && cr6&(0x80000000>>x.isc) != 0 {
			return x
		}
	}
	return nil
}

func (s *ChannelSubsystem) nextDeadline() (uint64, bool) { return 0, false }

// Unsolicited presents an unsolicited status (for example attention) for a
// device. It reports false when the subchannel is busy or already pending.
func (s *ChannelSubsystem) Unsolicited(devno uint16, status byte) bool {
	x := s.bydev[devno]
	if x == nil || !x.enabled {
		return false
	}
	if x.pending || x.ac != 0 {
		x.attnHold = true
		return false
	}
	x.fc = 0
	x.ac = 0
	x.sc = scAlert | scPending
	x.flags = 0
	x.devStatus = status
	x.schStatus = 0
	x.residual = 0
	x.ccwaddr = 0
	x.pending = true
	x.irq = true
	return true
}

// scsw returns the 12-byte subchannel-status word.
func (x *Subchannel) scsw() [12]byte {
	var b [12]byte
	w0 := uint32(x.key)<<28 | x.flags | uint32(x.ccDeferred)<<24 | uint32(x.fc)<<12 | uint32(x.ac)<<5 | uint32(x.sc)
	if x.pending {
		w0 |= scPending
	}
	be.PutUint32(b[0:], w0)
	be.PutUint32(b[4:], x.ccwaddr)
	b[8] = x.devStatus
	b[9] = x.schStatus
	be.PutUint16(b[10:], x.residual)
	return b
}

// Activity-control bit values (SCSW bits 20-26 shifted into ac<<5).
const (
	acResumePending = 0x40
	acStartPending  = 0x20
	acHaltPending   = 0x10
	acClearPending  = 0x08
	acSubchActive   = 0x04
	acDeviceActive  = 0x02
	acSuspended     = 0x01
)

// pmcw returns the 28-byte path-management control word.
func (x *Subchannel) pmcw() [28]byte {
	var b [28]byte
	be.PutUint32(b[0:], x.intparm)
	w1 := uint32(x.isc&7)<<27 | uint32(x.devno) | 1<<16 // V: device number valid
	if x.enabled {
		w1 |= 1 << 23
	}
	w1 |= uint32(x.limit&3) << 21
	w1 |= uint32(x.mm&3) << 19
	if x.multip {
		w1 |= 1 << 18
	}
	if x.timing {
		w1 |= 1 << 17
	}
	be.PutUint32(b[4:], w1)
	b[8] = x.lpm // LPM
	b[9] = 0x00  // PNOM
	b[10] = 0x00 // LPUM
	b[11] = 0x80 // PIM
	be.PutUint16(b[12:], x.mbi)
	b[14] = 0xff               // POM
	b[15] = 0x80               // PAM
	b[16] = byte(x.devno >> 8) // CHPID 0
	return b
}

// ---- Instructions ----

func (c *CPU) subchannel(r int) *Subchannel {
	id := c.GR[1]
	if id&0xffff0000 != 0x00010000 {
		c.program(pgmOperand)
	}
	n := int(id & 0xffff)
	if n >= len(c.M.CSS.subs) {
		return nil
	}
	return c.M.CSS.subs[n]
}

// ssch: START SUBCHANNEL.
func (c *CPU) ssch(a uint32, b int) {
	c.privileged()
	if a&3 != 0 {
		c.program(pgmSpecification)
	}
	x := c.subchannel(1)
	w0 := c.fetchWord(a, b)
	w1 := c.fetchWord(a+4, b)
	w2 := c.fetchWord(a+8, b)
	if w1&0x00000040 != 0 || w2&0x80000000 != 0 {
		// Reserved ORB bits.
	}
	if x == nil {
		c.PSW.CC = 3
		return
	}
	if !x.enabled {
		c.PSW.CC = 3
		return
	}
	if x.pending || x.fc != 0 {
		c.PSW.CC = 2
		if x.pending {
			c.PSW.CC = 1
		}
		if c.M.TraceIO && !c.M.TraceIOSkip[x.devno] {
			c.M.event("io", c, fmt.Sprintf("dev %04X ssch cc %d orb %08X ccw %08X fc %X ac %X sc %X", x.devno, c.PSW.CC, w1, w2, x.fc, x.ac, x.sc))
		}
		return
	}
	x.intparm = w0
	x.key = byte(w1 >> 28)
	x.flags = 0
	if w1&0x00800000 != 0 {
		x.flags |= 1 << 23 // F: format-1 CCWs
	}
	if w1&0x00200000 != 0 {
		x.flags |= 1 << 21 // I: initial-status interruption
	}
	x.fc = fcStart
	c.PSW.CC = 0
	c.M.CSS.start(x, w2&0x7ffffffc, w1)
}

func orbFormat1(w1 uint32) bool { return w1&0x00800000 != 0 }

// tsch: TEST SUBCHANNEL.
func (c *CPU) tsch(a uint32, b int) {
	c.privileged()
	if a&3 != 0 {
		c.program(pgmSpecification)
	}
	x := c.subchannel(1)
	if x == nil {
		c.PSW.CC = 3
		return
	}
	c.checkStore(a, 64, b)
	var irb [64]byte
	s := x.scsw()
	copy(irb[0:12], s[:])
	// ESW format 0: word 1 = extended-report word (none); word 0 logout.
	// Format-1 extended-status word: the last-path-used mask names the
	// subchannel's single path.
	irb[13] = 0x80
	if len(x.sense) > 0 && x.devStatus&usUnitCheck != 0 {
		// Concurrent sense is not modelled; the program issues SENSE.
	}
	for i := 0; i < 64; i++ {
		c.storeByte(a+uint32(i), b, irb[i])
	}
	if x.pending {
		c.PSW.CC = 0
		if x.sc == scIntermediate {
			// Intermediate (PCI) status: the channel program goes on
			// once the program has had time to act on it.
			x.schStatus &^= scsPCI
			x.pciAt = c.Instructions
		}
		// Clear the status-pending condition and completed functions.
		if x.sc&(scPrimary|scSecondary) != 0 || x.sc&scAlert != 0 && x.ac == 0 || x.fc&(fcClear|fcHalt) != 0 {
			x.fc = 0
			x.ac = 0
			// The ORB-derived bits (F, I) describe the start function
			// and stay in the SCSW through intermediate status.
			x.flags = 0
		}
		x.sc = 0
		x.pending = false
		x.irq = false
		x.ccDeferred = 0
		if x.attnHold {
			x.attnHold = false
			c.M.CSS.Unsolicited(x.devno, usAttention)
		}
	} else {
		c.PSW.CC = 1
	}
}

// stsch: STORE SUBCHANNEL.
func (c *CPU) stsch(a uint32, b int) {
	c.privileged()
	if a&3 != 0 {
		c.program(pgmSpecification)
	}
	x := c.subchannel(1)
	if x == nil {
		c.PSW.CC = 3
		return
	}
	c.checkStore(a, 52, b)
	p := x.pmcw()
	s := x.scsw()
	var buf [52]byte
	copy(buf[0:28], p[:])
	copy(buf[28:40], s[:])
	for i := 0; i < 52; i++ {
		c.storeByte(a+uint32(i), b, buf[i])
	}
	c.PSW.CC = 0
}

// msch: MODIFY SUBCHANNEL.
func (c *CPU) msch(a uint32, b int) {
	c.privileged()
	if a&3 != 0 {
		c.program(pgmSpecification)
	}
	x := c.subchannel(1)
	w0 := c.fetchWord(a, b)
	w1 := c.fetchWord(a+4, b)
	w2 := c.fetchWord(a+8, b)
	w3 := c.fetchWord(a+12, b)
	w6 := c.fetchWord(a+24, b)
	if w1&0xc7000000 != 0 {
		c.program(pgmOperand)
	}
	if x == nil {
		c.PSW.CC = 3
		return
	}
	if x.pending {
		c.PSW.CC = 1
		return
	}
	if x.fc != 0 {
		c.PSW.CC = 2
		return
	}
	x.intparm = w0
	x.isc = byte(w1>>27) & 7
	x.enabled = w1&(1<<23) != 0
	x.limit = byte(w1>>21) & 3
	x.mm = byte(w1>>19) & 3
	x.multip = w1&(1<<18) != 0
	x.timing = w1&(1<<17) != 0
	x.lpm = byte(w2 >> 24)
	x.mbi = uint16(w3 >> 16)
	_ = w6
	c.PSW.CC = 0
}

// hsch: HALT SUBCHANNEL. Channel programs complete synchronously, so a halt
// finds no activity and presents halt status.
func (c *CPU) hsch() {
	c.privileged()
	x := c.subchannel(1)
	if x == nil {
		c.PSW.CC = 3
		return
	}
	if x.pending && x.sc&scIntermediate == 0 {
		c.PSW.CC = 1
		return
	}
	if x.fc&(fcHalt|fcClear) != 0 {
		c.PSW.CC = 2
		return
	}
	x.fc |= fcHalt
	x.ac = 0
	x.sc = scPrimary | scSecondary
	x.pending = true
	x.irq = true
	x.devStatus = 0
	c.PSW.CC = 0
}

// csch: CLEAR SUBCHANNEL.
func (c *CPU) csch() {
	c.privileged()
	x := c.subchannel(1)
	if x == nil {
		c.PSW.CC = 3
		return
	}
	x.clearStatus()
	x.fc = fcClear
	x.pending = true
	x.irq = true
	x.dev.Reset()
	c.PSW.CC = 0
}

// rsch: RESUME SUBCHANNEL (suspend is not used; reports not suspended).
func (c *CPU) rsch() {
	c.privileged()
	x := c.subchannel(1)
	if x == nil {
		c.PSW.CC = 3
		return
	}
	if x.pending {
		c.PSW.CC = 1
		return
	}
	c.PSW.CC = 2
}

// xsch: CANCEL SUBCHANNEL.
func (c *CPU) xsch() {
	c.privileged()
	x := c.subchannel(1)
	if x == nil {
		c.PSW.CC = 3
		return
	}
	if x.pending {
		c.PSW.CC = 1
		return
	}
	c.PSW.CC = 2
}

// tpi: TEST PENDING INTERRUPTION.
func (c *CPU) tpi(a uint32, b int) {
	c.privileged()
	if a&3 != 0 {
		c.program(pgmSpecification)
	}
	x := c.M.CSS.pendingInterrupt(c.CR[6])
	if x == nil {
		c.PSW.CC = 0
		return
	}
	sid, parm := x.interruptCode()
	if a == 0 {
		c.setLowWord(0xb8, sid)
		c.setLowWord(0xbc, parm)
	} else {
		c.storeWord(a, b, sid)
		c.storeWord(a+4, b, parm)
	}
	// The interruption is cleared but status remains pending for TSCH.
	x.irq = false
	c.PSW.CC = 1
}

// stcrw: STORE CHANNEL REPORT WORD.
func (c *CPU) stcrw(a uint32, b int) {
	c.privileged()
	if a&3 != 0 {
		c.program(pgmSpecification)
	}
	css := c.M.CSS
	if len(css.crw) == 0 {
		c.storeWord(a, b, 0)
		c.PSW.CC = 1
		return
	}
	c.storeWord(a, b, css.crw[0])
	css.crw = css.crw[1:]
	c.PSW.CC = 0
}

// ---- Channel program execution ----

type ccw struct {
	cmd   byte
	flags byte
	count uint16
	addr  uint32
}

const (
	ccwCD   = 0x80
	ccwCC   = 0x40
	ccwSLI  = 0x20
	ccwSkip = 0x10
	ccwPCI  = 0x08
	ccwIDA  = 0x04
	ccwS    = 0x02
)

func (s *ChannelSubsystem) fetchCCW(addr uint32, fmt1 bool) (ccw, bool) {
	m := s.m.S
	if addr&7 != 0 || !m.valid(addr, 8) {
		return ccw{}, false
	}
	b := m.Mem[addr:]
	if fmt1 {
		return ccw{cmd: b[0], flags: b[1], count: be.Uint16(b[2:]), addr: be.Uint32(b[4:]) & 0x7fffffff}, b[4]&0x80 == 0
	}
	return ccw{cmd: b[0], flags: b[4], count: be.Uint16(b[6:]), addr: be.Uint32(b[0:]) & 0x00ffffff}, true
}

type segment struct {
	addr, n uint32
	skip    bool // the CCW suppresses transfer to storage
}

// segments resolves a CCW's data area, including IDAW lists.
func (s *ChannelSubsystem) segments(w ccw) ([]segment, bool) {
	if w.count == 0 {
		return nil, true
	}
	if w.flags&ccwIDA == 0 {
		return []segment{{addr: w.addr, n: uint32(w.count)}}, true
	}
	var out []segment
	left := uint32(w.count)
	list := w.addr
	if list&3 != 0 {
		return nil, false
	}
	first := true
	for left > 0 {
		if !s.m.S.valid(list, 4) {
			return nil, false
		}
		a := be.Uint32(s.m.S.Mem[list:]) & 0x7fffffff
		list += 4
		var n uint32
		if first {
			n = 0x800 - a&0x7ff
		} else {
			if a&0x7ff != 0 {
				return nil, false
			}
			n = 0x800
		}
		first = false
		if n > left {
			n = left
		}
		out = append(out, segment{addr: a, n: n})
		left -= n
	}
	return out, true
}

func cmdIsRead(cmd byte) bool {
	switch {
	case cmd&3 == 2: // read
		return true
	case cmd&0xf == 4: // sense
		return true
	case cmd&0xf == 0xc: // read backward
		return true
	}
	return false
}

// start executes a channel program to completion and makes status pending.
func (s *ChannelSubsystem) start(x *Subchannel, addr uint32, orb uint32) {
	fmt1 := orbFormat1(orb)
	if ce, ok := x.dev.(ChainEnd); ok {
		ce.StartChain()
		defer ce.EndChain()
	}
	x.ac = acSubchActive | acDeviceActive
	x.schStatus, x.devStatus, x.residual = 0, 0, 0
	s.trace = s.trace[:0]
	s.run(x, addr, fmt1, orb, x.key)
	if x.blocked {
		return
	}
	s.finish(x, orb, addr)
}

// finish makes the status of a completed channel program pending.
func (s *ChannelSubsystem) finish(x *Subchannel, orb, addr uint32) {
	if s.m.TraceIO && !s.m.TraceIOSkip[x.devno] {
		s.m.event("io", s.m.CPUs[0], fmt.Sprintf("dev %04X orb %08X ccw %08X cmds %s -> dev %02X sch %02X ccwaddr %08X resid %d", x.devno, orb, addr, s.traceString(), x.devStatus, x.schStatus, x.ccwaddr, x.residual))
	}
	x.ac = 0
	x.sc = scPrimary | scSecondary
	if x.devStatus&(usUnitCheck|usUnitExcept) != 0 || x.schStatus&^scsPCI != 0 {
		// Status that ended the chain abnormally is alert status.
		x.sc |= scAlert
	}
	x.pending = true
	x.irq = true
}

// Resume continues a channel program waiting for its device. It reports
// whether one was waiting.
func (s *ChannelSubsystem) Resume(devno uint16) bool {
	x := s.bydev[devno]
	if x == nil || !x.blocked {
		return false
	}
	s.resume(x)
	return true
}

// Waiting reports whether the device's channel program is blocked waiting
// for operator input.
func (s *ChannelSubsystem) Waiting(devno uint16) bool {
	x := s.bydev[devno]
	return x != nil && x.blocked
}

// resume continues a waiting channel program at its next CCW.
func (s *ChannelSubsystem) resume(x *Subchannel) {
	x.blocked, x.pciWait = false, false
	s.trace = s.trace[:0]
	s.run(x, x.blockAddr, x.blockFmt1, 0, x.key)
	if x.blocked {
		return
	}
	if ce, ok := x.dev.(ChainEnd); ok {
		ce.EndChain()
	}
	if s.m.TraceIO && !s.m.TraceIOSkip[x.devno] {
		s.m.event("io", nil, fmt.Sprintf("resume %04X cmds %s -> dev %02X ch %02X ccw %06X resid %d", x.devno, s.traceString(), x.devStatus, x.schStatus, x.ccwaddr, x.residual))
	}
	if x.pciIRQ { // a PCI interruption not taken merges into the final status
		x.pciIRQ = false
		x.schStatus |= scsPCI
	}
	if s.m.S370 {
		x.pending, x.irq = true, true
		return
	}
	s.finish(x, 0, x.blockAddr)
}

// tickPCI resumes channel programs paused after a PCI once the program has
// had time to act on the interruption: a few thousand instructions after it
// was taken, at once when every CPU waits (idle), or after a long delay
// when the interruption stays masked.
func (s *ChannelSubsystem) tickPCI(idle bool) bool {
	now := s.m.CPUs[0].Instructions
	resumed := false
	for _, x := range s.subs {
		if !x.pciWait {
			continue
		}
		taken := !x.pciIRQ
		if !s.m.S370 {
			taken = !x.pending
		}
		if idle && taken || taken && now-x.pciAt >= 4000 || now-x.pciAt >= 200000 {
			s.resume(x)
			resumed = true
		}
	}
	return resumed
}

// run executes CCWs and fills the subchannel's status fields.
func (s *ChannelSubsystem) run(x *Subchannel, addr uint32, fmt1 bool, orb uint32, key byte) {
	mem := s.m.S
	for steps := 0; ; steps++ {
		if steps > 1<<20 {
			// A channel program that never ends (for example a search
			// loop that cannot complete) is ended with an interface
			// control check so the emulator does not hang.
			s.m.event("io", nil, fmt.Sprintf("dev %04X: channel program exceeded %d CCWs at %08X", x.devno, steps, addr))
			x.ccwaddr = addr + 8
			x.schStatus = scsIFCC
			return
		}
		w, ok := s.fetchCCW(addr, fmt1)
		if !ok {
			x.ccwaddr = addr + 8
			x.schStatus = scsProgramCheck
			x.devStatus = 0
			return
		}
		if w.cmd&0xf == 8 { // TIC
			if w.addr&7 != 0 {
				x.ccwaddr = addr + 8
				x.schStatus = scsProgramCheck
				return
			}
			addr = w.addr
			continue
		}
		if !fmt1 && w.cmd == 0 || fmt1 && w.cmd == 0 {
			x.ccwaddr = addr + 8
			x.schStatus = scsProgramCheck
			return
		}
		if w.count == 0 && !fmt1 {
			x.ccwaddr = addr + 8
			x.schStatus = scsProgramCheck
			return
		}
		// Gather data-chained CCWs.
		cur := addr
		chain := []ccw{w}
		addrs := []uint32{addr}
		for chain[len(chain)-1].flags&ccwCD != 0 {
			cur += 8
			nw, ok := s.fetchCCW(cur, fmt1)
			if !ok {
				x.ccwaddr = cur + 8
				x.schStatus = scsProgramCheck
				return
			}
			if nw.cmd&0xf == 8 {
				cur = nw.addr - 8
				continue
			}
			nw.cmd = w.cmd
			chain = append(chain, nw)
			addrs = append(addrs, cur)
		}
		last := chain[len(chain)-1]
		var segs []segment
		total := uint32(0)
		for _, cw := range chain {
			sg, ok := s.segments(cw)
			if !ok {
				x.ccwaddr = cur + 8
				x.schStatus = scsProgramCheck
				return
			}
			for _, g := range sg {
				if !mem.valid(g.addr, g.n) {
					x.ccwaddr = cur + 8
					x.schStatus = scsProgramCheck
					x.devStatus = 0
					return
				}
			}
			if cw.flags&ccwSkip != 0 {
				for i := range sg {
					sg[i].skip = true
				}
			}
			segs = append(segs, sg...)
			total += uint32(cw.count)
		}
		read := cmdIsRead(w.cmd)
		var in []byte
		if !read && total > 0 {
			in = make([]byte, 0, total)
			for _, g := range segs {
				in = append(in, mem.Mem[g.addr:g.addr+g.n]...)
			}
		}
		chained := last.flags&ccwCC != 0
		if bd, ok := x.dev.(Blocking); ok && bd.Blocked(w.cmd) {
			x.blocked, x.blockAddr, x.blockFmt1 = true, addr, fmt1
			return
		}
		out, used, status := x.dev.Exec(w.cmd, in, chained)
		if s.m.TraceIO {
			// Keep the last 64 commands: the end of a long chain is
			// where it fails.
			if len(s.trace) >= 64 {
				s.trace = append(s.trace[:0], s.trace[1:]...)
			}
			s.trace = append(s.trace, ioTrace{w.cmd, last.flags, total, status, in, out})
		}
		var moved uint32
		if read {
			moved = uint32(len(out))
			if moved > total {
				moved = total
			}
			off := uint32(0)
			for _, g := range segs {
				if off >= moved {
					break
				}
				n := g.n
				if off+n > moved {
					n = moved - off
				}
				if !g.skip && !s.storeKeyed(g.addr, out[off:off+n], key) {
					x.ccwaddr = cur + 8
					x.schStatus = scsProtection
					x.devStatus = 0
					return
				}
				off += n
			}
		} else {
			moved = uint32(used)
		}
		x.ccwaddr = cur + 8
		x.residual = uint16(total - moved)
		// Within a data chain, the CSW names the CCW where the transfer
		// stopped and that CCW's own residual count.
		if len(chain) > 1 && moved < total {
			rem := moved
			for i, cw := range chain {
				if rem < uint32(cw.count) || i == len(chain)-1 {
					x.ccwaddr = addrs[i] + 8
					x.residual = uint16(uint32(cw.count) - rem)
					last = cw
					break
				}
				rem -= uint32(cw.count)
			}
		}
		x.devStatus = status
		incorrect := false
		if read && uint32(len(out)) != total && status&(usUnitCheck|usUnitExcept) == 0 {
			incorrect = true
		}
		if !read && uint32(used) != total && status&(usUnitCheck|usUnitExcept) == 0 {
			incorrect = true
			if used == 0 && w.cmd&3 == 3 && chained {
				incorrect = false // immediate command with chaining
			}
		}
		// A PCI flag takes effect when its CCW takes control, so the
		// condition is part of the final status however the CCW ends.
		pci := false
		for _, cw := range chain {
			pci = pci || cw.flags&ccwPCI != 0
		}
		if incorrect && last.flags&ccwSLI == 0 {
			x.schStatus = scsIncorrectLen
			if pci {
				x.schStatus |= scsPCI
			}
			return
		}
		if status&(usUnitCheck|usUnitExcept|usAttention) != 0 || status&(usCE|usDE) != usCE|usDE {
			if pci {
				x.schStatus |= scsPCI
			}
			return
		}
		if !chained {
			if pci {
				x.schStatus |= scsPCI
			}
			return
		}
		x.devStatus = 0
		addr = cur + 8
		if status&usSM != 0 {
			addr += 8
		}
		if pci {
			// Pause so the program can act on the interruption (for
			// example extend or end the chain) before the channel
			// fetches the next CCW.
			x.blocked, x.blockAddr, x.blockFmt1 = true, addr, fmt1
			x.pciWait = true
			x.pciAt = s.m.CPUs[0].Instructions
			if s.m.S370 {
				x.pciIRQ = true
			} else if !x.pending {
				// Intermediate status: the subchannel stays active.
				x.sc = scIntermediate
				x.schStatus |= scsPCI
				x.ccwaddr = addr
				x.devStatus = 0
				x.pending, x.irq = true, true
			}
			return
		}
	}
}

// storeKeyed writes channel data to absolute storage with key protection.
func (s *ChannelSubsystem) storeKeyed(a uint32, data []byte, key byte) bool {
	m := s.m.S
	block := uint32(1) << m.KeyShift
	for off := uint32(0); off < uint32(len(data)); {
		k := m.key(a + off)
		if key != 0 && *k>>4 != key {
			return false
		}
		n := block - (a+off)&(block-1)
		if n > uint32(len(data))-off {
			n = uint32(len(data)) - off
		}
		copy(m.Mem[a+off:], data[off:off+n])
		*k |= keyRef | keyChg
		for _, c := range s.m.CPUs {
			c.icache.invalidatePage(a + off)
		}
		off += n
	}
	return true
}

// iplChannelProgram runs the IPL channel program starting at location 0.
func (s *ChannelSubsystem) iplChannelProgram(x *Subchannel) error {
	if ce, ok := x.dev.(ChainEnd); ok {
		ce.StartChain()
		defer ce.EndChain()
	}
	x.clearStatus()
	s.run(x, 0, false, 0, 0)
	if x.schStatus != 0 || x.devStatus&(usUnitCheck|usUnitExcept) != 0 {
		return fmt.Errorf("ipl: channel program failed: device status %02X subchannel status %02X at CCW %06X", x.devStatus, x.schStatus, x.ccwaddr)
	}
	x.clearStatus()
	return nil
}
