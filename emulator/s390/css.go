package s390

import (
	"fmt"
	"sort"
	"time"
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
	scsPCI           = 0x80
	scsIncorrectLen  = 0x40
	scsProgramCheck  = 0x20
	scsProtection    = 0x10
	scsDataCheck     = 0x08
	scsControlCheck  = 0x04
	scsIFCC          = 0x02
	scsChainCheck    = 0x01
	scsStoppedSE9020 = scsProgramCheck | scsChainCheck
)

// Device is a channel-attached I/O device.
type Device interface {
	// SenseID returns the SENSE ID response.
	SenseID() []byte
	// Exec executes one channel command. For read-type commands the device
	// returns the data in transfer order (last byte first for read backward);
	// for write and control commands
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
	num            uint16
	devno          uint16
	dev            Device
	ce9020         uint16 // CE that started the current channel program
	controller9020 uint8  // One plus the control unit's selection-mask bit.
	intparm        uint32
	isc            byte
	enabled        bool
	lpm            byte
	mbi            uint16
	mm             byte
	limit          byte
	multip         bool
	timing         bool

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

	sense      []byte
	heldStatus byte

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

	// System/370 timed operation (devices implementing Timed); see chan370.go.
	timed        bool   // the device reports command timing
	endCE, endDE uint64 // last CCW: TOD units to channel end, then to device end
	ccws         int    // CCWs executed since START I/O
	resumeAt     uint64 // chain paused at blockAddr until this TOD (command chaining waits for device end)
	finishAt     uint64 // data transfer in progress: channel end at this TOD
	deAt         uint64 // device working after channel end: device end at this TOD
	deStatus     byte   // status presented with that device end
	cuBusyUntil  uint64 // control-unit work that outlasts device end
	cuEndWanted  bool   // a selection during the busy interval requests control-unit end
	endAtDE      bool   // the paused chain ends at device end (holdChannelEnd)
	devPending   bool   // the pending status is held by the device, not the subchannel
	op           *ccwOp // CCW whose transfer completes at finishAt
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
	rcus9020         [2]*rcu9020
	dauUnits9020     [2]*dau2701
	rcuEndpoints9020 [28]rcuEndpoint9020
	trace            []ioTrace
	m                *Machine
	subs             []*Subchannel
	bydev            map[uint16]*Subchannel
	crw              []uint32
	crwPend          bool
	ipl              bool   // running the IPL channel program, which is not timed
	next             uint64 // earliest System/370 timed transition, or zero
	mach             []byte // 9020 IOCE MACH storage, separate from CE main storage
	ioceATR          [3]channelATR9020
	ioceChecks9020   [3]ioceMachineCheck9020
}

type channelATR9020 struct {
	Mask   uint64
	Active bool
}

func (s *ChannelSubsystem) ioceAddresses(devno uint16) channelATR9020 {
	if n := devno >> 10; n < 3 {
		return s.ioceATR[n]
	}
	return channelATR9020{}
}

func (s *ChannelSubsystem) channelAddress(atr channelATR9020, addr uint32) uint32 {
	if atr.Active && !s.machAddress(addr) {
		addr = s.m.translateATR9020(atr.Mask, addr)
	}
	return s.ioceInterleave9020(addr).physical(addr)
}

// Map the data addresses when the CCW is accepted. Split a transfer that
// straddles an SE boundary, since adjacent ATR slots need not be adjacent
// in physical storage. Keep transfer order for READ BACKWARD.
func (s *ChannelSubsystem) channelSegments(atr channelATR9020, sg []segment, backward bool) []segment {
	if !atr.Active && !s.m.interleavingDefeated9020() {
		return sg
	}
	size := s.m.storageElementSize9020()
	var out []segment
	for _, g := range sg {
		if s.machAddress(g.addr) {
			out = append(out, g)
			continue
		}
		for g.n > 0 {
			physical := g.addr
			if atr.Active {
				physical = s.m.translateATR9020(atr.Mask, g.addr)
			}
			mode := s.ioceInterleave9020(physical)
			span := size
			if mode != 0 {
				span = oddBank9020
			}
			var n uint32
			if backward {
				n = min(g.n, g.addr&(span-1)+1)
			} else {
				n = min(g.n, span-g.addr&(span-1))
			}
			out = append(out, segment{addr: mode.physical(physical), n: n, skip: g.skip})
			g.n -= n
			if backward {
				g.addr -= n
			} else {
				g.addr += n
			}
		}
	}
	return out
}

func newCSS(m *Machine) *ChannelSubsystem {
	s := &ChannelSubsystem{m: m, bydev: map[uint16]*Subchannel{}}
	if m.Model9020 {
		s.mach = make([]byte, 0x1f000)
	}
	return s
}

const machBase = 0x00c00000

func (s *ChannelSubsystem) machAddress(addr uint32) bool {
	return len(s.mach) != 0 && addr&0x00c00000 == machBase
}

// channelStorage resolves a 9020 channel address with bits 8 and 9 set
// to local IOCE storage. The last 4 KiB of the 128 KiB MACH store are
// reserved for multiplexor UCWs (A27-2734-2, appendix H).
func (s *ChannelSubsystem) channelStorage(addr, size uint32) []byte {
	if s.machAddress(addr) {
		offset := addr - machBase
		if uint64(offset)+uint64(size) <= uint64(len(s.mach)) {
			return s.mach[offset : offset+size]
		}
		return nil
	}
	if s.m.cfg.Model9020E && uint64(addr)+uint64(size) > displayBase9020E || !s.m.S.valid(addr, size) {
		return nil
	}
	return s.m.S.Mem[addr : addr+size]
}

// channelAvailable9020 reports the reachable prefix and the check at its
// boundary (9020D System FETOM, figure 8-7).
func (s *ChannelSubsystem) channelAvailable9020(devno uint16, addr, count uint32, backward bool) (uint32, byte) {
	if !s.m.Model9020 || s.machAddress(addr) {
		return count, 0
	}
	size := s.m.storageElementSize9020()
	var available uint32
	for available < count {
		if !s.ioceStorageConfigured9020(devno, addr) {
			return available, scsProgramCheck
		}
		if s.m.storageStopped9020(addr) {
			return available, scsStoppedSE9020
		}
		offset := addr % size
		if backward {
			n := min(count-available, offset+1)
			available += n
			addr -= n
		} else {
			n := min(count-available, size-offset)
			available += n
			addr += n
		}
	}
	return available, 0
}

func (s *ChannelSubsystem) checkAttachment(devno uint16) error {
	if _, ok := s.bydev[devno]; ok {
		return fmt.Errorf("device %04X already attached", devno)
	}
	if s.m.S370 && s.m.cfg.ByteMuxSubchannels != 0 && devno < 0x100 {
		switch {
		case devno < 8:
			first := 0x80 + devno*16
			for address := first; address < first+16; address++ {
				if s.bydev[address] != nil {
					return fmt.Errorf("device %04X conflicts with byte multiplexor address %04X", devno, address)
				}
			}
		case devno < 0x80:
			if int(devno) >= s.m.cfg.ByteMuxSubchannels {
				return fmt.Errorf("device %04X has no configured byte multiplexor subchannel", devno)
			}
		default:
			shared := (devno >> 4) & 7
			if s.bydev[shared] != nil {
				return fmt.Errorf("device %04X conflicts with byte multiplexor address %04X", devno, shared)
			}
		}
	}
	return nil
}

// Attach adds a device at a device number and returns its subchannel number.
func (s *ChannelSubsystem) Attach(devno uint16, d Device) (uint16, error) {
	if err := s.checkAttachment(devno); err != nil {
		return 0, err
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
	s.ioceATR = [3]channelATR9020{}
	s.ioceChecks9020 = [3]ioceMachineCheck9020{}
	for _, x := range s.subs {
		x.intparm, x.isc, x.enabled, x.mbi, x.mm, x.limit, x.multip, x.timing = 0, 0, s.m.S370, 0, 0, 0, false, false
		x.lpm = 0x80
		x.clearStatus()
		x.heldStatus = 0
		x.blocked, x.pciWait, x.pciIRQ = false, false, false
		x.resumeAt, x.finishAt, x.deAt, x.deStatus, x.devPending, x.endAtDE = 0, 0, 0, 0, false, false
		x.cuBusyUntil, x.cuEndWanted = 0, false
		x.op = nil
		x.ce9020 = 0
		x.dev.Reset()
	}
	s.crw = nil
	s.reschedule()
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

func (s *ChannelSubsystem) nextDeadline() (uint64, bool) { return s.next, s.next != 0 }

// Unsolicited presents an unsolicited status (for example attention) for a
// device. It reports false when the subchannel is busy or already pending.
func (s *ChannelSubsystem) Unsolicited(devno uint16, status byte) bool {
	x := s.bydev[devno]
	if x == nil || !x.enabled {
		return false
	}
	if x.pending || x.ac != 0 || x.blocked || x.finishAt != 0 {
		x.heldStatus |= status
		return false
	}
	x.devPending = true
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
		if status := x.heldStatus; status != 0 {
			x.heldStatus = 0
			c.M.CSS.Unsolicited(x.devno, status)
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

func (s *ChannelSubsystem) fetchCCW(devno uint16, addr uint32, fmt1 bool) (ccw, byte) {
	b := s.channelStorage(addr, 8)
	if addr&7 != 0 || b == nil || !s.ioceStorageConfigured9020(devno, addr) {
		return ccw{}, scsProgramCheck
	}
	if s.m.storageStopped9020(addr) {
		return ccw{}, scsStoppedSE9020
	}
	if fmt1 {
		if b[4]&0x80 != 0 {
			return ccw{}, scsProgramCheck
		}
		return ccw{cmd: b[0], flags: b[1], count: be.Uint16(b[2:]), addr: be.Uint32(b[4:]) & 0x7fffffff}, 0
	}
	return ccw{cmd: b[0], flags: b[4], count: be.Uint16(b[6:]), addr: be.Uint32(b[0:]) & 0x00ffffff}, 0
}

type segment struct {
	addr, n uint32
	skip    bool // the CCW suppresses transfer to storage
}

// IDAW errors found by segments.
const (
	idaOK    = iota
	idaFirst // the IDAW list address or the first IDAW is invalid
	idaLater // a later IDAW is invalid; found during the transfer
)

// segments resolves a CCW's data area, including IDAW lists.
func (s *ChannelSubsystem) segments(w ccw) ([]segment, int) {
	if w.count == 0 {
		return nil, idaOK
	}
	if w.flags&ccwIDA == 0 {
		return []segment{{addr: w.addr, n: uint32(w.count)}}, idaOK
	}
	var out []segment
	left := uint32(w.count)
	list := w.addr
	if list&3 != 0 {
		return nil, idaFirst
	}
	first := true
	backward := w.cmd&0xf == 0xc
	for left > 0 {
		bad := idaLater
		if first {
			bad = idaFirst
		}
		if !s.m.S.valid(list, 4) {
			return nil, bad
		}
		raw := be.Uint32(s.m.S.Mem[list:])
		if s.m.S370 && raw&0xff000000 != 0 {
			return nil, bad // System/370 IDAWs hold 24-bit addresses
		}
		a := raw & 0x7fffffff
		list += 4
		var n uint32
		if first {
			if backward {
				n = (a & 0x7ff) + 1
			} else {
				n = 0x800 - a&0x7ff
			}
		} else {
			last := uint32(0)
			if backward {
				last = 0x7ff
			}
			if a&0x7ff != last {
				return nil, bad
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
	return out, idaOK
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
	if x == nil || !x.blocked || x.resumeAt != 0 {
		return false
	}
	s.resume(x)
	return true
}

// Waiting reports whether the device's channel program is blocked waiting
// for operator input.
func (s *ChannelSubsystem) Waiting(devno uint16) bool {
	x := s.bydev[devno]
	return x != nil && x.blocked && x.resumeAt == 0 && !x.pciWait
}

// resume continues a waiting channel program at its next CCW.
func (s *ChannelSubsystem) resume(x *Subchannel) {
	x.blocked, x.pciWait = false, false
	if x.endAtDE {
		x.endAtDE = false
		s.programEnd(x)
		return
	}
	s.trace = s.trace[:0]
	if s.run(x, x.blockAddr, x.blockFmt1, 0, x.key) {
		return
	}
	if x.blocked || x.finishAt != 0 {
		return
	}
	s.programEnd(x)
}

// programEnd completes a channel program that waited or paused.
func (s *ChannelSubsystem) programEnd(x *Subchannel) {
	if ce, ok := x.dev.(ChainEnd); ok {
		ce.EndChain()
	}
	if p, ok := x.dev.(*dau2701Port); ok && p.dau.cuEndWanted {
		x.devStatus |= usCUE
		p.dau.cuEndWanted = false
	}
	if s.m.TraceIO && !s.m.TraceIOSkip[x.devno] {
		s.m.event("io", nil, fmt.Sprintf("resume %04X cmds %s -> dev %02X ch %02X ccw %06X resid %d", x.devno, s.traceString(), x.devStatus, x.schStatus, x.ccwaddr, x.residual))
	}
	if x.pciIRQ { // a PCI interruption not taken merges into the final status
		x.pciIRQ = false
		x.schStatus |= scsPCI
	}
	if s.m.S370 {
		s.complete370(x, false)
		return
	}
	s.finish(x, 0, x.blockAddr)
}

// tickPCI resumes channel programs paused after a PCI. An enabled program
// gets time to update subsequent CCWs after accepting the interruption.
// A masked System/360 channel keeps operating and can merge PCI with its
// final ending status before the program enables interruptions.
func (s *ChannelSubsystem) tickPCI(idle bool) bool {
	cpu := s.m.CPUs[0]
	now := cpu.Instructions
	resumed := false
	for _, x := range s.subs {
		if !x.pciWait {
			continue
		}
		taken := !x.pciIRQ
		if !s.m.S370 {
			taken = !x.pending
		}
		masked := s.m.S360 && !cpu.channelEnabled(x.devno>>8)
		if masked || idle && taken || taken && now-x.pciAt >= 4000 || now-x.pciAt >= 200000 {
			s.resume(x)
			resumed = true
		}
	}
	return resumed
}

// run executes CCWs and fills the subchannel's status fields.
func (s *ChannelSubsystem) run(x *Subchannel, addr uint32, fmt1 bool, orb uint32, key byte) (ioceCheck bool) {
	x.endCE, x.endDE = 0, 0
	atr := s.ioceAddresses(x.devno)
	// System/370 CCW rules (GA22-7000, chapter 12): a TIC may be neither
	// the first CCW nor follow another TIC, command codes with low bits
	// 0000 are invalid, and flag bits 38-39 must be zero.
	s370 := s.m.S370 && !s.ipl
	// Flag bits that must be zero: 38-39 on System/370, 37-39 (there is no
	// indirect data addressing) on System/360.
	zeroFlags := byte(ccwS | 1)
	if s.m.S360 {
		zeroFlags |= ccwIDA
	}
	prevTIC := false
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
		physical := s.channelAddress(atr, addr)
		w, fetchStatus := s.fetchCCW(x.devno, physical, fmt1)
		if fetchStatus != 0 {
			x.ccwaddr = addr + 8
			x.schStatus = fetchStatus
			x.devStatus = 0
			return
		}
		if s.m.Model9020 && !s.ipl && int(x.ce9020) < len(s.m.CPUs) &&
			s.checkIOCECCW9020(s.m.CPUs[x.ce9020], x.devno, physical, key) {
			if ce, ok := x.dev.(ChainEnd); ok {
				ce.EndChain()
			}
			x.ac = 0
			return true
		}
		if s370 && !s.fetchAllowed(physical, 8, key) {
			// The 9020 multiplexor reports program check for a
			// fetch-protected CCW. Its selector adds protection check
			// (D30542 and D31544, routines 57 and 61).
			x.ccwaddr = addr + 8
			x.schStatus = scsProtection
			if s.m.Model9020 {
				x.schStatus = scsProgramCheck
				if x.devno>>8 != 0 {
					x.schStatus |= scsProtection
				}
			}
			x.devStatus = 0
			return
		}
		s.latchIOCEStorage9020(x.devno, physical, 8, accFetch, key)
		if w.cmd&0xf == 8 { // TIC
			if w.addr&7 != 0 || s370 && (prevTIC || steps == 0 && x.ccws == 0) {
				x.ccwaddr = addr + 8
				x.schStatus = scsProgramCheck
				x.devStatus = 0
				return
			}
			prevTIC = true
			addr = w.addr
			continue
		}
		prevTIC = false
		if w.cmd == 0 || s370 && (w.cmd&0xf == 0 || w.flags&zeroFlags != 0) {
			x.ccwaddr = addr + 8
			x.schStatus = scsProgramCheck
			x.devStatus = 0
			return
		}
		if w.count == 0 && !fmt1 {
			x.ccwaddr = addr + 8
			x.schStatus = scsProgramCheck
			return
		}
		// Gather data-chained CCWs. On a System/370 channel with a timed
		// device, an invalid CCW in the data chain is found when the
		// channel fetches it, after the device has started: the transfer
		// up to it completes and the device then ends with program check.
		transferChecks := s.m.S370 && !s.ipl && isTimed(x.dev)
		cur := addr
		chain := []ccw{w}
		addrs := []uint32{addr}
		// The 9020 selector resolves these data chains on the device's
		// byte clock, so each CCW sees storage at its fetch point.
		liveDataChain := w.flags&ccwCD != 0 && (s.liveReadChain9020(x, w.cmd) || s.liveWriteChain9020(x, w.cmd))
		chainErr := uint32(0) // address of an invalid data-chained CCW, plus 8
		var chainStatus byte
		chainTIC := false
		for !liveDataChain && chain[len(chain)-1].flags&ccwCD != 0 {
			cur += 8
			physical = s.channelAddress(atr, cur)
			nw, fetchStatus := s.fetchCCW(x.devno, physical, fmt1)
			if fetchStatus == 0 && s.m.Model9020 && !s.ipl && int(x.ce9020) < len(s.m.CPUs) &&
				s.checkIOCECCW9020(s.m.CPUs[x.ce9020], x.devno, physical, key) {
				if ce, ok := x.dev.(ChainEnd); ok {
					ce.EndChain()
				}
				x.ac = 0
				return true
			}
			if fetchStatus == 0 && s370 && !s.fetchAllowed(physical, 8, key) {
				fetchStatus = scsProgramCheck
			}
			if fetchStatus == 0 {
				s.latchIOCEStorage9020(x.devno, physical, 8, accFetch, key)
			}
			if fetchStatus == 0 && nw.cmd&0xf == 8 {
				if nw.addr&7 != 0 || s370 && chainTIC {
					fetchStatus = scsProgramCheck
				} else {
					chainTIC = true
					cur = nw.addr - 8
					continue
				}
			}
			chainTIC = false
			if fetchStatus == 0 && s370 && nw.flags&zeroFlags != 0 {
				fetchStatus = scsProgramCheck
			}
			if fetchStatus != 0 {
				if transferChecks {
					chainErr, chainStatus = cur+8, fetchStatus
					break
				}
				x.ccwaddr = cur + 8
				x.schStatus = fetchStatus
				return
			}
			nw.cmd = w.cmd
			chain = append(chain, nw)
			addrs = append(addrs, cur)
		}
		last := chain[len(chain)-1]
		var segs []segment
		total := uint32(0)
		// On a System/370 channel with a timed device, data addresses and
		// protection are checked as the data is transferred: the device has
		// accepted the command and presents its ending status with the
		// program or protection check. Otherwise they are checked first.
		// An invalid first IDAW is always found before the device starts.
		var dataErr byte
		var inputLimit uint32
		read := cmdIsRead(w.cmd)
		backward := w.cmd&0xf == 0xc
		for _, cw := range chain {
			// With skip set on an input command, the data address (including
			// an IDAW list) is not used or checked.
			if cw.flags&ccwSkip != 0 && cmdIsRead(w.cmd) {
				segs = append(segs, segment{n: uint32(cw.count), skip: true})
				total += uint32(cw.count)
				continue
			}
			sg, ida := s.segments(cw)
			if ida != idaOK {
				if transferChecks && (ida == idaLater || len(segs) > 0) {
					dataErr = scsProgramCheck
					break
				}
				x.ccwaddr = cur + 8
				x.schStatus = scsProgramCheck
				return
			}
			valid := true
			sg = s.channelSegments(atr, sg, backward)
			for _, g := range sg {
				start := g.addr
				if backward {
					start -= g.n - 1
				}
				if g.addr == ^uint32(0) || backward && g.n > g.addr+1 || s.machAddress(start) != s.machAddress(g.addr) ||
					s.channelStorage(start, g.n) == nil {
					valid = false
				}
			}
			if !valid {
				disk, _ := x.dev.(*DASD3390)
				timedInput := transferChecks || disk != nil && disk.devType == 0x2314 && !s.ipl
				if timedInput && s.m.S360 && read && !atr.Active && len(sg) == 1 {
					g := sg[0]
					size := s.m.S.Size()
					if size < 1<<24 && g.addr < size && !s.machAddress(g.addr) {
						available := size - g.addr
						if backward {
							available = g.addr + 1
						}
						if g.n > available {
							// Use the installed storage up to the
							// first invalid address in transfer order.
							g.n = available
							inputLimit = total + available
							segs = append(segs, g)
							break
						}
					}
				}
				if transferChecks {
					dataErr = scsProgramCheck
					break
				}
				x.ccwaddr = cur + 8
				x.schStatus = scsProgramCheck
				x.devStatus = 0
				return
			}
			if cw.flags&ccwSkip != 0 {
				for i := range sg {
					sg[i].skip = true
				}
			}
			segs = append(segs, sg...)
			total += uint32(cw.count)
		}
		if dataErr != 0 || inputLimit != 0 {
			total = 0
			for _, cw := range chain {
				total += uint32(cw.count)
			}
			if inputLimit == 0 {
				segs = nil
			}
		}
		var in []byte
		var storageCheck byte
		tape, isTape := x.dev.(*Tape2401)
		disk, isDisk := x.dev.(*DASD3390)
		timedOutput9020 := s.m.Model9020 && !s.ipl &&
			(isTape && w.cmd == 0x01 || isDisk && disk.devType == 0x2314 && (w.cmd == 0x05 || w.cmd == 0x0d))
		_, isDAU := x.dev.(*dau2701Port)
		timedRKMWrite := transferChecks && isDAU && (w.cmd == 0xc1 || w.cmd == 0xe1)
		if !read && total > 0 && dataErr == 0 {
			if timedOutput9020 || timedRKMWrite {
				// These commands select the destination and set timing from
				// the count. The device reads the payload on its byte clock.
				in = make([]byte, total)
			} else {
				in = make([]byte, 0, total)
				for _, g := range segs {
					available, check := s.channelAvailable9020(x.devno, g.addr, g.n, false)
					if !s.ipl && len(s.m.storageBadKey9020) != 0 {
						block := uint32(1) << s.m.S.KeyShift
						for addr, end := g.addr, g.addr+available; addr < end; {
							n := min(end-addr, block-addr%block)
							if s.checkIOCEKey9020(x.ce9020, x.devno, addr, n, accFetch, key) {
								if ce, ok := x.dev.(ChainEnd); ok {
									ce.EndChain()
								}
								x.ac = 0
								return true
							}
							addr += n
						}
					}
					if transferChecks && !g.skip && available != 0 && !s.fetchAllowed(g.addr, available, key) {
						dataErr = scsProtection
						break
					}
					in = append(in, s.channelStorage(g.addr, available)...)
					if check != 0 {
						storageCheck, dataErr = check, check
						break
					}
				}
			}
		}
		chained := last.flags&ccwCC != 0
		if bd, ok := x.dev.(Blocking); ok && bd.Blocked(w.cmd) {
			x.blocked, x.blockAddr, x.blockFmt1 = true, addr, fmt1
			return
		}
		var out []byte
		var used int
		var status byte
		var diskWrite *diskWrite2314
		var diskCyl uint32
		op := &ccwOp{Cmd: w.cmd, Last: last, Chain: chain, Addrs: addrs, Segs: segs, Total: total, Cur: cur,
			Read: read, Chained: chained, Key: key, Fmt1: fmt1, Err: dataErr, InputLimit: inputLimit,
			ChainErr: chainErr, ChainStatus: chainStatus, Checked: transferChecks || inputLimit != 0}
		if storageCheck != 0 && len(in) == 0 {
			// The first fetch failed. No data was delivered to the device.
		} else if d, ok := x.dev.(*ctc9020Side); ok && !s.ipl {
			if d.selectCCW(x, op, in) {
				if s.m.TraceIO && !s.m.TraceIOSkip[x.devno] {
					s.m.event("io", nil, fmt.Sprintf("CTC %04X waiting for %04X cmd %02X ccw %06X", x.devno, d.peer.addr, op.Cmd, op.Cur))
				}
				return
			}
			out, used, status = op.Out, op.Used, op.Status
		} else if d, ok := x.dev.(*dau2701Port); ok {
			out, used, status = d.exec(w.cmd, in, op, transferChecks)
		} else if p, ok := x.dev.(*rcu9020Port); ok {
			out, used, status = p.Exec(w.cmd, in, chained)
			op.LengthOnException = w.cmd == 0x31 && p.rcu.state.Sense == 1
			if w.cmd == 0x67 && p.attentionPending() {
				// An attention generated by Control Test terminates the
				// chain after the initial CE/DE (D9051200 routine 06).
				op.Chained = false
			}
		} else if d, ok := x.dev.(*UnitRecord); ok && d.port != nil {
			out, used, status = d.exec2821(x, w.cmd, in, chained)
		} else if d, ok := x.dev.(*DASD3390); ok && d.devType == 0x2314 && s.m.S360 && !s.ipl {
			diskCyl = d.cyl
			if w.cmd == 0x05 || w.cmd == 0x0d {
				diskWrite = &diskWrite2314{}
			}
			out, used, status = d.exec(w.cmd, in, chained, diskWrite, s.m.Model9020)
		} else {
			if tape, ok := x.dev.(*Tape2401); ok && !tape.unloaded && !tape.manual {
				switch w.cmd {
				case 0x07:
					if tape.pos != 0 || tape.pastLoadPoint {
						tape.rewindDisconnect = s.m.tod + durationTOD(tape.rewindDisconnectTime())
					}
				case 0x0f:
					if tape.model2415 || tape.transportModel != 0 {
						travel := tape.rewindTravelTime(true)
						tape.unloadUntil = s.m.tod + durationTOD(travel)
						if s.m.TraceIO && !s.m.TraceIOSkip[x.devno] {
							s.m.event("io", nil, fmt.Sprintf("rewind unload %04X estimated travel %d us", x.devno, travel.Microseconds()))
						}
					}
				}
			}
			out, used, status = x.dev.Exec(w.cmd, in, chained)
		}
		if tape, ok := x.dev.(*Tape2401); ok && !s.ipl {
			s.setTapeMode(x, tape, w.cmd, status)
			if s.m.S360 {
				tape.scheduleMotion(s.m.tod, w.cmd)
			}
		}
		x.ccws++
		x.endCE, x.endDE = s.timing(x, w.cmd, min(len(out)+used, int(total)), status, diskCyl)
		switch x.dev.(type) {
		case *ctc9020Side:
			if status&usCE == 0 || status&usUnitExcept != 0 {
				x.endCE = 0 // initial unit status
			}
		case *dau2701Port, *rcu9020Port:
			if status == usUnitCheck {
				x.endCE = 0 // command rejected at selection
			}
		}
		if s.m.TraceIO {
			// Keep the last 64 commands: the end of a long chain is
			// where it fails.
			if len(s.trace) >= 64 {
				s.trace = append(s.trace[:0], s.trace[1:]...)
			}
			s.trace = append(s.trace, ioTrace{w.cmd, last.flags, total, status, in, out})
		}
		op.Out, op.Used, op.Status, op.DiskWrite = out, used, status, diskWrite
		if d, ok := x.dev.(*ctc9020Side); ok && d.control != 0 && status == usCE && chained && len(chain) == 1 && dataErr == 0 {
			x.blocked, x.blockAddr, x.blockFmt1 = true, cur+8, fmt1
			x.ac = acSubchActive | acDeviceActive
			return
		}
		if _, ok := x.dev.(*Tape2401); ok && w.cmd == 0x01 && status == usCE|usDE {
			op.TapeWrite = in
		}
		if dataErr != 0 && x.endCE == 0 {
			// The device accepted the command; the check ends it.
			x.endCE = durationTOD(10 * time.Microsecond)
		}
		if x.endCE > 0 {
			// The channel remains active until the timed transfer ends.
			x.op = op
			x.ac = acSubchActive | acDeviceActive
			x.finishAt = s.m.tod + x.endCE
			op.TimedOutput = timedOutput9020 && (len(op.TapeWrite) > 0 || op.DiskWrite != nil && len(op.DiskWrite.Fields) != 0)
			if op.TimedOutput && isTape && !tape.model2415 && op.Used > 0 {
				// The 2803 takes the first byte at selection, before motion.
				// A fault on this first fetch still reports channel status
				// asynchronously, as it would for an already stopped SE.
				check, machineCheck := s.fetchCCWOutput9020(x, 1)
				if check == 0 && !machineCheck && s.writeChainBoundary9020(x) == 1 {
					check, machineCheck = s.advanceOutput9020(x, s.m.tod)
				}
				if machineCheck {
					s.interruptOutput9020(x)
					return true
				}
				if check != 0 {
					op.Used, op.Err = 0, check
					if check == scsStoppedSE9020 {
						op.Status = 0
					}
					x.endCE = durationTOD(10 * time.Microsecond)
					x.finishAt = s.m.tod + x.endCE
				}
			}
			s.reschedule()
			return
		}
		next, cont, pci, machineCheck := s.endCCW(x, op)
		if machineCheck {
			x.op = op
			s.interruptRead9020(x)
			s.reschedule()
			return true
		}
		if !cont {
			s.holdChannelEnd(x, op)
			return
		}
		x.ccws++ // status from a later CCW is not initial status
		addr = next
		if x.endDE > 0 && !pci {
			// Command chaining proceeds at device end.
			s.pauseChain(x, addr, fmt1, x.endDE)
			return
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
func (s *ChannelSubsystem) storeKeyed(devno uint16, a uint32, data []byte, key byte) bool {
	if s.machAddress(a) {
		dst := s.channelStorage(a, uint32(len(data)))
		if dst == nil {
			return false
		}
		copy(dst, data)
		return true
	}
	m := s.m.S
	block := uint32(1) << m.KeyShift
	for off := uint32(0); off < uint32(len(data)); {
		k := m.key(a + off)
		if !s.m.storageKeyMatches(key, *k) {
			return false
		}
		n := block - (a+off)&(block-1)
		if n > uint32(len(data))-off {
			n = uint32(len(data)) - off
		}
		copy(m.Mem[a+off:], data[off:off+n])
		*k |= keyRef | keyChg
		s.latchIOCEStorage9020(devno, a+off, n, accStore, key)
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
	s.ipl = true
	s.run(x, 0, false, 0, 0)
	s.ipl = false
	if x.schStatus != 0 || x.devStatus&(usUnitCheck|usUnitExcept) != 0 {
		return fmt.Errorf("ipl: channel program failed: device status %02X subchannel status %02X at CCW %06X", x.devStatus, x.schStatus, x.ccwaddr)
	}
	x.clearStatus()
	return nil
}

// ccwOp is a CCW the device has executed whose data and status the channel
// has not yet completed. Fields are exported for checkpoints.
type ccwOp struct {
	Cmd                 byte
	Last                ccw
	Chain               []ccw
	Addrs               []uint32
	Segs                []segment
	Total, Cur          uint32
	ReadStored          uint32 // input bytes already delivered to storage or skipped
	OutputFetched       uint32 // output bytes already accepted by the device
	InputLimit          uint32 // first invalid input offset, zero if none after a valid prefix
	Out                 []byte
	TapeWrite           []byte           // tape output is recorded only as bytes are transferred
	DiskWrite           *diskWrite2314   // fields selected for a pending 2314 write
	RKMOrder            byte             // formatted order on the live RKM bus
	RKMOutput           []byte           // bytes fetched on the RKM bus clock
	RKMOperator         rkmOperator9020E // a deferred RKM order waiting for operand transfer
	TimedOutput         bool             // fetch output bytes on the device clock
	OutputOverrun       bool             // device finishing after the IOCE lost byte service
	Used                int
	Status              byte
	Read, Chained, Fmt1 bool
	Halted              bool
	LengthOnException   bool
	Key                 byte
	Err                 byte   // channel status of a check found during the transfer
	ChainErr            uint32 // an invalid data-chained CCW follows (its address plus 8)
	ChainStatus         byte   // channel status when a transfer reaches ChainErr
	Checked             bool   // checks are made during the transfer (see run)
}

// storeCCWInput delivers the newly arrived prefix of input. Data chaining
// and skip apply to the logical byte offset even across timed updates.
func (s *ChannelSubsystem) storeCCWInput(x *Subchannel, op *ccwOp, moved uint32) (channelCheck byte, machineCheck bool) {
	if op.InputLimit != 0 {
		moved = min(moved, op.InputLimit)
	}
	var off uint32
	for _, g := range op.Segs {
		if off >= moved {
			break
		}
		end := off + g.n
		lo, hi := max(off, op.ReadStored), min(end, moved)
		if lo < hi {
			if !g.skip {
				backward := op.Cmd&0xf == 0xc
				addr := g.addr + (lo - off)
				if backward {
					addr = g.addr - (lo - off)
				}
				available, check := s.channelAvailable9020(x.devno, addr, hi-lo, backward)
				limit := lo + available
				block := uint32(1) << s.m.S.KeyShift
				for i := lo; i < limit; {
					n := min(limit-i, block-addr%block)
					if backward {
						n = 1
					}
					if !s.ipl && s.checkIOCEKey9020(x.ce9020, x.devno, addr, n, accStore, op.Key) {
						return 0, true
					}
					if !s.storeKeyed(x.devno, addr, op.Out[i:i+n], op.Key) {
						return scsProtection, false
					}
					i += n
					op.ReadStored = i
					if backward {
						addr--
					} else {
						addr += n
					}
				}
				if check != 0 {
					return check, false
				}
			}
			op.ReadStored = hi
		}
		off = end
	}
	return 0, false
}

// endCCW stores a CCW's input data and sets the subchannel status. It
// returns the address of the next CCW and whether command chaining
// continues, and whether the CCW had the PCI flag.
func (s *ChannelSubsystem) endCCW(x *Subchannel, op *ccwOp) (next uint32, cont, pci, machineCheck bool) {
	last, chain, total, cur, out, used, status := op.Last, op.Chain, op.Total, op.Cur, op.Out, op.Used, op.Status
	if op.TimedOutput || rkmWriteOrder(op.RKMOrder) {
		used = min(used, int(op.OutputFetched))
	}
	// A PCI flag takes effect when its CCW takes control, so the
	// condition is part of the final status however the CCW ends.
	for _, cw := range chain {
		pci = pci || cw.flags&ccwPCI != 0
	}
	acceptedOutput := op.TimedOutput && used > 0 && (op.Err == scsProtection || op.Err == scsProgramCheck)
	acceptedRKM := op.RKMOrder >= 0x80 && (op.ReadStored != 0 || op.OutputFetched != 0)
	if op.Err != 0 && op.Err != scsStoppedSE9020 && !acceptedOutput && !acceptedRKM {
		// The device ends with its status when the check preceded transfer.
		x.ccwaddr, x.residual = op.Addrs[0]+8, uint16(chain[0].count)
		x.devStatus, x.schStatus = status, op.Err
		if pci {
			x.schStatus |= scsPCI
		}
		return 0, false, pci, false
	}
	if len(op.TapeWrite) > 0 && used > 0 {
		tape := x.dev.(*Tape2401)
		status |= tape.finishWrite(op.TapeWrite[:used])
	}
	if op.DiskWrite != nil && len(op.DiskWrite.Fields) != 0 {
		d := x.dev.(*DASD3390)
		if err := d.commitWrite2314(op.DiskWrite, used, op.Halted); err != nil {
			_, _, status = d.ioErr(err)
		}
	}
	if op.Err == 0 && !op.Read && used == 0 && op.Cmd&3 == 3 && len(chain) > 1 {
		// An immediate control command ends at initiation: no data is
		// transferred, so data chaining does not occur, and the CC flag is
		// ignored when CD is on (A22-6821-7 p. 104).
		x.ccwaddr, x.residual = op.Addrs[0]+8, chain[0].count
		x.devStatus = status
		if pci {
			x.schStatus |= scsPCI
		}
		return 0, false, pci, false
	}
	var moved uint32
	dataStatus := op.Err
	if op.Read {
		moved = min(uint32(len(out)), total)
		if op.InputLimit != 0 && moved > op.InputLimit {
			moved, dataStatus = op.InputLimit, scsProgramCheck
		}
		check, machineCheck := s.storeCCWInput(x, op, moved)
		if machineCheck {
			return 0, false, false, true
		}
		switch check {
		case scsStoppedSE9020, scsProgramCheck:
			moved, dataStatus = op.ReadStored, check
		case scsProtection:
			// With checks made during the transfer, the device has
			// started and ends with its own status.
			x.ccwaddr = cur + 8
			x.schStatus = scsProtection
			x.devStatus = 0
			if op.Checked {
				x.devStatus = status
			}
			return 0, false, pci, false
		}
	} else {
		// A device may report using more than the count: it wanted more
		// data than the CCW supplied (incorrect length, no residual).
		moved = min(uint32(used), total)
	}
	x.ccwaddr = cur + 8
	x.residual = uint16(total - moved)
	// Within a data chain, the CSW names the CCW where the transfer
	// stopped and that CCW's own residual count.
	if len(chain) > 1 && moved < total {
		rem := moved
		for i, cw := range chain {
			if rem < uint32(cw.count) || i == len(chain)-1 {
				x.ccwaddr = op.Addrs[i] + 8
				x.residual = uint16(uint32(cw.count) - rem)
				last = cw
				break
			}
			rem -= uint32(cw.count)
		}
	}
	x.devStatus = status
	if dataStatus != 0 {
		x.schStatus = dataStatus
		if pci {
			x.schStatus |= scsPCI
		}
		return 0, false, pci, false
	}
	if op.ChainErr != 0 && moved == total {
		// The count ran out and the next data-chained CCW is invalid.
		x.ccwaddr, x.residual = op.ChainErr, 0
		x.schStatus = scsProgramCheck | op.ChainStatus
		if pci {
			x.schStatus |= scsPCI
		}
		return 0, false, pci, false
	}
	incorrect := false
	checkLength := status&(usUnitCheck|usUnitExcept) == 0 || op.LengthOnException
	if _, ok := x.dev.(*ctc9020Side); ok && status&usCE == 0 {
		checkLength = false // the adapter did not accept the command
	}
	if d, ok := x.dev.(*DASD3390); ok && d.devType == 0x2314 && status&usCE != 0 {
		checkLength = checkLength || d.lengthOnCheck2314(op.Cmd)
	}
	if op.Read && uint32(len(out)) != total && checkLength {
		incorrect = true
	}
	if !op.Read && uint32(used) != total && checkLength {
		incorrect = true
		if used == 0 && op.Cmd&3 == 3 && status&(usUnitCheck|usUnitExcept) == 0 {
			// A control command that transfers no data executes as an
			// immediate operation: incorrect length is not indicated
			// (A22-6821-7 p. 108; GA22-7000 chapter 12).
			incorrect = false
		}
	}
	// The 2803's tape write has no device-side record length. The
	// channel count ending the write is therefore incorrect length.
	if _, ok := x.dev.(*Tape2401); ok && op.Cmd == 0x01 && status == usCE|usDE {
		incorrect = true
	}
	end := func() (uint32, bool, bool, bool) {
		if pci {
			x.schStatus |= scsPCI
		}
		if d, ok := x.dev.(*DASD3390); s.m.S370 && ok && d.devType == 0x2314 &&
			(d.formatErase || status == usCE|usDE && formatWrite2314(op.Cmd)) {
			// A terminal format write erases through the next index point.
			// This takes at most one revolution (GA26-3599-6).
			x.cuBusyUntil = s.m.tod + durationTOD(25*time.Millisecond)
			s.reschedule()
		}
		return 0, false, pci, false
	}
	suppressLength := last.flags&ccwSLI != 0 && (!s.m.S360 || last.flags&ccwCD == 0)
	if incorrect && !suppressLength {
		x.schStatus = scsIncorrectLen
		return end()
	}
	if status&(usUnitCheck|usUnitExcept|usAttention) != 0 || status&(usCE|usDE) != usCE|usDE || !op.Chained {
		return end()
	}
	x.devStatus = 0
	next = cur + 8
	if status&usSM != 0 {
		next += 8
	}
	return next, true, pci, false
}

// pauseChain suspends command chaining at addr for d TOD units.
func (s *ChannelSubsystem) pauseChain(x *Subchannel, addr uint32, fmt1 bool, d uint64) {
	x.blocked, x.blockAddr, x.blockFmt1 = true, addr, fmt1
	x.ac = acSubchActive | acDeviceActive
	x.resumeAt = s.m.tod + d
	s.reschedule()
}

// holdChannelEnd handles a command-chained CCW that ends the chain with unit
// check or unit exception arriving with a later device end (a carriage space
// sensing channel 9, a tape motion reaching a tape mark): the channel has
// accepted channel end while waiting to chain, so the program sees one
// interruption at device end, without channel end.
func (s *ChannelSubsystem) holdChannelEnd(x *Subchannel, op *ccwOp) {
	if !s.m.S370 || x.endDE == 0 || !op.Chained || x.blocked || x.finishAt != 0 ||
		x.devStatus&(usUnitCheck|usUnitExcept) == 0 || x.devStatus&(usCE|usDE) != usCE|usDE ||
		x.schStatus&^scsPCI != 0 {
		return
	}
	x.devStatus &^= usCE
	d := x.endDE
	x.endDE = 0
	x.endAtDE = true
	s.pauseChain(x, x.blockAddr, op.Fmt1, d)
}

func isTimed(d Device) bool { _, ok := d.(Timed); return ok }

// fetchAllowed reports whether the channel may fetch n bytes at a with the
// subchannel key: a nonzero key must match blocks that are fetch protected.
func (s *ChannelSubsystem) fetchAllowed(a, n uint32, key byte) bool {
	if key == 0 || s.machAddress(a) {
		return true
	}
	m := s.m.S
	block := uint32(1) << m.KeyShift
	for b := a &^ (block - 1); b < a+n; b += block {
		k := *m.key(b)
		if k&keyFetch != 0 && !s.m.storageKeyMatches(key, k) {
			return false
		}
	}
	return true
}
