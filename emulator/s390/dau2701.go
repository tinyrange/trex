package s390

import (
	"bytes"
	"fmt"
	"time"
)

const (
	rkmSelectTime = 2 * time.Microsecond
	rkmByteTime   = 15 * time.Microsecond // Design Data chapter 7, 66.6 kHz.
)

// The 9020 DAU has five RKM addresses sharing a diagnostic register and
// sense. Its diagnostic commands work with the external RKMs disconnected
// (A27-2734-2, appendix K).
type dau2701 struct {
	css             *ChannelSubsystem
	base            uint16
	peer            uint16
	paired          bool
	owner           byte // 0 neutral, 1 primary, 2 secondary
	register, sense byte
	attention       byte
	cuEndWanted     bool
	configuration   byte
	queuedConfig    byte
	configPending   bool
	configUnit      int
}

// dau2701Port is one of the five RKM addresses decoded by the DAU.
type dau2701Port struct {
	dau  *dau2701
	addr uint16
	side byte
}

func (s *ChannelSubsystem) Attach2701(base uint16) error {
	return s.attach2701Unit(base, 0, false, 0)
}

func (s *ChannelSubsystem) attach2701Unit(base, peer uint16, paired bool, unit int) error {
	if unit < 0 || unit > len(s.dauUnits9020) || unit != 0 && (!s.m.cfg.Model9020E || s.dauUnits9020[unit-1] != nil) {
		return fmt.Errorf("2701 configuration interface requires a free DAU unit on a 9020E")
	}
	bases := []uint16{base}
	if paired {
		if base == peer || byte(base) != byte(peer) {
			return fmt.Errorf("2701 two-processor interfaces require different channels with the same unit address")
		}
		bases = append(bases, peer)
	}
	for _, cuu := range bases {
		if !s.m.Model9020 || cuu > 0xbf8 || cuu&7 != 0 {
			return fmt.Errorf("2701 requires a 9020 and a DAU base address divisible by eight")
		}
		for addr := cuu + 1; addr <= cuu+5; addr++ {
			if s.bydev[addr] != nil {
				return fmt.Errorf("2701 port %04X already attached", addr)
			}
		}
	}
	d := &dau2701{css: s, base: base, peer: peer, paired: paired, configUnit: unit}
	for i, cuu := range bases {
		for addr := cuu + 1; addr <= cuu+5; addr++ {
			if _, err := s.Attach(addr, &dau2701Port{dau: d, addr: addr, side: byte(i + 1)}); err != nil {
				return err
			}
		}
	}
	if unit != 0 {
		s.dauUnits9020[unit-1] = d
	}
	return nil
}

func (p *dau2701Port) selected() bool {
	if p.dau.configUnit != 0 {
		return p.side == p.dau.configuredSide()
	}
	return p.dau.owner == 0 || p.dau.owner == p.side
}

func (d *dau2701) configuredSide() byte {
	switch d.configuration & 0xc0 {
	case 0x80:
		return 1
	case 0x40:
		if d.paired {
			return 2
		}
	}
	return 0
}

// The console's configuration strobe is accepted independently of the
// IOCE operation. The two-processor switch changes once that path is idle.
func (d *dau2701) setConfiguration(value byte) {
	d.queuedConfig = value
	d.configPending = true
	d.applyConfiguration()
}

func (d *dau2701) applyConfiguration() {
	if !d.configPending {
		return
	}
	if side := d.configuredSide(); side != 0 {
		base := d.baseFor(side)
		for address := base + 1; address <= base+5; address++ {
			x := d.css.bydev[address]
			if x.working() || x.pending || x.resumeAt != 0 || x.deAt != 0 {
				return
			}
		}
	}
	if d.queuedConfig&1 != 0 {
		d.reset()
	}
	d.configuration = d.queuedConfig & 0xf0
	d.configPending = false
}

func (d *dau2701) baseFor(side byte) uint16 {
	if side == 2 {
		return d.peer
	}
	return d.base
}

func (p *dau2701Port) SenseID() []byte { return nil }

func (p *dau2701Port) Reset() {
	p.dau.reset()
}

func (d *dau2701) reset() {
	d.register, d.sense, d.attention = 0, 0, 0
	d.owner = 0
	d.cuEndWanted = false
}

func (p *dau2701Port) Exec(cmd byte, data []byte, chained bool) ([]byte, int, byte) {
	return p.exec(cmd, data, &ccwOp{Total: 1}, false)
}

func (p *dau2701Port) exec(cmd byte, data []byte, op *ccwOp, timed bool) ([]byte, int, byte) {
	d := p.dau
	count := int(op.Total)
	if d.paired {
		// Address selection of a neutral switch seizes the interface.
		// Release passes the command but leaves the switch neutral.
		if cmd == 0xd4 {
			d.owner = 0
		} else {
			d.owner = p.side
		}
	}
	switch cmd {
	case 0x03, 0xd4, 0xf4:
		return nil, 0, usCE | usDE
	case 0x04:
		return []byte{d.sense}, 0, usCE | usDE
	case 0x09, 0x29:
		d.sense = 0
		if len(data) > 0 {
			d.register = data[len(data)-1]
		}
		if cmd == 0x29 {
			d.attention = 0x1f &^ (1 << (p.addr - d.baseFor(p.side) - 1))
			return nil, len(data), usCE | usDE | usAttention | usSM | usUnitExcept
		}
		return nil, len(data), usCE | usDE
	case 0x0a:
		return bytes.Repeat([]byte{d.register}, count), 0, usCE | usDE
	}
	if formatted, ok := formatRKMCommand(cmd); ok {
		d.register = formatted
		if rkm := p.connectedRKM(); rkm != nil {
			if rkm.advanceRKMOperator(d.css.m.tod) {
				d.css.presentRCUAttention9020()
			}
			bus := p.otherRKMBus()
			switch {
			case formatted == 0x08:
				d.sense = 0
				if timed {
					op.RKMOrder = formatted
					return nil, 0, usCE | usDE
				}
				return nil, 0, p.disconnectRKM()
			case formatted >= 0x80 && bus != nil:
				// Appendix K defines overlapping non-status orders as
				// procedural errors. The existing transfer retains the bus.
				rkm.raiseStatus(0, 0x04)
				d.css.presentRCUAttention9020()
				d.sense = 0x01
				return nil, 0, usCE | usDE | usUnitCheck
			case timed && rkmWriteOrder(formatted):
				op.RKMOrder, op.RKMOutput = formatted, data
				d.sense = 0
				return nil, len(data), usCE | usDE
			case timed && rkmReadOrder(formatted):
				op.RKMOrder = formatted
				d.sense = 0
				return make([]byte, count), 0, usCE | usDE
			}
			if used, handled := rkm.prepareRKMOrder(formatted, data, &op.RKMOperator); handled {
				d.sense = 0
				if timed {
					op.RKMOrder = formatted
				} else if op.RKMOperator.Order != 0 {
					status := p.startRKMOrder(op.RKMOperator)
					d.css.reschedule()
					return nil, used, status
				}
				return nil, used, usCE | usDE
			}
			if out, used, handled := rkm.execRKM(formatted, data, count); handled {
				if formatted == 0 && bus != nil {
					out[0] |= 0x80
				}
				if timed && formatted >= 0x80 {
					op.RKMOrder = formatted
				}
				d.sense = 0
				return out, used, usCE | usDE
			}
		}
		d.sense = 0x01 // no response from the disconnected RKM
		return nil, 0, usCE | usDE | usUnitCheck
	}
	d.sense = 0x80
	return nil, 0, usUnitCheck
}

func (p *dau2701Port) rkmNumber() uint16 { return p.addr - p.dau.baseFor(p.side) }

func (p *dau2701Port) otherRKMBus() *Subchannel {
	for _, d := range p.dau.css.dauUnits9020 {
		if d == nil || d == p.dau || d.configuredSide() == 0 {
			continue
		}
		x := d.css.bydev[d.baseFor(d.configuredSide())+p.rkmNumber()]
		if x.op != nil && x.op.RKMOrder >= 0x80 && x.finishAt != 0 {
			return x
		}
	}
	return nil
}

func (p *dau2701Port) disconnectRKM() byte {
	if p.connectedRKM() == nil {
		p.dau.sense = 0x01
		return usCE | usDE | usUnitCheck
	}
	if bus := p.otherRKMBus(); bus != nil {
		s := p.dau.css
		if at := bus.nextRKMBusByte(); at != 0 && at <= s.m.tod {
			s.advanceRKMBus(bus, s.m.tod)
		}
		if bus.op != nil && !bus.op.OutputOverrun {
			s.stopRKMBus(bus)
		}
	}
	return usCE | usDE
}

func (x *Subchannel) nextRKMBusByte() uint64 {
	op := x.op
	if op == nil || x.finishAt == 0 || op.Err != 0 || op.OutputOverrun {
		return 0
	}
	var moved uint32
	switch {
	case rkmReadOrder(op.RKMOrder) && op.ReadStored < uint32(len(op.Out)):
		moved = op.ReadStored
	case rkmWriteOrder(op.RKMOrder) && op.OutputFetched < uint32(op.Used):
		moved = op.OutputFetched
	default:
		return 0
	}
	return x.finishAt - x.endCE + durationTOD(rkmSelectTime+time.Duration(moved+1)*rkmByteTime)
}

func (s *ChannelSubsystem) advanceRKMBus(x *Subchannel, now uint64) {
	op, p := x.op, x.dev.(*dau2701Port)
	e := p.connectedRKM()
	if e == nil {
		p.dau.sense = 0x01
		op.Status = usCE | usDE | usUnitCheck
		s.stopRKMBus(x)
		return
	}
	for at := x.nextRKMBusByte(); at != 0 && at <= now; at = x.nextRKMBusByte() {
		if e.advanceRKMOperator(at) {
			s.presentRCUAttention9020()
		}
		if rkmReadOrder(op.RKMOrder) {
			idx := op.ReadStored
			op.Out[idx] = e.RKM.readRKMByte(op.RKMOrder)
			if op.InputLimit != 0 && idx >= op.InputLimit {
				op.Err = scsProgramCheck
			} else {
				var machineCheck bool
				op.Err, machineCheck = s.storeCCWInput(x, op, idx+1)
				if machineCheck {
					s.interruptRead9020(x)
					return
				}
				if op.Err == 0 && op.ReadStored == idx {
					op.Err = scsProgramCheck
				}
			}
			if op.Err != 0 {
				s.stopRKMBus(x)
				return
			}
			e.RKM.advanceRKMAddress()
			continue
		}
		idx := op.OutputFetched
		check, machineCheck := s.fetchCCWOutput9020(x, idx+1)
		if machineCheck {
			s.interruptOutput9020(x)
			return
		}
		if check != 0 {
			op.Err = check
			s.stopRKMBus(x)
			return
		}
		e.RKM.writeRKMByte(op.RKMOrder, op.RKMOutput[idx])
	}
}

// The DAU's Disconnect signal ends the bus exchange. Only an accepted
// complete operand can launch a separate RKM data operator.
func (s *ChannelSubsystem) stopRKMBus(x *Subchannel) {
	op := x.op
	switch {
	case rkmReadOrder(op.RKMOrder):
		op.Out = op.Out[:op.ReadStored]
	case rkmWriteOrder(op.RKMOrder):
		op.Used = int(op.OutputFetched)
	default:
		elapsed := s.m.tod - (x.finishAt - x.endCE)
		selection := durationTOD(rkmSelectTime)
		moved := int((elapsed - min(elapsed, selection)) / durationTOD(rkmByteTime))
		op.Used = min(op.Used, moved)
		op.Out = op.Out[:min(len(op.Out), moved)]
	}
	op.RKMOperator = rkmOperator9020E{}
	op.Chained, op.Halted = false, true
	s.transferEnd(x)
}

// Deferred RKM operations start after the complete operand arrives.
func (p *dau2701Port) startRKMOrder(op rkmOperator9020E) byte {
	e := p.connectedRKM()
	if e == nil {
		p.dau.sense = 0x01
		return usCE | usDE | usUnitCheck
	}
	if e.RKM.applyRKMOperand(op) {
		return usCE | usDE
	}
	if op.Order == 0x80 {
		rkm := &e.RKM
		rkm.Queue, rkm.Polling, rkm.PollDAU = op.Target, true, p.dau.configUnit
		e.Status[0] &^= 0x01
		p.dau.css.schedulePendingRKMInput()
		return usCE | usDE
	}
	if op.Order == 0x84 {
		if rkm := &e.RKM; rkm.FetchAt == 0 {
			e.Status[0] &^= 0x02
			rkm.FetchAt = p.dau.css.m.tod + rkmConsoleCycle9020E
			rkm.FetchConsole, rkm.FetchDAU = byte(op.Target), p.dau.configUnit
			return usCE | usDE
		}
		e.raiseStatus(0, 0x04)
		p.dau.css.presentRCUAttention9020()
		return usCE | usDE
	}
	if e.RKM.Operator.Order != 0 {
		e.raiseStatus(0, 0x04)
		p.dau.css.presentRCUAttention9020()
		return usCE | usDE
	}
	op.Next = p.dau.css.m.tod + rkmOperatorCycle9020E
	e.RKM.Operator = op
	return usCE | usDE
}

func (p *dau2701Port) connectedRKM() *rcuEndpoint9020 {
	d := p.dau
	if d.configUnit == 0 || d.configuration&0x30 == 0 {
		return nil // State Zero ignores the external interfaces.
	}
	rkm := d.css.radarKeyboard9020E(p.rkmNumber())
	if rkm == nil || rkm.Stopped || rkm.InterfacesOff || rkm.Configuration[0]&(0x08>>(d.configUnit-1)) == 0 {
		return nil
	}
	return rkm
}

func (p *dau2701Port) CommandTiming(cmd byte, n int) (time.Duration, time.Duration) {
	switch cmd {
	case 0x03, 0xd4, 0xf4:
		return 0, 0
	case 0x09, 0x29, 0x0a, 0x04:
		return time.Duration(max(n, 1)) * 4 * time.Microsecond, 0
	default:
		return rkmSelectTime + time.Duration(n)*rkmByteTime, 0
	}
}

// formatRKMCommand maps channel commands to the order byte on the
// RKM interface (A27-2734-2, table K-II).
func formatRKMCommand(cmd byte) (byte, bool) {
	switch cmd {
	case 0x47:
		return 0x08, true // Disconnect
	case 0xc1, 0xe1:
		return 0x98 | (cmd&0x20)>>3, true // Write RKM
	case 0x81, 0xa1:
		return 0x90 | (cmd&0x20)>>3, true // Clear RKM Memory
	case 0x91, 0xb1:
		return 0x92 | (cmd&0x20)>>3, true // Blink Display
	case 0x21:
		return 0x84, true // Fetch Display Constants
	case 0x01:
		return 0x80, true // Load Queue Address
	case 0x61:
		return 0x8c, true // Move Data
	case 0x41:
		return 0x88, true // Special Move
	case 0xc2, 0xe2:
		return 0xd8 | (cmd&0x20)>>3, true // Read RKM
	case 0x02, 0x22:
		return 0xc0, true // Read Queue Address
	case 0x05, 0x25:
		return 0xa0 | (cmd&0x20)>>3, true // Load I/O Address
	case 0x85, 0xa5:
		return 0xb0 | (cmd&0x20)>>3, true // Keyboard Write
	case 0x06, 0x0e, 0x16:
		return (cmd - 0x06) >> 3, true // Read RKM status/error
	}
	if cmd&0x47 == 0x45 {
		return 0xa8 | (cmd&0x80)>>3 | (cmd>>3)&7, true // Bit Modify
	}
	return 0, false
}

func (p *dau2701Port) TestIOStatus() byte {
	d := p.dau
	base := d.baseFor(p.side)
	for addr := base + 1; addr <= base+5; addr++ {
		if addr != p.addr && d.css.bydev[addr].working() {
			d.cuEndWanted = true
			return usBusy | usSM
		}
	}
	return 0
}

func (s *ChannelSubsystem) rkmAttentionDAU(number uint16, preferred int) *dau2701 {
	var available *dau2701
	for _, d := range s.dauUnits9020 {
		if d == nil || d.configuredSide() == 0 {
			continue
		}
		x := s.bydev[d.baseFor(d.configuredSide())+number]
		if x.enabled && x.dev.(*dau2701Port).connectedRKM() != nil {
			if d.configUnit == preferred {
				return d
			}
			if available == nil {
				available = d
			}
		}
	}
	return available
}

func (s *ChannelSubsystem) notifyDAU9020E() {
	for _, d := range s.dauUnits9020 {
		if d != nil {
			d.notify()
		}
	}
}

func (d *dau2701) notify() {
	d.applyConfiguration()
	if d.attention == 0 && d.configUnit == 0 {
		return
	}
	side := d.owner
	if d.configUnit != 0 {
		side = d.configuredSide()
		if side == 0 {
			return
		}
	}
	base := d.baseFor(side)
	for i := uint16(0); i < 5; i++ {
		x := d.css.bydev[base+1+i]
		if x.working() || x.pending || x.resumeAt != 0 || x.deAt != 0 {
			return
		}
	}
	for i := uint16(0); i < 5; i++ {
		x := d.css.bydev[base+1+i]
		if bit := byte(1 << i); d.attention&bit != 0 {
			d.attention &^= bit
			x.presentDeviceStatus(usAttention | usSM | usUnitExcept)
			return
		}
		if e := x.dev.(*dau2701Port).connectedRKM(); e != nil && x.enabled {
			rkm := &e.RKM
			switch {
			case rkm.AttentionA && d.css.rkmAttentionDAU(i+1, rkm.FetchDAU) == d:
				rkm.AttentionA = false
				x.presentDeviceStatus(usAttention | usSM)
				return
			case rkm.AttentionB && d.css.rkmAttentionDAU(i+1, rkm.PollDAU) == d:
				rkm.AttentionB = false
				x.presentDeviceStatus(usAttention | usUnitExcept)
				return
			}
		}
	}
}

func (p *dau2701Port) snapshotKind() string { return "2701" }

func (p *dau2701Port) snapshot() ([]byte, error) {
	d := p.dau
	return encodeGob(dau2701Snap{Register: d.register, Sense: d.sense, Attention: d.attention, CUEndWanted: d.cuEndWanted,
		Paired: d.paired, Peer: d.peer, Owner: d.owner, Unit: d.configUnit, Configuration: d.configuration,
		QueuedConfig: d.queuedConfig, ConfigPending: d.configPending})
}

type dau2701Snap struct {
	Register, Sense, Attention  byte
	CUEndWanted                 bool
	Paired                      bool
	Peer                        uint16
	Owner                       byte
	Unit                        int
	Configuration, QueuedConfig byte
	ConfigPending               bool
}

func (p *dau2701Port) restore(data []byte, _ bool) error {
	var snap dau2701Snap
	if err := decodeGob(data, &snap); err != nil {
		return err
	}
	if p.dau.paired != snap.Paired || p.dau.peer != snap.Peer || p.dau.configUnit != snap.Unit {
		return fmt.Errorf("2701 interface configuration differs from checkpoint")
	}
	p.dau.register, p.dau.sense, p.dau.attention, p.dau.cuEndWanted = snap.Register, snap.Sense, snap.Attention, snap.CUEndWanted
	p.dau.owner = snap.Owner
	p.dau.configuration, p.dau.queuedConfig, p.dau.configPending = snap.Configuration, snap.QueuedConfig, snap.ConfigPending
	return nil
}
