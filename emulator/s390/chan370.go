package s390

import (
	"fmt"
	"time"
)

// System/370 channel timing.
//
// A device that implements Timed reports how long each command occupies the
// channel and the device. The channel then presents status as the
// architecture describes rather than at once:
//
//   - An immediate command (channel end in the initial status, such as tape
//     motion or a mode set) ends START I/O with condition code 1. Only the
//     status portion of the CSW is stored; no interruption condition is
//     generated. If device end is not part of that status the device stays
//     working and presents device end later as an interruption condition of
//     its own, with zero key, address and count in the CSW.
//   - A data transfer keeps the subchannel working (START I/O and TEST I/O
//     set condition code 2) until channel end, when the ending status becomes
//     pending in the subchannel.
//   - Command chaining proceeds at device end.
//   - While the device works after channel end, START I/O and TEST I/O store
//     busy status. Status held by the device is returned, with busy for START
//     I/O, and cleared by START I/O or TEST I/O; status pending in the
//     subchannel makes START I/O set condition code 2.
//
// Transitions are kept as TOD deadlines on the subchannel, so they follow
// the virtual clock, are reached by idle skipping, and are checkpointed.
// Devices without Timed keep synchronous completion.
// See System/370 Principles of Operation, GA22-7000, chapter 12.

// Timed is implemented by devices whose commands take time on a System/370
// channel. CommandTiming is called after Exec for the command just executed,
// with the number of bytes the device read or wrote. channelEnd is the time
// from initiation to channel end; zero means channel end is part of the
// initial status (an immediate command). deviceEnd is the further time until
// device end; status other than channel end is presented with device end.
type Timed interface {
	CommandTiming(cmd byte, n int) (channelEnd, deviceEnd time.Duration)
}

func durationTOD(d time.Duration) uint64 {
	if d <= 0 {
		return 0
	}
	return max(uint64(d)*todMicro/uint64(time.Microsecond), 1)
}

// timing returns a command's delays in TOD units.
func (s *ChannelSubsystem) timing(x *Subchannel, cmd byte, n int, status byte, diskCyl uint32) (uint64, uint64) {
	t, ok := x.dev.(Timed)
	x.timed = ok && s.m.S370
	if _, ok := x.dev.(*Console1052); ok && status == usUnitCheck {
		return 0, 0
	}
	if d, ok := x.dev.(*DASD3390); ok && d.devType == 0x2314 {
		if d.motorStopped && status == usUnitCheck {
			x.timed = true
			return 0, 0
		}
		if cmd == 0x03 {
			x.timed = s.m.S370
			return 0, 0
		}
		if s.m.S360 && !s.ipl {
			switch {
			case n > 0 && dataTransfer2314(cmd):
				x.timed = true
				return diskTransferTOD2314(uint32(n)), 0
			case cmd == 0x15 && status&usUnitCheck != 0 && d.sense[1]&sense2314TrackOverrun != 0:
				x.timed = true
				return diskTransferTOD2314(uint32(n)), 0
			case cmd == 0x13 && status == usCE|usDE:
				x.timed = true
				return durationTOD(15 * time.Millisecond), durationTOD(seekDuration2314(diskCyl, 0))
			case cmd == 0x07 || cmd == 0x0b:
				if d.seekIncomplete && status == usCE|usDE|usUnitCheck {
					x.timed = true
					return diskTransferTOD2314(uint32(n)), durationTOD(600 * time.Millisecond)
				}
				if status == usCE|usDE && diskCyl != d.cyl {
					x.timed = true
					return diskTransferTOD2314(uint32(n)), durationTOD(seekDuration2314(diskCyl, d.cyl) + d.seekExtra2314)
				}
			}
		}
	}
	if !x.timed || s.ipl {
		return 0, 0
	}
	if u, ok := x.dev.(*UnitRecord); ok && u.on2821() {
		ce, de := u.commandTiming(cmd, n, u.burst2821 || x.devno>>8 != 0)
		return durationTOD(ce), durationTOD(de)
	}
	ce, de := t.CommandTiming(cmd, n)
	return durationTOD(ce), durationTOD(de)
}

// seekDuration2314 approximates model 1 access time over the cylinder stroke
// (GA26-3599-6, figure 15).
func seekDuration2314(from, to uint32) time.Duration {
	distance := max(from, to) - min(from, to)
	return 25*time.Millisecond + time.Duration(distance)*(100*time.Millisecond)/202
}

// Halter is implemented by devices operating in multiplex mode that HALT
// I/O stops during a data transfer: elapsed is the time since the transfer
// started. The device returns the bytes it took from the channel and the
// delays to channel end and device end.
type Halter interface {
	Halt(elapsed time.Duration) (sent int, channelEnd, deviceEnd time.Duration)
}

// TestIOStatus is the selection status of an idle device addressed by TIO.
type TestIOStatus interface {
	TestIOStatus() byte
}

func isHalter(d Device) bool { _, ok := d.(Halter); return ok }

// working reports whether the subchannel is executing a channel program.
func (x *Subchannel) working() bool { return x.blocked || x.finishAt != 0 }

func (x *Subchannel) burst2821() bool {
	u, ok := x.dev.(*UnitRecord)
	return ok && u.on2821() && (u.burst2821 || x.devno>>8 != 0)
}

func (x *Subchannel) is2821() bool {
	u, ok := x.dev.(*UnitRecord)
	return ok && u.on2821()
}

// motionBusyStatus presents control-unit busy when motion still holds the
// 2803. That unit reports control-unit end after it has been polled busy.
func (x *Subchannel) motionBusyStatus() byte {
	if tape, ok := x.dev.(*Tape2401); ok && (tape.controlUnitBusy() || x.deStatus&usCE != 0) {
		x.deStatus |= usCUE
		return usBusy | usSM
	}
	return usBusy
}

// busyTapePeer returns the other drive holding a 2415 or 2803 control.
// The low three address bits designate the drive (GA22-6862-6, figure 5).
func (s *ChannelSubsystem) busyTapePeer(selected *Subchannel) *Subchannel {
	tape, ok := selected.dev.(*Tape2401)
	if !ok || selected.controller9020 == 0 && !tape.model2415 && tape.transportModel == 0 {
		return nil
	}
	for _, peer := range s.subs {
		if peer == selected {
			continue
		}
		drive, ok := peer.dev.(*Tape2401)
		if !ok || !selected.sharesTapeControl(peer, tape, drive) {
			continue
		}
		// A normal rewind completes with a unit-free notification.
		// Other drives remain selectable while the channel holds it.
		if drive.rewindDisconnect > s.m.tod || peer.working() || peer.pending && peer.devPending && drive.lastCommand != 0x07 ||
			peer.deAt != 0 && (drive.controlUnitBusy() || drive.lastCommand == 0x0f) {
			return peer
		}
	}
	return nil
}

func (s *ChannelSubsystem) canPresentDeviceEnd(x *Subchannel) bool {
	if x.deAt == 0 || x.pending {
		return false
	}
	// A rewinding transport released the controller. Its unit-free signal
	// waits if the controller is now engaged with another transport.
	tape, ok := x.dev.(*Tape2401)
	return !ok || tape.lastCommand != 0x07 || s.busyTapePeer(x) == nil
}

// complete370 handles the end of a channel program on a System/370 channel.
// initial is true when START I/O executed only the first CCW; it reports
// whether the status belongs in the CSW stored by START I/O.
func (s *ChannelSubsystem) complete370(x *Subchannel, initial bool) bool {
	if !x.timed {
		x.ac = 0
		x.devPending = false
		x.pending, x.irq = true, true
		return false
	}
	if x.endCE > 0 {
		x.ac = acSubchActive | acDeviceActive
		x.finishAt = s.m.tod + x.endCE
		s.reschedule()
		return false
	}
	return s.channelEnd370(x, initial)
}

// channelEnd370 presents channel end. Device end follows after endDE.
func (s *ChannelSubsystem) channelEnd370(x *Subchannel, initial bool) bool {
	x.ac = 0
	x.finishAt = 0
	if p, ok := x.dev.(*rcu9020Port); ok && p.rcu.state.BusyEnd {
		x.devStatus |= usCUE
		p.rcu.state.BusyEnd = false
	}
	if x.endDE > 0 && x.devStatus&usCE != 0 && x.schStatus&^(scsPCI|scsIncorrectLen) == 0 {
		ce := byte(usCE)
		if _, ok := x.dev.(*Console1052); ok {
			// Keyboard Cancel and keyboard parity checks are known at
			// channel end, before the carrier returns.
			ce |= x.devStatus & (usUnitExcept | usUnitCheck)
		}
		x.deStatus = x.devStatus&^ce | usDE
		x.devStatus = ce
		x.deAt = s.m.tod + x.endDE
	}
	s.reschedule()
	if initial && x.schStatus&scsPCI == 0 {
		x.notify2821()
		return true
	}
	x.devPending = false
	x.pending, x.irq = true, true
	x.notify2821()
	return false
}

// tick370 makes due timed transitions. It reports whether any happened.
func (s *ChannelSubsystem) tick370() bool {
	if s.next == 0 || s.m.tod < s.next {
		return false
	}
	now := s.m.tod
	if s.rcus9020[0] != nil || s.rcus9020[1] != nil {
		s.tickRKM9020E(now)
	}
	for _, x := range s.subs {
		if x.resumeAt != 0 && now >= x.resumeAt {
			x.resumeAt = 0
			s.resume(x)
		}
		if at := x.nextRKMBusByte(); at != 0 && now >= at {
			s.advanceRKMBus(x, now)
		}
		for at := s.nextReadChain9020(x); at != 0 && now >= at; at = s.nextReadChain9020(x) {
			s.advanceReadChain9020(x)
		}
		var outputCheck byte
		var machineCheck bool
		if at := s.nextOutput9020(x); at != 0 && now >= at {
			outputCheck, machineCheck = s.advanceOutput9020(x, now)
		}
		if machineCheck {
			s.interruptOutput9020(x)
		} else if outputCheck != 0 {
			s.endOutputCheck9020(x, outputCheck)
		} else if x.finishAt != 0 && now >= x.finishAt {
			s.transferEnd(x)
		} else if at := x.nextDiskInputAt(); at != 0 && now >= at {
			op := x.op
			moved := min(x.diskBytes2314(now), uint32(len(op.Out)), op.Total)
			check, machineCheck := s.storeCCWInput(x, op, moved)
			if machineCheck {
				s.interruptRead9020(x)
			} else if check != 0 || op.InputLimit != 0 && moved > op.InputLimit {
				// End the command with the check at the attempted
				// storage address, without transferring later bytes.
				op.Out = op.Out[:moved]
				s.transferEnd(x)
			}
		}
		if now >= x.deAt && s.canPresentDeviceEnd(x) {
			// The device presents device end once any channel-end
			// condition has been cleared.
			if s.m.TraceIO && !s.m.TraceIOSkip[x.devno] {
				s.m.event("io", nil, fmt.Sprintf("device end %04X -> dev %02X", x.devno, x.deStatus))
			}
			x.deAt = 0
			x.presentDeviceStatus(x.deStatus)
			x.notify2821()
		}
		if x.cuBusyUntil != 0 && now >= x.cuBusyUntil && (!x.cuEndWanted || !x.pending) {
			if x.cuEndWanted {
				x.presentDeviceStatus(usCUE)
			}
			x.cuBusyUntil, x.cuEndWanted = 0, false
		}
		if tape, ok := x.dev.(*Tape2401); ok {
			if tape.reload != 0 && now >= tape.unloadUntil {
				s.remountTape(x, tape, tape.reload == 2)
			}
			if tape.readyEnd && s.busyTapePeer(x) == nil {
				tape.readyEnd = false
				s.Unsolicited(x.devno, usDE)
			}
		}
	}
	s.reschedule()
	return true
}

func (x *Subchannel) presentDeviceStatus(status byte) {
	x.key, x.ccwaddr, x.residual, x.schStatus = 0, 0, 0, 0
	x.devStatus = status
	x.devPending, x.pending, x.irq = true, true, true
}

func (x *Subchannel) notify2821() {
	if u, ok := x.dev.(*UnitRecord); ok && u.port != nil {
		u.port.control.notify()
	}
}

// Set2314Plug removes or replaces a drive's module identifier plug. On
// insertion the module returns to cylinder zero and reports device end
// for the not-ready to ready transition (GA26-3599-6).
func (s *ChannelSubsystem) Set2314Plug(devno uint16, inserted bool) error {
	x := s.bydev[devno]
	if x == nil {
		return fmt.Errorf("no disk at %04X", devno)
	}
	d, ok := x.dev.(*DASD3390)
	if !ok || d.devType != 0x2314 {
		return fmt.Errorf("device %04X is not a 2314", devno)
	}
	if d.plugRemoved == !inserted {
		return nil
	}
	if x.working() || x.pending || x.deAt != 0 || x.cuBusyUntil != 0 {
		return fmt.Errorf("2314 %04X is busy", devno)
	}
	d.plugRemoved = !inserted
	if inserted && !d.motorStopped {
		delay := seekDuration2314(d.cyl, 0)
		d.Reset()
		d.recalibrate()
		x.deStatus, x.deAt = usDE, s.m.tod+durationTOD(delay)
		s.reschedule()
	}
	return nil
}

// Set2314Motor operates the drive module's START/STOP switch. The module
// keeps its address and signals device end after the startup sequence.
func (s *ChannelSubsystem) Set2314Motor(devno uint16, start bool) error {
	x := s.bydev[devno]
	if x == nil {
		return fmt.Errorf("no disk at %04X", devno)
	}
	d, ok := x.dev.(*DASD3390)
	if !ok || d.devType != 0x2314 {
		return fmt.Errorf("device %04X is not a 2314", devno)
	}
	if d.motorStopped == !start {
		return nil
	}
	if !start && x.blocked && x.resumeAt != 0 && !x.pending && x.deAt == 0 && x.cuBusyUntil == 0 {
		// The heads retract when STOP cuts motor power. A channel
		// program waiting for seek completion cannot continue chaining.
		d.motorStopped = true
		d.sense[0] |= senseIntervReq
		d.EndChain()
		x.blocked, x.resumeAt = false, 0
		x.endCE, x.endDE = 0, 0
		x.devStatus = usCE | usDE | usUnitCheck
		s.complete370(x, false)
		return nil
	}
	if x.working() || x.pending || x.deAt != 0 || x.cuBusyUntil != 0 {
		return fmt.Errorf("2314 %04X is busy", devno)
	}
	d.motorStopped = !start
	if start {
		d.Reset()
		// The intervention sense survives startup until Sense reads it.
		d.sense[0] = senseIntervReq
		d.recalibrate()
		if !d.plugRemoved {
			x.deStatus, x.deAt = usDE, s.m.tod+durationTOD(60*time.Second)
			s.reschedule()
		}
	}
	return nil
}

// Exchange2314Packs exchanges two stopped modules' packs and ID plugs.
// The pack contents stay with the logical address carried by the plug.
// Both mechanisms will recalibrate on their next START.
func (s *ChannelSubsystem) Exchange2314Packs(first, second uint16) error {
	if first == second {
		return fmt.Errorf("2314 pack exchange requires two different modules")
	}
	if first>>4 != second>>4 {
		return fmt.Errorf("2314 pack exchange requires modules on the same control unit")
	}
	var disks [2]*DASD3390
	for i, devno := range [2]uint16{first, second} {
		x := s.bydev[devno]
		if x == nil {
			return fmt.Errorf("no disk at %04X", devno)
		}
		d, ok := x.dev.(*DASD3390)
		if !ok || d.devType != 0x2314 {
			return fmt.Errorf("device %04X is not a 2314", devno)
		}
		if !d.motorStopped || d.plugRemoved || x.working() || x.pending || x.deAt != 0 || x.cuBusyUntil != 0 {
			return fmt.Errorf("2314 %04X must be stopped with its ID plug inserted and no pending I/O", devno)
		}
		disks[i] = d
	}
	disks[0].physical2314, disks[1].physical2314 = disks[1].physical2314, disks[0].physical2314
	disks[0].seekExtra2314, disks[1].seekExtra2314 = disks[1].seekExtra2314, disks[0].seekExtra2314
	return nil
}

// Move2314Plug moves the first address plug to a running, unplugged module
// on the same control unit. Packs stay in their physical modules.
func (s *ChannelSubsystem) Move2314Plug(first, second uint16) error {
	if first == second || first>>4 != second>>4 {
		return fmt.Errorf("2314 plug move requires distinct modules on the same control unit")
	}
	a, b := s.bydev[first], s.bydev[second]
	if a == nil || b == nil {
		return fmt.Errorf("2314 plug move requires two attached modules")
	}
	from, fromOK := a.dev.(*DASD3390)
	to, toOK := b.dev.(*DASD3390)
	if !fromOK || !toOK || from.devType != 0x2314 || to.devType != 0x2314 {
		return fmt.Errorf("2314 plug move requires two 2314 modules")
	}
	if from.plugRemoved || !to.plugRemoved || from.motorStopped || to.motorStopped {
		return fmt.Errorf("2314 plug move requires running modules with only the source plugged in")
	}
	for _, x := range []*Subchannel{a, b} {
		if x.working() || x.pending || x.deAt != 0 || x.cuBusyUntil != 0 {
			return fmt.Errorf("2314 %04X is busy", x.devno)
		}
	}
	a.dev, b.dev = to, from
	to.SetDeviceNumber(first)
	from.SetDeviceNumber(second)
	from.plugRemoved = true
	return s.Set2314Plug(first, true)
}

// transferEnd completes a CCW whose data transfer has ended and continues
// or ends its channel program.
func (s *ChannelSubsystem) transferEnd(x *Subchannel) {
	op := x.op
	if op != nil && !op.OutputOverrun {
		s.finishCCW370(x, op)
		return
	}
	x.op, x.finishAt = nil, 0
	x.endCE = 0
	if op == nil {
		s.channelEnd370(x, false)
		return
	}
	s.finishOutputOverrun9020(x, op)
}

func (s *ChannelSubsystem) finishCCW370(x *Subchannel, op *ccwOp) {
	if p, ok := x.dev.(*dau2701Port); ok && op.Err == 0 {
		switch {
		case op.RKMOrder == 0x08:
			op.Status = p.disconnectRKM()
		case op.RKMOperator.Order != 0:
			op.Status = p.startRKMOrder(op.RKMOperator)
		}
	}
	if _, ok := x.dev.(*ctc9020Side); ok && s.m.TraceIO {
		s.trace = append(s.trace[:0], ioTrace{op.Cmd, op.Last.flags, op.Total, op.Status, nil, op.Out})
	}
	next, cont, pci, machineCheck := s.endCCW(x, op)
	if machineCheck {
		s.interruptRead9020(x)
		return
	}
	if tape, ok := x.dev.(*Tape2401); ok && (op.Cmd == 0x02 || op.Cmd == 0x0c) && x.endCE >= durationTOD(tapeStart) {
		tape.finishReadMotion(s.m.tod, x.endCE)
	}
	x.op, x.finishAt, x.endCE = nil, 0, 0
	if !cont {
		if s.holdChannelEnd(x, op); x.endAtDE {
			return
		}
		s.programEnd(x)
		return
	}
	x.blockAddr, x.blockFmt1 = next, op.Fmt1
	x.ccws++
	switch {
	case pci:
		x.blocked, x.pciWait, x.pciIRQ = true, true, true
		x.pciAt = s.m.CPUs[0].Instructions
	case x.endDE > 0:
		s.pauseChain(x, next, op.Fmt1, x.endDE)
	default:
		s.resume(x)
	}
}

// reschedule recomputes the earliest pending transition. Device end waiting
// for a pending channel-end condition is not a deadline: it becomes due when
// that condition is cleared.
func (s *ChannelSubsystem) reschedule() {
	s.next = 0
	if s.rcus9020[0] != nil || s.rcus9020[1] != nil {
		s.next = s.nextRKM9020E()
	}
	for _, x := range s.subs {
		if tape, ok := x.dev.(*Tape2401); ok && tape.rewindDisconnect > s.m.tod &&
			(s.next == 0 || tape.rewindDisconnect < s.next) {
			s.next = tape.rewindDisconnect
		}
		if tape, ok := x.dev.(*Tape2401); ok && tape.readyEnd && s.busyTapePeer(x) == nil {
			s.next = s.m.tod
		}
		if tape, ok := x.dev.(*Tape2401); ok && tape.reload != 0 {
			at := max(tape.unloadUntil, s.m.tod)
			if s.next == 0 || at < s.next {
				s.next = at
			}
		}
		for _, t := range []uint64{x.resumeAt, x.finishAt, x.nextDiskInputAt(), s.nextOutput9020(x), s.nextReadChain9020(x), x.nextRKMBusByte()} {
			if t != 0 && (s.next == 0 || t < s.next) {
				s.next = t
			}
		}
		if s.canPresentDeviceEnd(x) {
			at := max(x.deAt, s.m.tod)
			if s.next == 0 || at < s.next {
				s.next = at
			}
		}
		if at := x.cuBusyUntil; at != 0 && (!x.cuEndWanted || !x.pending) && (s.next == 0 || at < s.next) {
			s.next = at
		}
	}
}

// storeStatus370 replaces the status portion of the CSW, as START I/O and
// HALT I/O do; the key, address and count are unchanged.
func (c *CPU) storeStatus370(devno uint16, unit, channel byte) {
	c.checkIOPSA9020(devno)
	addr := c.iocePSAAddress9020(0x44, accStore)
	be.PutUint16(c.S.Mem[addr:], uint16(unit)<<8|uint16(channel))
	*c.S.key(addr) |= keyRef | keyChg
	c.M.CSS.latchIOCEStorage9020(devno, addr, 2, accStore, 0)
}

// accept370 clears status the program has received and presents unsolicited
// status held while it was pending.
func (s *ChannelSubsystem) accept370(x *Subchannel) {
	x.pending, x.irq = false, false
	x.devPending = false
	if u, ok := x.dev.(*UnitRecord); ok && u.port != nil {
		u.port.acceptReady(s, x)
	}
	if status := x.heldStatus; status != 0 {
		x.heldStatus = 0
		s.Unsolicited(x.devno, status)
	}
	if d, ok := x.dev.(*ctc9020Side); ok {
		d.flush()
	}
	if p, ok := x.dev.(*dau2701Port); ok {
		p.dau.notify()
	}
	if _, ok := x.dev.(*rcu9020Port); ok {
		s.presentRCUAttention9020()
	}
	if t, ok := x.dev.(*Console1052); ok {
		t.flushReadyEnd()
	}
	x.notify2821()
	s.reschedule() // a device end may have been waiting
}

// io370 executes START I/O, TEST I/O, HALT I/O and TEST CHANNEL.
func (c *CPU) io370(op []byte, a uint32) {
	c.privileged()
	devno := uint16(a)
	css := c.M.CSS
	if c.M.TraceIO && !c.M.TraceIOSkip[devno] {
		defer func() {
			if op[0] != 0x9c || c.PSW.CC != 0 {
				unit := c.M.S.Mem[c.realToAbs(0x44)]
				if c.M.TraceIOQuietPolls && op[0] == 0x9d && (c.PSW.CC == 2 ||
					c.PSW.CC == 1 && (unit == usBusy || unit == usBusy|usSM)) {
					return
				}
				name := map[byte]string{0x9c: "SIO", 0x9d: "TIO", 0x9e: "HIO", 0x9f: "TCH"}[op[0]]
				c.M.event("io", c, fmt.Sprintf("%s %04X cc %d csw %016X", name, devno, c.PSW.CC, be.Uint64(c.S.Mem[c.realToAbs(0x40):])))
			}
		}()
	}
	if !c.ioceConfigured9020(devno>>10) || css.ioceMachineCheckPending9020(devno) {
		c.PSW.CC = 3
		return
	}
	if op[0] == 0x9f { // TCH
		ch := devno >> 8
		c.PSW.CC = 3
		if ch == 0 && c.M.cfg.ByteMuxSubchannels != 0 {
			c.PSW.CC = 0
		}
		for _, x := range css.subs {
			if x.devno>>8 != ch {
				continue
			}
			switch {
			case x.finishAt != 0 && (!x.is2821() || x.burst2821()):
				c.PSW.CC = 2 // burst mode
			case x.pending && (c.M.S360 || !x.devPending) && c.PSW.CC != 2:
				c.PSW.CC = 1
			case c.PSW.CC == 3:
				c.PSW.CC = 0
			}
		}
		return
	}
	if c.M.cfg.ByteMuxSubchannels != 0 && devno >= 0x80 && devno < 0x100 {
		// Devices in this address group share one channel program slot.
		// TEST I/O to an alias cannot accept the owner's completion.
		first := devno &^ 0xf
		for address := first; address < first+16; address++ {
			peer := css.bydev[address]
			if peer == nil || address == devno {
				continue
			}
			if peer.working() && op[0] != 0x9e {
				c.PSW.CC = 2
				return
			}
			if peer.pending && !peer.devPending {
				c.PSW.CC = 2
				if op[0] == 0x9e {
					c.PSW.CC = 0
				}
				return
			}
		}
	}
	x := css.bydev[devno]
	if x == nil || !css.controlConfigured9020(x) {
		c.PSW.CC = 3
		return
	}
	rcu, _ := x.dev.(*rcu9020Port)
	if rcu != nil {
		defer css.presentRCUAttention9020()
	}
	if op[0] == 0x9c || op[0] == 0x9d {
		for _, peer := range css.subs {
			if peer != x && peer.devno>>8 == devno>>8 && peer.finishAt != 0 && peer.burst2821() {
				c.PSW.CC = 2
				return
			}
		}
	}
	if disk, ok := x.dev.(*DASD3390); ok && disk.plugRemoved {
		c.PSW.CC = 3
		return
	}
	if p, ok := x.dev.(*dau2701Port); ok && !p.selected() {
		c.PSW.CC = 3
		return
	}
	u, _ := x.dev.(*UnitRecord)
	if u != nil && u.printer() && u.pr.unavailable {
		c.PSW.CC = 3
		return
	}
	switched := u != nil && u.port != nil
	if switched && (op[0] == 0x9c || op[0] == 0x9d) && !x.working() && (!x.pending || x.devStatus == usCUE) {
		if status := u.port.selectStatus(css, x); status != 0 {
			if op[0] == 0x9c {
				c.storeStatus370(devno, status, 0)
			} else {
				c.storeChannelStatus370(devno, uint64(status)<<24)
			}
			c.PSW.CC = 1
			return
		}
	}
	if peer := css.busyTapePeer(x); (op[0] == 0x9c || op[0] == 0x9d) && peer != nil {
		drive := peer.dev.(*Tape2401)
		if peer.deAt != 0 && !peer.pending && !peer.working() && drive.lastCommand != 0x07 {
			peer.deStatus |= usCUE
		}
		if op[0] == 0x9c {
			c.storeStatus370(devno, usSM|usBusy, 0)
		} else {
			c.storeChannelStatus370(devno, uint64(usSM|usBusy)<<24)
		}
		c.PSW.CC = 1
		return
	}
	switch op[0] {
	case 0x9c: // SIO, SIOF
		switch {
		case x.working():
			c.PSW.CC = 2
			return
		case x.pending && x.devPending:
			// Status held by the device is returned with busy and cleared.
			// The 9020's channels present it without busy.
			busy := byte(usBusy)
			if _, tape2401 := x.dev.(*Tape2401); c.M.Model9020 && !tape2401 && !switched {
				busy = 0
			}
			c.storeStatus370(devno, x.devStatus|busy, 0)
			css.accept370(x)
			c.PSW.CC = 1
			return
		case x.pending && x.timed:
			c.PSW.CC = 2 // interruption pending in the subchannel
			return
		case x.pending:
			// Synchronous devices: the status and busy are returned and
			// the condition cleared.
			c.storeChannelStatus370(devno, x.csw()|uint64(usBusy)<<24)
			css.accept370(x)
			c.PSW.CC = 1
			return
		case x.cuBusyUntil != 0:
			x.cuEndWanted = true
			c.storeStatus370(devno, usSM|usBusy, 0)
			c.PSW.CC = 1
			return
		case x.deAt != 0:
			c.storeStatus370(devno, x.motionBusyStatus(), 0)
			c.PSW.CC = 1
			return
		}
		if p, ok := x.dev.(*dau2701Port); ok {
			if status := p.TestIOStatus(); status != 0 {
				c.storeStatus370(devno, status, 0)
				c.PSW.CC = 1
				return
			}
		}
		if rcu != nil {
			if status := rcu.TestIOStatus(); status != 0 {
				c.storeStatus370(devno, status, 0)
				c.PSW.CC = 1
				return
			}
		}
		caw := c.fetchCAW370(devno)
		x.key = byte(caw >> 28)
		x.ccwaddr, x.devStatus, x.schStatus, x.residual = 0, 0, 0, 0
		if caw&0x0f000007 != 0 {
			x.schStatus = scsProgramCheck
			c.storeCSW(x)
			c.PSW.CC = 1
			return
		}
		if ce, ok := x.dev.(ChainEnd); ok {
			ce.StartChain()
		}
		css.trace = css.trace[:0]
		x.ccws = 0
		x.ce9020 = c.Addr
		if css.run(x, caw&0x00fffff8, false, 0, x.key) {
			c.PSW.CC = 3
			return
		}
		c.PSW.CC = 0
		if x.blocked || x.finishAt != 0 {
			return // continues when the device or program is ready
		}
		if x.ccws == 0 && x.schStatus != 0 {
			// A programming error in the CAW or first CCW, found before
			// the device is selected: the operation is not initiated.
			if ce, ok := x.dev.(ChainEnd); ok {
				ce.EndChain()
			}
			c.storeStatus370(devno, 0, x.schStatus)
			c.PSW.CC = 1
			return
		}
		if ce, ok := x.dev.(ChainEnd); ok {
			ce.EndChain()
		}
		if c.M.TraceIO {
			c.M.event("io", c, fmt.Sprintf("SIO %04X caw %08X cmds %s -> dev %02X ch %02X ccw %06X resid %d", devno, caw, css.traceString(), x.devStatus, x.schStatus, x.ccwaddr, x.residual))
		}
		if css.complete370(x, x.ccws == 1) {
			c.storeStatus370(devno, x.devStatus, x.schStatus)
			c.PSW.CC = 1
		}
	case 0x9d: // TIO, CLRIO
		switch {
		case x.working():
			c.PSW.CC = 2
		case x.pending:
			c.storeCSW(x)
			css.accept370(x)
			c.PSW.CC = 1
		case x.cuBusyUntil != 0:
			x.cuEndWanted = true
			c.storeChannelStatus370(devno, uint64(usSM|usBusy)<<24)
			c.PSW.CC = 1
		case x.deAt != 0:
			c.storeChannelStatus370(devno, uint64(x.motionBusyStatus())<<24)
			c.PSW.CC = 1
		default:
			c.PSW.CC = 0
			if d, ok := x.dev.(TestIOStatus); ok {
				if status := d.TestIOStatus(); status != 0 {
					c.storeChannelStatus370(devno, uint64(status)<<24)
					c.PSW.CC = 1
				}
			}
		}
	case 0x9e: // HIO, HDV
		tape, _ := x.dev.(*Tape2401)
		disk, _ := x.dev.(*DASD3390)
		ctc, _ := x.dev.(*ctc9020Side)
		switch {
		case x.op != nil && x.op.OutputOverrun:
			c.PSW.CC = 2 // The device is finishing its write after losing service.
		case ctc != nil:
			if c.PSW.CC = ctc.halt(x); c.PSW.CC == 1 {
				c.storeStatus370(devno, 0, 0)
			}
		case x.blocked && x.resumeAt == 0 && !x.pciWait:
			// A read waiting for an operator is terminated.
			x.blocked = false
			x.devStatus, x.schStatus = usCE|usDE, 0
			x.ccwaddr = x.blockAddr + 8
			c.storeCSW(x)
			c.PSW.CC = 1
		case x.finishAt != 0 && x.op != nil && tape != nil && c.M.S360 && devno>>8 != 0:
			css.haltTapeSelector(x, tape)
			c.PSW.CC = 2
		case x.finishAt != 0 && x.op != nil && x.timed && disk != nil && disk.devType == 0x2314 &&
			c.M.S360 && dataTransfer2314(x.op.Cmd):
			css.haltDiskSelector(x)
			c.PSW.CC = 2
		case x.finishAt != 0 && x.op != nil && x.op.RKMOrder >= 0x80:
			css.stopRKMBus(x)
			c.PSW.CC = 2
		case x.finishAt != 0 && x.op != nil && isHalter(x.dev):
			// A device in multiplex mode is signaled to terminate: data
			// transfer stops and channel end, with the count sent,
			// follows from the device (A22-6821-7 pp. 96, 110).
			elapsed := time.Duration((css.m.tod - (x.finishAt - x.endCE)) * uint64(time.Microsecond) / todMicro)
			sent, ce, de := x.dev.(Halter).Halt(elapsed)
			x.op.Used = min(sent, int(x.op.Total))
			x.op.Chained = false
			x.op.Status = usCE | usDE
			x.endCE, x.endDE = durationTOD(ce), durationTOD(de)
			x.finishAt = css.m.tod + x.endCE
			css.reschedule()
			c.storeStatus370(devno, 0, 0)
			c.PSW.CC = 1
		case x.finishAt != 0 || x.resumeAt != 0:
			// The burst is terminated; the subchannel becomes
			// interruption-pending with the status reached.
			if x.op != nil {
				if _, _, _, machineCheck := css.endCCW(x, x.op); machineCheck {
					css.interruptRead9020(x)
					css.reschedule()
					c.PSW.CC = 3
					return
				}
				x.op, x.finishAt = nil, 0
			}
			x.blocked, x.resumeAt = false, 0
			if x.devStatus&usCE == 0 {
				x.devStatus |= usCE | usDE
			}
			x.endDE = 0
			css.channelEnd370(x, false)
			c.PSW.CC = 2
		case x.pending && !x.devPending:
			c.PSW.CC = 0 // interruption pending in the subchannel
		case x.cuBusyUntil != 0:
			x.cuEndWanted = true
			c.storeStatus370(devno, usSM|usBusy, 0)
			c.PSW.CC = 1
		case x.deAt != 0 && tape != nil && tape.controlUnitBusy():
			// The tape control unit is still handling a motion
			// command and cannot pass the halt signal to the drive.
			c.storeStatus370(devno, x.motionBusyStatus(), 0)
			c.PSW.CC = 1
		default:
			// The device is selected and signaled to terminate; status it
			// holds remains pending.
			c.storeStatus370(devno, 0, 0)
			c.PSW.CC = 1
		}
	}
}

// haltTapeSelector first generates the selector channel's interruption
// with no unit status. The tape then signals channel and device end as a
// distinct condition (A22-6821-7 p. 110).
func (s *ChannelSubsystem) haltTapeSelector(x *Subchannel, tape *Tape2401) {
	elapsed := time.Duration((s.m.tod - (x.finishAt - x.endCE)) * uint64(time.Microsecond) / todMicro)
	op := x.op
	status := tape.haltTransfer(op, elapsed)
	if op.Cmd == 0x02 || op.Cmd == 0x0c {
		tape.inhibitGo(s.m.tod + durationTOD(tapeControl))
	}
	s.haltSelector(x, status, s.m.tod+durationTOD(tapeControl))
}

const diskRate2314 = 312000 // bytes per second (GA26-3599-6)
const todSecond = todMicro * 1_000_000

func diskTransferTOD2314(n uint32) uint64 {
	return (uint64(n)*todSecond + diskRate2314 - 1) / diskRate2314
}

func (x *Subchannel) diskBytes2314(now uint64) uint32 {
	elapsed := now - (x.finishAt - x.endCE)
	return uint32(elapsed * diskRate2314 / todSecond)
}

func (s *ChannelSubsystem) nextOutput9020(x *Subchannel) uint64 {
	op := x.op
	if op == nil || !op.TimedOutput || op.OutputOverrun || x.finishAt == 0 || op.Err != 0 {
		return 0
	}
	start := x.finishAt - x.endCE
	n := op.OutputFetched + 1
	if boundary := s.writeChainBoundary9020(x); boundary != 0 {
		n = min(n, boundary)
	} else if op.OutputFetched >= uint32(op.Used) {
		return 0
	}
	if tape, ok := x.dev.(*Tape2401); ok {
		return min(x.finishAt, start+durationTOD(tape.writeByteDelay(n)))
	}
	return min(x.finishAt, start+diskTransferTOD2314(n))
}

func (s *ChannelSubsystem) liveWriteChain9020(x *Subchannel, cmd byte) bool {
	if !s.m.Model9020 || !s.m.S360 || s.ipl || x.devno>>8 == 0 {
		return false
	}
	switch d := x.dev.(type) {
	case *Tape2401:
		return cmd == 0x01
	case *DASD3390:
		return d.devType == 0x2314 && (cmd == 0x05 || cmd == 0x0d)
	}
	return false
}

func (s *ChannelSubsystem) writeChainBoundary9020(x *Subchannel) uint32 {
	op := x.op
	if op.Last.flags&ccwCD == 0 || op.ChainErr != 0 || !s.liveWriteChain9020(x, op.Cmd) {
		return 0
	}
	// The selector may buffer one successor with at most 16 bytes
	// remaining in the current CCW (A22-6821-7, Data Chaining).
	boundary := max(1, op.Total-uint32(min(op.Last.count, 16)))
	if boundary > uint32(op.Used) {
		return 0
	}
	return boundary
}

func (s *ChannelSubsystem) advanceOutput9020(x *Subchannel, now uint64) (byte, bool) {
	op := x.op
	for {
		moved := uint32(op.Used)
		if now < x.finishAt {
			moved = min(moved, max(op.OutputFetched, x.writeBytesAt9020(now)))
		}
		boundary := s.writeChainBoundary9020(x)
		if boundary == 0 || moved < boundary {
			return s.fetchCCWOutput9020(x, moved)
		}
		if check, machineCheck := s.fetchCCWOutput9020(x, boundary); check != 0 || machineCheck {
			return check, machineCheck
		}
		if s.advanceWriteChain9020(x) {
			return 0, true
		}
	}
}

func (s *ChannelSubsystem) advanceWriteChain9020(x *Subchannel) (machineCheck bool) {
	op := x.op
	atr := s.ioceAddresses(x.devno)
	w, addr, machineCheck := s.fetchNextDataCCW9020(x, atr)
	if machineCheck || op.ChainErr != 0 {
		return machineCheck
	}
	sg, _ := s.segments(w)
	sg = s.channelSegments(atr, sg, false)
	for i := range sg {
		g := &sg[i]
		if s.channelStorage(g.addr, g.n) == nil {
			op.ChainErr = addr + 8
			return false
		}
		g.skip = w.flags&ccwSkip != 0
	}
	op.Segs = append(op.Segs, sg...)
	op.appendDataCCW(w, addr)
	start := x.finishAt - x.endCE
	if tape, ok := x.dev.(*Tape2401); ok {
		op.TapeWrite = append(op.TapeWrite, make([]byte, int(w.count))...)
		op.Used = int(op.Total)
		x.endCE = durationTOD(tape.writeTransferDuration(op.Used) + tape.goDelay)
	} else {
		write := op.DiskWrite
		write.Data = append(write.Data, make([]byte, int(w.count))...)
		op.Used = min(int(op.Total), write.Capacity)
		x.endCE = diskTransferTOD2314(uint32(op.Used))
	}
	x.finishAt = start + x.endCE
	return false
}

// fetchCCWOutput9020 accepts the newly requested bytes from live storage.
// Data chains share a byte clock even when their storage is discontiguous.
func (s *ChannelSubsystem) fetchCCWOutput9020(x *Subchannel, moved uint32) (channelCheck byte, machineCheck bool) {
	op := x.op
	dst := op.TapeWrite
	if op.DiskWrite != nil {
		dst = op.DiskWrite.Data
	} else if rkmWriteOrder(op.RKMOrder) {
		dst = op.RKMOutput
	}
	block := uint32(1) << s.m.S.KeyShift
	var off uint32
	for _, g := range op.Segs {
		if off >= moved {
			break
		}
		end := off + g.n
		for lo, hi := max(off, op.OutputFetched), min(end, moved); lo < hi; {
			addr := g.addr + lo - off
			size := s.m.storageElementSize9020()
			n := min(hi-lo, size-addr%size)
			n = min(n, block-addr%block)
			if _, check := s.channelAvailable9020(x.devno, addr, n, false); check != 0 {
				return check, false
			}
			if s.checkIOCEKey9020(x.ce9020, x.devno, addr, n, accFetch, op.Key) {
				return 0, true
			}
			if op.Checked && !g.skip && !s.fetchAllowed(addr, n, op.Key) {
				return scsProtection, false
			}
			if failed, bad := s.m.firstBadDataWord9020(addr, n); bad && int(x.ce9020) < len(s.m.CPUs) {
				if addr < failed {
					// Accept and latch the sound prefix before stopping the SE.
					n = failed - addr
				} else if s.checkIOCEFetch9020(s.m.CPUs[x.ce9020], x.devno, addr&^3, op.Key) {
					return 0, true
				}
			}
			copy(dst[lo:lo+n], s.channelStorage(addr, n))
			s.latchIOCEStorage9020(x.devno, addr, n, accFetch, op.Key)
			lo += n
			op.OutputFetched = lo
		}
		off = end
	}
	return 0, false
}

func (x *Subchannel) writeBytesAt9020(at uint64) uint32 {
	if tape, ok := x.dev.(*Tape2401); ok {
		elapsed := time.Duration((at-(x.finishAt-x.endCE))/todMicro) * time.Microsecond
		return uint32(tape.transferredBytes(x.op.Cmd, false, elapsed))
	}
	return x.diskBytes2314(at)
}

func (s *ChannelSubsystem) endOutputCheck9020(x *Subchannel, check byte) {
	op := x.op
	op.Used, op.Err, op.Halted = int(op.OutputFetched), check, true
	if op.Used == 0 && check == scsStoppedSE9020 {
		op.Status = 0
		op.DiskWrite = nil
	} else if d, ok := x.dev.(*DASD3390); ok && op.Status&usUnitCheck != 0 {
		// A later disk check was never reached, as with a selector halt.
		d.sense = [32]byte{}
		op.Status = usCE | usDE
	}
	s.transferEnd(x)
}

// A CLU machine check ends the channel program. The peripheral already
// selected for output independently finishes after losing byte service.
func (s *ChannelSubsystem) interruptOutput9020(x *Subchannel) {
	op := x.op
	x.pciWait, x.pciIRQ = false, false
	var delay uint64
	if tape, ok := x.dev.(*Tape2401); ok {
		if op.OutputFetched == 0 && !tape.model2415 {
			// The 2803 is still in initial selection, waiting for its
			// first service-out before starting the tape (Y22-2853-1).
			x.ac, x.op, x.finishAt, x.endCE, x.endDE = 0, nil, 0, 0, 0
			s.reschedule()
			return
		}
		delay = durationTOD(time.Second / time.Duration(tape.frameRate()))
		if last := durationTOD(tape.writeByteDelay(uint32(op.Used))); last < x.endCE {
			delay += x.endCE - last
		}
	} else if d, ok := x.dev.(*DASD3390); ok {
		remaining, err := d.limitOverrun2314(op.DiskWrite, int(op.OutputFetched))
		if err != nil {
			_, _, op.Status = d.ioErr(err)
			op.DiskWrite = nil
		}
		delay = diskTransferTOD2314(uint32(remaining))
	}
	op.OutputOverrun = true
	x.finishAt = s.m.tod + max(delay, 1)
	s.reschedule()
}

func (s *ChannelSubsystem) finishOutputOverrun9020(x *Subchannel, op *ccwOp) {
	used := int(op.OutputFetched)
	status := byte(usCE | usDE | usUnitCheck)
	switch d := x.dev.(type) {
	case *Tape2401:
		if used > 0 {
			status |= d.finishWrite(op.TapeWrite[:used])
		} else {
			d.sense[0] |= 0x02 // Word Count Zero.
		}
		d.sense[0] |= senseOverrun
	case *DASD3390:
		if op.DiskWrite != nil {
			if err := d.commitWrite2314(op.DiskWrite, used, false); err != nil {
				_, _, status = d.ioErr(err)
			} else {
				_, _, status = d.check(senseOverrun, 0, 0, "2314 write lost channel byte service")
			}
		} else {
			status = op.Status
		}
	}
	x.ac, x.endDE = 0, 0
	x.presentDeviceStatus(status)
}

func (x *Subchannel) nextDiskInputAt() uint64 {
	op := x.op
	if op == nil || x.finishAt == 0 || !x.timed || !op.Read || op.Err != 0 ||
		op.ReadStored >= min(uint32(len(op.Out)), op.Total) || !dataTransfer2314(op.Cmd) {
		return 0
	}
	if d, ok := x.dev.(*DASD3390); ok && d.devType == 0x2314 {
		return x.finishAt - x.endCE + diskTransferTOD2314(op.ReadStored+1)
	}
	return 0
}

func (s *ChannelSubsystem) liveReadChain9020(x *Subchannel, cmd byte) bool {
	if !s.m.Model9020 || !s.m.S360 || s.ipl || x.devno>>8 == 0 {
		return false
	}
	switch d := x.dev.(type) {
	case *Tape2401:
		return cmd == 0x02 || cmd == 0x0c
	case *DASD3390:
		return d.devType == 0x2314 && cmdIsRead(cmd) && dataTransfer2314(cmd)
	}
	return false
}

func (s *ChannelSubsystem) nextReadChain9020(x *Subchannel) uint64 {
	op := x.op
	if op == nil || x.finishAt == 0 || op.Last.flags&ccwCD == 0 || op.Err != 0 ||
		op.ChainErr != 0 || op.InputLimit != 0 || uint32(len(op.Out)) < op.Total ||
		!s.liveReadChain9020(x, op.Cmd) {
		return 0
	}
	if tape, ok := x.dev.(*Tape2401); ok {
		return min(x.finishAt, x.finishAt-x.endCE+durationTOD(tape.readByteDelay(op.Cmd, op.Total)))
	}
	// The 2314 deadline is the end of the current storage buffer or
	// device data, whichever comes first. A live CCW may extend it.
	return x.finishAt
}

func (s *ChannelSubsystem) advanceReadChain9020(x *Subchannel) {
	op := x.op
	check, machineCheck := s.storeCCWInput(x, op, op.Total)
	if machineCheck {
		s.interruptRead9020(x)
		return
	}
	if check != 0 {
		s.transferEnd(x)
		return
	}
	// A22-6821-7, Data Chaining: input can supply the next CCW itself.
	// Fetch after the last byte of the current buffer reaches storage.
	atr := s.ioceAddresses(x.devno)
	w, addr, machineCheck := s.fetchNextDataCCW9020(x, atr)
	if machineCheck {
		s.interruptRead9020(x)
		return
	}
	if op.ChainErr != 0 {
		return
	}
	if w.flags&ccwSkip != 0 {
		op.Segs = append(op.Segs, segment{n: uint32(w.count), skip: true})
	} else {
		sg, _ := s.segments(w) // System/360 format 0 has no IDAWs.
		backward := w.cmd == 0x0c
		sg = s.channelSegments(atr, sg, backward)
		for _, g := range sg {
			start := g.addr
			if backward {
				start -= g.n - 1
			}
			if s.machAddress(start) != s.machAddress(g.addr) || s.channelStorage(start, g.n) == nil {
				size := s.m.S.Size()
				if atr.Active || g.addr >= size || s.machAddress(g.addr) {
					op.ChainErr = addr + 8
					return
				}
				g.n = size - g.addr
				if backward {
					g.n = g.addr + 1
				}
				op.InputLimit = op.Total + g.n
				sg = []segment{g}
				break
			}
		}
		op.Segs = append(op.Segs, sg...)
	}
	op.appendDataCCW(w, addr)
	if _, ok := x.dev.(*DASD3390); ok {
		start := x.finishAt - x.endCE
		x.endCE = diskTransferTOD2314(min(op.Total, uint32(len(op.Out))))
		x.finishAt = start + x.endCE
	}
}

func (s *ChannelSubsystem) fetchNextDataCCW9020(x *Subchannel, atr channelATR9020) (ccw, uint32, bool) {
	op := x.op
	addr := op.Cur + 8
	for tic := false; ; tic = true {
		physical := s.channelAddress(atr, addr)
		w, check := s.fetchCCW(x.devno, physical, op.Fmt1)
		if check != 0 {
			op.ChainErr, op.ChainStatus = addr+8, check
			return ccw{}, addr, false
		}
		if int(x.ce9020) < len(s.m.CPUs) &&
			s.checkIOCECCW9020(s.m.CPUs[x.ce9020], x.devno, physical, op.Key) {
			return ccw{}, addr, true
		}
		if !s.fetchAllowed(physical, 8, op.Key) {
			op.ChainErr = addr + 8
			return ccw{}, addr, false
		}
		s.latchIOCEStorage9020(x.devno, physical, 8, accFetch, op.Key)
		if w.cmd&0xf == 8 && !tic && w.addr&7 == 0 {
			addr = w.addr
			continue
		}
		if w.cmd&0xf == 8 || w.count == 0 || w.flags&(ccwIDA|ccwS|1) != 0 {
			op.ChainErr = addr + 8
			return ccw{}, addr, false
		}
		w.cmd = op.Cmd
		return w, addr, false
	}
}

func (op *ccwOp) appendDataCCW(w ccw, addr uint32) {
	op.Chain = append(op.Chain, w)
	op.Addrs = append(op.Addrs, addr)
	op.Last, op.Cur, op.Chained = w, addr, w.flags&ccwCC != 0
	op.Total += uint32(w.count)
}

func (s *ChannelSubsystem) interruptRead9020(x *Subchannel) {
	status := x.op.Status
	deviceEnd := max(x.finishAt, s.m.tod)
	available := uint32(len(x.op.Out))
	if available > x.op.ReadStored {
		switch d := x.dev.(type) {
		case *Tape2401:
			d.sense[0] |= senseOverrun
			status |= usUnitCheck
		case *DASD3390:
			d.check(senseOverrun, 0, 0, "2314 read lost channel byte service")
			deviceEnd = x.finishAt - x.endCE + diskTransferTOD2314(available)
			status |= usUnitCheck
		}
	}
	if tape, ok := x.dev.(*Tape2401); ok {
		tape.finishReadMotion(deviceEnd, x.endCE)
	}
	x.deAt, x.deStatus = deviceEnd, status
	x.op, x.finishAt, x.endCE, x.endDE, x.ac = nil, 0, 0, 0, 0
	x.pciWait, x.pciIRQ = false, false
	if ce, ok := x.dev.(ChainEnd); ok {
		ce.EndChain()
	}
}

func dataTransfer2314(cmd byte) bool {
	switch cmd & 0x7f {
	case 0x05, 0x06, 0x0d, 0x0e, 0x1e:
		return true
	}
	return false
}

func (s *ChannelSubsystem) haltDiskSelector(x *Subchannel) {
	sent := int(x.diskBytes2314(s.m.tod))
	op := x.op
	if op.Read {
		op.Out = op.Out[:min(sent, len(op.Out))]
	} else {
		op.Used = min(sent, op.Used)
	}
	status := byte(usCE | usDE)
	if op.Status&usUnitCheck != 0 {
		// The halt terminated the data transfer before the device reached
		// the later check that would have ended the operation.
		x.dev.(*DASD3390).sense = [32]byte{}
	}
	op.Status, op.Halted = status, true
	s.haltSelector(x, status, x.finishAt)
}

func (s *ChannelSubsystem) haltSelector(x *Subchannel, status byte, devEndAt uint64) {
	x.op.Chained = false
	if _, _, _, machineCheck := s.endCCW(x, x.op); machineCheck {
		s.interruptRead9020(x)
		s.reschedule()
		return
	}
	x.op, x.finishAt, x.endCE, x.endDE, x.ac = nil, 0, 0, 0, 0
	x.devStatus, x.devPending = 0, false
	x.pending, x.irq = true, true
	x.deStatus = status
	x.deAt = devEndAt
	s.reschedule()
}
