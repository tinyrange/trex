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
					return diskTransferTOD2314(uint32(n)), durationTOD(seekDuration2314(diskCyl, d.cyl))
				}
			}
		}
	}
	if !x.timed || s.ipl {
		return 0, 0
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

// motionBusyStatus presents control-unit busy when motion still holds the
// 2803. That unit reports control-unit end after it has been polled busy.
func (x *Subchannel) motionBusyStatus() byte {
	if tape, ok := x.dev.(*Tape2401); ok && (tape.controlUnitBusy() || x.deStatus&usCE != 0) {
		x.deStatus |= usCUE
		return usBusy | usSM
	}
	return usBusy
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
	if x.endDE > 0 && x.devStatus&usCE != 0 && x.schStatus&^(scsPCI|scsIncorrectLen) == 0 {
		ce := byte(usCE)
		if _, ok := x.dev.(*Console1052); ok {
			// Keyboard Cancel reports unit exception with channel end.
			ce |= x.devStatus & usUnitExcept
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
	for _, x := range s.subs {
		if x.resumeAt != 0 && now >= x.resumeAt {
			x.resumeAt = 0
			s.resume(x)
		}
		if x.finishAt != 0 && now >= x.finishAt {
			s.transferEnd(x)
		} else if at := x.nextDiskInputAt(); at != 0 && now >= at {
			op := x.op
			moved := min(x.diskBytes2314(now), uint32(len(op.Out)), op.Total)
			if !s.storeCCWInput(op, moved) {
				// End the command with the check at the attempted
				// storage address, without transferring later bytes.
				op.Out = op.Out[:moved]
				s.transferEnd(x)
			}
		}
		if x.deAt != 0 && now >= x.deAt && !x.pending {
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
	if inserted {
		delay := seekDuration2314(d.cyl, 0)
		d.Reset()
		d.recalibrate()
		x.deStatus, x.deAt = usDE, s.m.tod+durationTOD(delay)
		s.reschedule()
	}
	return nil
}

// transferEnd completes a CCW whose data transfer has ended and continues
// or ends its channel program.
func (s *ChannelSubsystem) transferEnd(x *Subchannel) {
	op := x.op
	x.op, x.finishAt = nil, 0
	x.endCE = 0
	if op == nil {
		s.channelEnd370(x, false)
		return
	}
	if _, ok := x.dev.(*ctc9020Side); ok && s.m.TraceIO {
		s.trace = append(s.trace[:0], ioTrace{op.Cmd, op.Last.flags, op.Total, op.Status, nil, op.Out})
	}
	next, cont, pci := s.endCCW(x, op)
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
	for _, x := range s.subs {
		for _, t := range []uint64{x.resumeAt, x.finishAt, x.nextDiskInputAt()} {
			if t != 0 && (s.next == 0 || t < s.next) {
				s.next = t
			}
		}
		if x.deAt != 0 && !x.pending && (s.next == 0 || x.deAt < s.next) {
			s.next = x.deAt
		}
		if at := x.cuBusyUntil; at != 0 && (!x.cuEndWanted || !x.pending) && (s.next == 0 || at < s.next) {
			s.next = at
		}
	}
}

// storeStatus370 replaces the status portion of the CSW, as START I/O and
// HALT I/O do; the key, address and count are unchanged.
func (c *CPU) storeStatus370(unit, channel byte) {
	c.setLowByte(0x44, unit)
	c.setLowByte(0x45, channel)
}

// accept370 clears status the program has received and presents an
// attention held while it was pending.
func (s *ChannelSubsystem) accept370(x *Subchannel) {
	x.pending, x.irq = false, false
	x.devPending = false
	if x.attnHold {
		x.attnHold = false
		s.Unsolicited(x.devno, usAttention)
	}
	if d, ok := x.dev.(*ctc9020Side); ok {
		d.flush()
	}
	if p, ok := x.dev.(*dau2701Port); ok {
		p.dau.notify()
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
				name := map[byte]string{0x9c: "SIO", 0x9d: "TIO", 0x9e: "HIO", 0x9f: "TCH"}[op[0]]
				c.M.event("io", c, fmt.Sprintf("%s %04X cc %d csw %016X", name, devno, c.PSW.CC, be.Uint64(c.S.Mem[c.realToAbs(0x40):])))
			}
		}()
	}
	if op[0] == 0x9f { // TCH
		ch := devno >> 8
		c.PSW.CC = 3
		for _, x := range css.subs {
			if x.devno>>8 != ch {
				continue
			}
			switch {
			case x.finishAt != 0:
				c.PSW.CC = 2 // burst mode
			case x.pending && (c.M.S360 || !x.devPending) && c.PSW.CC != 2:
				c.PSW.CC = 1
			case c.PSW.CC == 3:
				c.PSW.CC = 0
			}
		}
		return
	}
	x := css.bydev[devno]
	if x == nil {
		c.PSW.CC = 3
		return
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
	switched := u != nil && u.port != nil
	if switched && (op[0] == 0x9c || op[0] == 0x9d) && !x.working() && (!x.pending || x.devStatus == usCUE) {
		if status := u.port.selectStatus(css, x); status != 0 {
			if op[0] == 0x9c {
				c.storeStatus370(status, 0)
			} else {
				c.setLowDouble(0x40, uint64(status)<<24)
			}
			c.PSW.CC = 1
			return
		}
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
			c.storeStatus370(x.devStatus|busy, 0)
			css.accept370(x)
			c.PSW.CC = 1
			return
		case x.pending && x.timed:
			c.PSW.CC = 2 // interruption pending in the subchannel
			return
		case x.pending:
			// Synchronous devices: the status and busy are returned and
			// the condition cleared.
			c.storeCSW(x)
			c.setLowByte(0x44, x.devStatus|usBusy)
			css.accept370(x)
			c.PSW.CC = 1
			return
		case x.cuBusyUntil != 0:
			x.cuEndWanted = true
			c.storeStatus370(usSM|usBusy, 0)
			c.PSW.CC = 1
			return
		case x.deAt != 0:
			c.storeStatus370(x.motionBusyStatus(), 0)
			c.PSW.CC = 1
			return
		}
		if p, ok := x.dev.(*dau2701Port); ok {
			if status := p.TestIOStatus(); status != 0 {
				c.storeStatus370(status, 0)
				c.PSW.CC = 1
				return
			}
		}
		caw := c.lowWord(0x48)
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
		css.run(x, caw&0x00fffff8, false, 0, x.key)
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
			c.storeStatus370(0, x.schStatus)
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
			c.storeStatus370(x.devStatus, x.schStatus)
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
			c.setLowDouble(0x40, uint64(usSM|usBusy)<<24)
			c.PSW.CC = 1
		case x.deAt != 0:
			c.setLowDouble(0x40, uint64(x.motionBusyStatus())<<24)
			c.PSW.CC = 1
		default:
			c.PSW.CC = 0
			if d, ok := x.dev.(TestIOStatus); ok {
				if status := d.TestIOStatus(); status != 0 {
					c.setLowDouble(0x40, uint64(status)<<24)
					c.PSW.CC = 1
				}
			}
		}
	case 0x9e: // HIO, HDV
		tape, _ := x.dev.(*Tape2401)
		disk, _ := x.dev.(*DASD3390)
		ctc, _ := x.dev.(*ctc9020Side)
		switch {
		case ctc != nil:
			if c.PSW.CC = ctc.halt(x); c.PSW.CC == 1 {
				c.storeStatus370(0, 0)
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
			c.storeStatus370(0, 0)
			c.PSW.CC = 1
		case x.finishAt != 0 || x.resumeAt != 0:
			// The burst is terminated; the subchannel becomes
			// interruption-pending with the status reached.
			if x.op != nil {
				css.endCCW(x, x.op)
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
			c.storeStatus370(usSM|usBusy, 0)
			c.PSW.CC = 1
		case x.deAt != 0 && tape != nil && tape.controlUnitBusy():
			// The tape control unit is still handling a motion
			// command and cannot pass the halt signal to the drive.
			c.storeStatus370(x.motionBusyStatus(), 0)
			c.PSW.CC = 1
		default:
			// The device is selected and signaled to terminate; status it
			// holds remains pending.
			c.storeStatus370(0, 0)
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
	s.endCCW(x, x.op)
	x.op, x.finishAt, x.endCE, x.endDE, x.ac = nil, 0, 0, 0, 0
	x.devStatus, x.devPending = 0, false
	x.pending, x.irq = true, true
	x.deStatus = status
	x.deAt = devEndAt
	s.reschedule()
}
