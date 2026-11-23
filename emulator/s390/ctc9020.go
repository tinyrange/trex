package s390

import (
	"fmt"
	"time"
)

// ctc9020Side is one selector-channel interface of the IOCE
// channel-to-channel adapter (A27-2734-2, appendix J).
type ctc9020Side struct {
	css          *ChannelSubsystem
	addr         uint16
	peer         *ctc9020Side
	notReady     byte // peer's Sense Adapter result: 40 reset, 41 halt
	control, eof byte // pending immediate command, until consumed by the peer
	notify       byte // attention or device end waiting for the peer to accept prior status
	write        []byte
}

// Attach9020CTC connects two selector channels of the local IOCE.
func (s *ChannelSubsystem) Attach9020CTC(a, b uint16) error {
	if !s.m.Model9020 || a>>8 == 0 || b>>8 == 0 || a>>8 == b>>8 || a > 0x7ff || b > 0x7ff {
		return fmt.Errorf("9020 CTC requires addresses on two different selector channels")
	}
	if s.bydev[a] != nil || s.bydev[b] != nil {
		return fmt.Errorf("9020 CTC address %04X or %04X already attached", a, b)
	}
	x, y := &ctc9020Side{css: s, addr: a}, &ctc9020Side{css: s, addr: b}
	x.peer, y.peer = y, x
	if _, err := s.Attach(a, x); err != nil {
		return err
	}
	_, err := s.Attach(b, y)
	return err
}

func (d *ctc9020Side) SenseID() []byte { return nil }

func (d *ctc9020Side) Reset() {
	d.notReady, d.control, d.eof, d.notify, d.write = 0x40, 0, 0, 0, nil
}

// The System/360 channel supplies the complete CCW, including its count,
// to selectCCW so that both sides reach the end of the transfer together.
func (d *ctc9020Side) Exec(byte, []byte, bool) ([]byte, int, byte) {
	return nil, 0, usUnitCheck
}

func (d *ctc9020Side) CommandTiming(cmd byte, n int) (time.Duration, time.Duration) {
	if cmd&0x0f == 0x04 || cmd&0x1f == 0x14 || cmd&3 == 2 || cmd&0x0f == 0x0c || cmd&0x83 == 0x01 {
		return time.Duration(max(n, 1)) * time.Microsecond, 0
	}
	return 0, 0
}

func (d *ctc9020Side) signal(status byte) {
	x := d.css.bydev[d.addr]
	if x.pending || x.working() {
		d.notify |= status
		return
	}
	x.presentDeviceStatus(status)
}

func (d *ctc9020Side) flush() {
	if status := d.notify; status != 0 {
		d.notify = 0
		d.signal(status)
	}
}

func (d *ctc9020Side) TestIOStatus() byte {
	p := d.peer
	y := d.css.bydev[p.addr]
	switch {
	case p.notReady != 0 && d.notReady == 0:
		return usUnitCheck
	case d.control != 0:
		return usBusy
	case p.control != 0 || p.eof == 0 && y.blocked && y.op != nil:
		return usAttention
	default:
		return 0
	}
}

func (d *ctc9020Side) selectCCW(x *Subchannel, op *ccwOp, in []byte) (waiting bool) {
	p := d.peer
	y := d.css.bydev[p.addr]
	op.Status = usCE | usDE
	if op.Cmd&0x0f == 0x04 {
		p.eof = 0
		sense := p.notReady
		if op.Cmd&0x1f == 0x14 { // Sense Command Byte
			sense = p.control
			if y.blocked && y.op != nil {
				sense = y.op.Cmd
			}
		}
		op.Out = []byte{sense}
		if p.control != 0 {
			p.control = 0
			if y.blocked {
				y.resumeAt = d.css.m.tod + durationTOD(time.Microsecond)
			} else {
				p.signal(usDE)
			}
		}
		return false
	}
	if d.notReady != 0 {
		d.notReady = 0
		p.signal(usDE)
	}
	if p.notReady != 0 {
		op.Status = usUnitCheck
		return false
	}
	if d.control != 0 {
		op.Status = usBusy
		return false
	}
	data := op.Cmd&3 == 2 || op.Cmd&0x0f == 0x0c || op.Cmd&0x83 == 0x01
	if p.eof != 0 {
		p.eof = 0
		if data && op.Read {
			op.Status |= usUnitExcept
			return false
		}
	}
	if y.blocked && y.op != nil && y.finishAt == 0 && data && op.Read != y.op.Read {
		d.notify &^= usAttention
		if op.Read {
			moveCTC(op, y.op, p.write)
		} else {
			moveCTC(y.op, op, in)
		}
		p.write = nil
		y.blocked = false
		y.endCE = durationTOD(time.Duration(max(len(op.Out)+op.Used, 1)) * time.Microsecond)
		y.finishAt = d.css.m.tod + y.endCE
		return false
	}
	if op.Cmd&0x83 == 0x81 && y.blocked && y.op != nil && y.op.Read {
		d.eof = op.Cmd
		p.stopData(y, usCE|usDE|usUnitExcept)
		return false
	}
	if p.control != 0 || y.blocked && y.op != nil {
		op.Status = usBusy | usAttention
		return false
	}
	switch {
	case data:
		d.write = in
		x.blocked, x.op = true, op
		x.ac = acSubchActive | acDeviceActive
		// A peer already chaining from the matched transfer takes
		// its next CCW without soliciting another program response.
		if d.eof == 0 && (y.op == nil || !y.op.Chained || y.finishAt == 0) {
			p.signal(usAttention)
		}
		return true
	case op.Cmd&7 == 7: // Control
		d.control = op.Cmd
		op.Status = usCE
		p.signal(usAttention)
	case op.Cmd&0x83 == 0x81:
		d.eof = op.Cmd
	case op.Cmd&7 == 3: // No operation
	default:
		op.Status = usUnitCheck
	}
	return false
}

func moveCTC(read, write *ccwOp, payload []byte) {
	read.Status, write.Status = usCE|usDE, usCE|usDE
	n := min(int(read.Total), len(payload))
	read.Out = payload[:n]
	write.Used = n
}

func (d *ctc9020Side) stopData(x *Subchannel, status byte) {
	x.blocked = false
	x.op.Status, x.op.Chained = status, false
	x.op.LengthOnException = status&usUnitExcept != 0
	x.finishAt = d.css.m.tod + durationTOD(time.Microsecond)
	d.write = nil
}

func (d *ctc9020Side) halt(x *Subchannel) byte {
	p := d.peer
	y := d.css.bydev[p.addr]
	cc := byte(1)
	if x.pending && !x.devPending {
		cc = 0
	}
	if x.blocked && x.op != nil || x.finishAt != 0 {
		x.blocked, x.op, x.finishAt, x.ac = false, nil, 0, 0
		x.ccwaddr, x.residual, x.schStatus = 0, 0, 0
		x.devStatus, x.devPending, x.pending, x.irq = 0, false, true, true
		cc = 2
	} else if !x.pending && d.notReady == 0 && !(y.blocked && y.op != nil) {
		d.signal(usCE | usDE)
	}
	if d.control != 0 && x.blocked {
		x.blocked, x.resumeAt, x.ac = false, 0, 0
	}
	d.notReady, d.control, d.eof, d.write = 0x41, 0, 0, nil
	if y.blocked && y.op != nil {
		p.stopData(y, usCE|usDE|usUnitCheck)
	}
	d.css.reschedule()
	return cc
}

type ctc9020Snap struct {
	Peer                           uint16
	NotReady, Control, EOF, Notify byte
	Write                          []byte
}

func (d *ctc9020Side) snapshotKind() string { return "9020ctc" }

func (d *ctc9020Side) snapshot() ([]byte, error) {
	return encodeGob(ctc9020Snap{d.peer.addr, d.notReady, d.control, d.eof, d.notify, d.write})
}

func (d *ctc9020Side) restore(data []byte, _ bool) error {
	var snap ctc9020Snap
	if err := decodeGob(data, &snap); err != nil {
		return err
	}
	if snap.Peer != d.peer.addr {
		return fmt.Errorf("9020 CTC peer address changed from %04X to %04X", snap.Peer, d.peer.addr)
	}
	d.notReady, d.control, d.eof, d.notify, d.write = snap.NotReady, snap.Control, snap.EOF, snap.Notify, snap.Write
	return nil
}
