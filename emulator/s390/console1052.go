package s390

import (
	"fmt"
	"time"
)

// Console1052 is a 1052 printer-keyboard on the console control unit of a
// System/360 Model 65 (IBM 1052 & 2150 FETO/FEDM, SY22-2909): a 3215-style
// line console with the 1052's timing. The printer takes 15.5 characters a
// second from the channel; a write presents channel end when the channel
// stops it, and write with automatic carrier return presents device end
// when the carrier reaches the left margin. Command reject (an invalid
// command) is unit check in the initial status.
//
// The control unit decodes the low seven bits of the command: the 9020's
// diagnostics issue X'89' and X'81' as writes.
type Console1052 struct {
	*Console3215
	// The write in progress, so that HALT I/O can type only what the
	// channel sent: the transcript before it, its data and whether it
	// returns the carrier.
	wLines int
	wPart  string
	wData  []byte
	wCR    bool

	notReady   bool
	cancelRead bool
	readyEnd   bool
}

// 1052 timing.
const (
	typeCycle     = time.Second * 2 / 31 // 15.5 characters a second
	carrierReturn = 200 * time.Millisecond
)

// NewConsole1052 creates a 1052 console.
func NewConsole1052() *Console1052 { return &Console1052{Console3215: NewConsole3215()} }

func (t *Console1052) Reset() {
	t.Console3215.Reset()
	t.cancelRead, t.readyEnd = false, false
}

// AttachConsole1052 binds a 1052 console to the channel subsystem.
func (s *ChannelSubsystem) AttachConsole1052(devno uint16, t *Console1052) error {
	t.css, t.devno = s, devno
	_, err := s.Attach(devno, t)
	return err
}

func console1052Cmd(cmd byte) (byte, bool) {
	c := cmd & 0x7f
	switch c {
	case 0x01, 0x09, 0x0a, 0x03, 0x0b, 0x04:
		return c, true
	}
	return c, false
}

// Blocked implements Blocking: a read waits for the operator.
func (t *Console1052) Blocked(cmd byte) bool {
	c, ok := console1052Cmd(cmd)
	return !t.notReady && ok && t.Console3215.Blocked(c)
}

func (t *Console1052) Exec(cmd byte, data []byte, chained bool) ([]byte, int, byte) {
	c, ok := console1052Cmd(cmd)
	if !ok {
		t.version++
		t.sense = 0x80 // command reject
		return nil, 0, usUnitCheck
	}
	if t.notReady && c != 0x04 {
		t.sense = senseIntervReq
		return nil, 0, usUnitCheck
	}
	if t.notReady {
		t.sense |= senseIntervReq
	}
	if c == 0x01 || c == 0x09 {
		t.version++
		t.wLines, t.wPart = t.dropped+len(t.Lines), t.Partial
		t.wData, t.wCR = append(t.wData[:0], data...), c == 0x09
		t.typeOut(data, t.wCR)
		return nil, len(data), usCE | usDE
	}
	out, used, status := t.Console3215.Exec(c, data, chained)
	if c == 0x0a && t.cancelRead {
		t.cancelRead = false
		status |= usUnitExcept
	}
	return out, used, status
}

// SetReady operates the printer-keyboard's Ready and Not Ready controls.
// A transition to ready presents device end (SY22-2909-2).
func (t *Console1052) SetReady(ready bool) {
	if ready == !t.notReady {
		return
	}
	t.notReady = !ready
	t.version++
	if ready {
		t.readyEnd = true
		t.flushReadyEnd()
	}
}

func (t *Console1052) flushReadyEnd() {
	if !t.readyEnd || t.css == nil {
		return
	}
	x := t.css.bydev[t.devno]
	if !x.pending && !x.working() && x.deAt == 0 {
		t.readyEnd = false
		x.presentDeviceStatus(usDE)
	}
}

func (t *Console1052) TestIOStatus() byte {
	if t.notReady {
		t.sense = senseIntervReq
		return usUnitCheck
	}
	return 0
}

// Cancel enters the characters typed during the current inquiry and
// terminates it with the Cancel key instead of End of Block.
func (t *Console1052) Cancel(text string) error {
	if t.notReady || t.css == nil || !t.css.Waiting(t.devno) {
		return fmt.Errorf("1052 %04X: there is no inquiry to cancel", t.devno)
	}
	t.cancelRead = true
	t.Type(text)
	return nil
}

// typeOut prints channel data: graphics in EBCDIC (code page 037), new line
// (X'15'), line feed (X'25', the carrier stays in its column), horizontal
// tab (X'05', to the next multiple of eight columns) and backspace (X'16',
// the next character overstrikes). Other codes print nothing.
func (t *Console1052) typeOut(data []byte, cr bool) {
	line := []rune(t.Partial)
	col := len(line)
	put := func(r rune) {
		for len(line) < col {
			line = append(line, ' ')
		}
		if col < len(line) {
			if r != ' ' {
				line[col] = r
			}
		} else {
			line = append(line, r)
		}
		col++
	}
	flush := func() {
		t.Partial = string(line)
		t.newline()
		line = line[:0]
	}
	for _, b := range data {
		switch b {
		case 0x15:
			flush()
			col = 0
		case 0x25:
			flush()
		case 0x05:
			col = (col/8 + 1) * 8
		case 0x16:
			col = max(col-1, 0)
		default:
			if r := []rune(EBCDICString([]byte{b})); len(r) == 1 && b >= 0x40 {
				put(r[0])
			}
		}
	}
	t.Partial = string(line)
	if cr {
		t.newline()
	}
}

// CommandTiming implements Timed.
func (t *Console1052) CommandTiming(cmd byte, n int) (time.Duration, time.Duration) {
	switch c, _ := console1052Cmd(cmd); c {
	case 0x01:
		return time.Duration(n) * typeCycle, 0
	case 0x09:
		return time.Duration(n) * typeCycle, carrierReturn
	case 0x0a:
		// The operator ends the read: the keyboard locks, channel end is
		// presented and device end follows the carrier return.
		return urControlXfr, carrierReturn
	case 0x04:
		// The sense byte is sent in forced burst mode with the ending
		// status.
		return urControlXfr, 0
	}
	return 0, 0
}

// Halt implements Halter: HALT I/O after elapsed of a write stops the
// printer after the character in progress. It returns the characters taken
// from the channel and when channel end and device end follow.
func (t *Console1052) Halt(elapsed time.Duration) (int, time.Duration, time.Duration) {
	sent := min(int(elapsed/typeCycle)+1, len(t.wData))
	// Type only what the channel sent.
	if keep := t.wLines - t.dropped; keep >= 0 && keep <= len(t.Lines) {
		t.Lines, t.Partial = t.Lines[:keep], t.wPart
		t.typeOut(t.wData[:sent], t.wCR)
	}
	t.version++
	de := time.Duration(0)
	if t.wCR {
		de = carrierReturn
	}
	return sent, typeCycle - elapsed%typeCycle, de
}
