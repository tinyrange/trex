package s390

import (
	"strings"
	"time"
)

// Console3215 is a 3215 console printer-keyboard: a line-mode console whose
// reads wait for the operator. Output is decoded from EBCDIC (code page 037).
type Console3215 struct {
	css   *ChannelSubsystem
	devno uint16
	// Lines holds completed output lines; Partial the current line.
	Lines   []string
	Partial string
	input   []string
	sense   byte
	dropped int    // lines trimmed from the front of Lines
	version uint64 // changes with every output or input
}

// NewConsole3215 creates a 3215 console.
func NewConsole3215() *Console3215 { return &Console3215{} }

func (t *Console3215) SenseID() []byte { return nil }
func (t *Console3215) Reset()          { t.sense = 0 }

// Blocked reports whether a read must wait for typed input.
// A read that blocks changes the console's Version, as frontends show that
// the program is waiting.
func (t *Console3215) Blocked(cmd byte) bool {
	if cmd == 0x0a && len(t.input) == 0 {
		t.version++
		return true
	}
	return false
}

func (t *Console3215) Exec(cmd byte, data []byte, chained bool) ([]byte, int, byte) {
	t.version++
	switch cmd {
	case 0x01, 0x09: // write without / with carrier return
		t.Partial += strings.TrimRight(EBCDICString(data), "\x00")
		if cmd == 0x09 {
			t.newline()
		}
		return nil, len(data), usCE | usDE
	case 0x0a: // read inquiry
		line := t.input[0]
		t.input = t.input[1:]
		t.Partial += line
		t.newline()
		return EncodeEBCDIC(line), 0, usCE | usDE
	case 0x03, 0x0b: // no-operation, audible alarm
		return nil, 0, usCE | usDE
	case 0x04: // sense
		s := t.sense
		t.sense = 0
		return []byte{s}, 0, usCE | usDE
	}
	t.sense = 0x80 // command reject
	return nil, 0, usCE | usDE | usUnitCheck
}

func (t *Console3215) newline() {
	t.Lines = append(t.Lines, t.Partial)
	if len(t.Lines) > 10000 {
		t.dropped += 5000
		t.Lines = append(t.Lines[:0], t.Lines[5000:]...)
	}
	t.Partial = ""
}

// Type enters a line as the operator does: a waiting read completes;
// otherwise the line is queued and the REQUEST key presents attention so the
// program reads it.
func (t *Console3215) Type(line string) {
	t.version++
	t.input = append(t.input, line)
	if t.css == nil {
		return
	}
	if t.css.Resume(t.devno) {
		return
	}
	t.css.Unsolicited(t.devno, usAttention)
}

// AttachLineConsole binds a 3215 console to the channel subsystem.
func (s *ChannelSubsystem) AttachLineConsole(devno uint16, t *Console3215) error {
	t.css, t.devno = s, devno
	_, err := s.Attach(devno, t)
	return err
}

// Request presents attention, as the REQUEST key does.
func (t *Console3215) Request() { t.css.Unsolicited(t.devno, usAttention) }

// Text returns the console transcript.
func (t *Console3215) Text() string {
	return strings.Join(append(append([]string(nil), t.Lines...), t.Partial), "\n")
}

// UnitRecord is a card reader (2540R, 3505), card punch (2540P, 3525) or
// line printer (1403, 3211). A reader supplies queued 80-column cards and
// then signals end of file; punch and printer output is retained as text.
//
// Commands follow the IBM 2821 Control Unit (GA24-3312): a command the
// device does not accept is rejected with unit check alone in the initial
// status (sense bit 0, command reject).
type UnitRecord struct {
	Type  uint16
	cards [][]byte
	// Output holds punched cards or printed lines.
	Output  []string
	sense   byte
	css     *ChannelSubsystem
	devno   uint16
	port    *unit2821Port
	dropped int    // output lines trimmed from the front of Output
	version uint64 // changes with every card read or line of output

	chanT, devT time.Duration // timing of the last command (CommandTiming)
	buffer      []byte        // printer control unit's print-line buffer

	// Printer state: the number of commands executed in the current chain,
	// the previous command, whether the UCS load is gated, and whether a
	// print scan has completed (the print-line-complete check plane).
	chainPos int
	prevCmd  byte
	pr       printer // printer.go

	// Reader state: the previous command's type and whether a card has been
	// read since the reader was made ready (initial run-in).
	last    byte
	started bool
	eof     bool // the end-of-file key: unit exception once the hopper empties

	punchStopped bool
	punched      [][]byte    // 80-column EBCDIC cards from a 2540 punch
	cardPeer     *UnitRecord // the other device on a paired 2821
	diagColumns  [160]byte
	diagReady    bool
}

// Reader command types (2821 GA24-3312, 2540 Card Read-Punch).
const (
	rdNone       = 0
	rdFeed       = 'A' // type AA: read, feed and select stacker
	rdNoFeed     = 'B' // type AB: read and no feed or stacker select
	rdStack      = 'S' // type BA: feed and select stacker
	senseCmdRej  = 0x80
	senseIntReq  = 0x40
	senseUnusual = 0x02 // unusual command sequence
)

// Unit-record timing, of the order of a 2540 reader (1,000 cards a minute),
// a buffered 1403 printer (1,100 lines a minute) on a multiplexer channel.
const (
	cardCycle    = 60 * time.Millisecond
	printCycle   = 55 * time.Millisecond
	printScan    = printCycle            // a diagnostic write's print scan
	spaceTime    = 10 * time.Millisecond // carriage motion of one line
	urByte       = 10 * time.Microsecond // multiplexer-channel transfer
	urControlXfr = 10 * time.Microsecond
)

// CommandTiming implements Timed. A reader sends a card from its read
// buffer (channel end) and then feeds the next card (device end); a read
// without feed ends with channel end and device end together. A print line
// is loaded into the printer's buffer (channel end) and then printed
// (device end). Feeds, carriage controls and stacker selects present channel
// end at once and device end when the motion completes. No-operation and
// commands rejected at initiation are immediate.
func (u *UnitRecord) CommandTiming(cmd byte, n int) (time.Duration, time.Duration) {
	if cmdIsRead(cmd) && !u.printer() && u.chanT > urControlXfr {
		// The channel stops the buffer transfer when its count runs out.
		return min(u.chanT, urControlXfr+time.Duration(n)*urByte), u.devT
	}
	return u.chanT, u.devT
}

// AttachUnitRecord binds a unit-record device to the channel subsystem.
func (s *ChannelSubsystem) AttachUnitRecord(devno uint16, u *UnitRecord) error {
	u.css, u.devno = s, devno
	if u.printer() {
		u.printScan(false, false)
	}
	_, err := s.Attach(devno, u)
	return err
}

// Reader reports whether the device is a card reader.
func (u *UnitRecord) Reader() bool { return u.reader() }

// Queued returns the number of cards waiting in a reader's hopper.
func (u *UnitRecord) Queued() int { return len(u.cards) }

// Submit loads a deck into the reader and readies it, presenting device
// end as pressing the reader's start key does.
func (u *UnitRecord) Submit(lines []string) {
	u.Load(lines)
	if u.css != nil {
		u.css.Unsolicited(u.devno, usDE)
	}
}

func (u *UnitRecord) SenseID() []byte { return nil }
func (u *UnitRecord) Reset() {
	u.sense = 0
	if u.port != nil {
		u.port.state = unit2821State{}
		u.port.control.state = switch2821State{}
	}
}

// StartChain and EndChain implement ChainEnd: printers check a command's
// position in its chain.
func (u *UnitRecord) StartChain() { u.chainPos, u.pr.ucsGated = 0, false }
func (u *UnitRecord) EndChain()   {}

func (u *UnitRecord) reader() bool { return u.Type == 0x2540 || u.Type == 0x3505 || u.Type == 0x2501 }

func (u *UnitRecord) printer() bool { return u.Type == 0x1403 || u.Type == 0x3211 }

// SetPunchReady operates the 2540 punch's start and stop keys. Starting it
// presents device end, which the channel must accept before a new operation.
func (u *UnitRecord) SetPunchReady(ready bool) {
	if u.punchStopped == !ready {
		return
	}
	u.punchStopped = !ready
	u.version++
	if ready && u.css != nil {
		u.css.Unsolicited(u.devno, usDE)
	}
}

func (u *UnitRecord) TestIOStatus() byte {
	if u.punchStopped {
		return usUnitCheck
	}
	return 0
}

// Load queues cards (ASCII text lines, padded to 80 columns) in the reader
// with the end-of-file key on, and readies it: the next read starts a new
// run-in.
func (u *UnitRecord) Load(lines []string) {
	for _, l := range lines {
		u.cards = append(u.cards, cardImage(EncodeEBCDIC(l)))
	}
	u.readyReader()
}

func cardImage(data []byte) []byte {
	card := make([]byte, 80)
	n := copy(card, data)
	for i := n; i < len(card); i++ {
		card[i] = 0x40
	}
	return card
}

func (u *UnitRecord) readyReader() {
	u.diagReady = false
	if len(u.cards) > 0 {
		u.eof = true
		u.started, u.last = false, rdNone
	}
	u.version++
}

// reject rejects a command at initial selection.
func (u *UnitRecord) reject() ([]byte, int, byte) {
	u.sense = senseCmdRej
	u.chanT, u.devT = 0, 0
	return nil, 0, usUnitCheck
}

func (u *UnitRecord) Exec(cmd byte, data []byte, chained bool) ([]byte, int, byte) {
	u.chanT, u.devT = 0, 0
	first, prev := u.chainPos == 0, u.prevCmd
	u.chainPos++
	u.prevCmd = cmd
	switch {
	case cmd == 0x03: // no-operation
		return nil, 0, usCE | usDE
	case cmd&0xf == 0x04 && (cmd == 0x04 || !u.printer()): // sense
		// The 2540 does not examine the modifier bits; printers accept
		// only X'04'.
		u.chanT = urControlXfr
		s := u.sense
		if u.punchStopped {
			s |= senseIntReq
		}
		u.sense = 0
		return []byte{s}, 0, usCE | usDE
	case cmd == 0xc6 && (u.Type == 0x2540 || u.Type == 0x2541):
		// Diagnostic check read transfers one check-plane byte per
		// card column. The translator check belongs in the first
		// byte only (2821 GA24-3312).
		checks := make([]byte, 80)
		if u.sense&0x08 != 0 {
			checks[0] = 0x02
		}
		u.chanT = urControlXfr + time.Duration(len(checks))*urByte
		return checks, 0, usCE | usDE
	case cmd == 0xc2 && u.Type == 0x2541: // 2821 diagnostic punch buffer read
		card := cardImage(nil)
		if len(u.punched) > 0 {
			card = u.punched[len(u.punched)-1]
		}
		u.chanT = urControlXfr + time.Duration(len(card))*urByte
		return card, 0, usCE | usDE
	case cmd&0x3f == 0x25 && cmd>>6 != 3 && u.Type == 0x2541:
		return u.diagnosticWrite(data)
	}
	switch {
	case u.reader():
		return u.readerExec(cmd)
	case u.printer():
		return u.printerExec(cmd, data, first, prev)
	}
	return u.punchExec(cmd, data)
}

// readerExec executes a 2540-style reader command.
func (u *UnitRecord) readerExec(cmd byte) ([]byte, int, byte) {
	if u.cardPeer != nil {
		punch := u.css.bydev[u.cardPeer.devno]
		if punch.op != nil && punch.op.Cmd&0x3f == 0x25 {
			return u.reject()
		}
	}
	var kind byte
	switch cmd &^ 0x20 {
	case 0x02, 0x42, 0x82, 0xd2: // read, feed, select stacker; compatibility read
		kind = rdFeed
	case 0xc2: // read, no feed
		kind = rdNoFeed
	case 0x03, 0x43, 0x83: // feed and select stacker
		if cmd&0x20 == 0 {
			return u.reject()
		}
		kind = rdStack
	default:
		return u.reject()
	}
	if kind == rdStack && (!u.started || u.last != rdNoFeed) {
		return u.reject() // must follow a read without feed
	}
	if len(u.cards) == 0 {
		u.last = rdNone
		if u.eof && u.started {
			u.eof = false
			return nil, 0, usUnitExcept // end of file, at initial selection
		}
		u.sense = senseIntReq // hopper empty: not ready
		return nil, 0, usUnitCheck
	}
	unusual := kind != rdStack && u.last == rdNoFeed
	u.started = true
	u.last = kind
	if kind == rdStack {
		u.cards = u.cards[1:]
		u.diagReady = false
		u.version++
		u.devT = cardCycle
		return nil, 0, usCE | usDE
	}
	card := u.cards[0]
	status := byte(usCE | usDE)
	if u.diagReady {
		var sense byte
		card, sense = u.readDiagnosticCard(cmd&0x20 != 0)
		u.sense = sense
		if sense != 0 {
			status |= usUnitCheck
		}
	}
	u.chanT = urControlXfr + time.Duration(len(card))*urByte
	if unusual {
		u.sense = senseUnusual
		status |= usUnitCheck
	}
	if kind == rdNoFeed {
		return card, 0, status
	}
	u.diagReady = false
	u.cards = u.cards[1:]
	u.version++
	u.devT = cardCycle
	return card, 0, status
}

// punchExec executes a punch command: write, feed and select stacker.
func (u *UnitRecord) punchExec(cmd byte, data []byte) ([]byte, int, byte) {
	if u.Type == 0x2541 {
		switch cmd &^ 0x30 { // column-binary and punch-feed-read modifiers
		case 0x01, 0x41, 0x81:
		default:
			return u.reject()
		}
		if u.punchStopped {
			return nil, 0, usUnitCheck
		}
		data = data[:min(80, len(data))]
		u.punched = append(u.punched, cardImage(data))
		if len(u.punched) > 20000 {
			u.punched = append(u.punched[:0], u.punched[10000:]...)
		}
	}
	if cmd&3 != 1 {
		return u.reject()
	}
	u.Output = append(u.Output, strings.TrimRight(EBCDICString(data), " "))
	if len(u.Output) > 20000 {
		u.dropped += 10000
		u.Output = append(u.Output[:0], u.Output[10000:]...)
	}
	u.version++
	u.chanT, u.devT = urControlXfr+time.Duration(len(data))*urByte, cardCycle
	return nil, len(data), usCE | usDE
}
