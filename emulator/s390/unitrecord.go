package s390

import "strings"

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
type UnitRecord struct {
	Type  uint16
	cards [][]byte
	// Output holds punched cards or printed lines.
	Output  []string
	sense   byte
	css     *ChannelSubsystem
	devno   uint16
	dropped int    // output lines trimmed from the front of Output
	version uint64 // changes with every card read or line of output
}

// AttachUnitRecord binds a unit-record device to the channel subsystem.
func (s *ChannelSubsystem) AttachUnitRecord(devno uint16, u *UnitRecord) error {
	u.css, u.devno = s, devno
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
func (u *UnitRecord) Reset()          { u.sense = 0 }

func (u *UnitRecord) reader() bool { return u.Type == 0x2540 || u.Type == 0x3505 || u.Type == 0x2501 }

// Load queues cards (ASCII text lines, padded to 80 columns) in the reader.
func (u *UnitRecord) Load(lines []string) {
	for _, l := range lines {
		card := EncodeEBCDIC(l)
		for len(card) < 80 {
			card = append(card, 0x40)
		}
		u.cards = append(u.cards, card[:80])
	}
	u.version++
}

func (u *UnitRecord) Exec(cmd byte, data []byte, chained bool) ([]byte, int, byte) {
	switch {
	case cmd == 0x03: // no-operation
		return nil, 0, usCE | usDE
	case cmd == 0x04: // sense
		s := u.sense
		u.sense = 0
		return []byte{s}, 0, usCE | usDE
	case u.reader() && cmd&3 == 2: // read (feed and stacker select variants)
		if len(u.cards) == 0 {
			u.sense = 0x40 // intervention required: hopper empty
			return nil, 0, usCE | usDE | usUnitCheck
		}
		card := u.cards[0]
		u.cards = u.cards[1:]
		u.version++
		st := byte(usCE | usDE)
		if len(u.cards) == 0 {
			st |= usUnitExcept // last card: end of file
		}
		return card, 0, st
	case !u.reader() && cmd&3 == 1: // write (punch or print, with carriage control)
		u.Output = append(u.Output, strings.TrimRight(EBCDICString(data), " "))
		if len(u.Output) > 20000 {
			u.dropped += 10000
			u.Output = append(u.Output[:0], u.Output[10000:]...)
		}
		u.version++
		return nil, len(data), usCE | usDE
	case !u.reader() && cmd&3 == 3: // control: skip, space, UCS load
		return nil, len(data), usCE | usDE
	case u.reader() && cmd&3 == 3: // feed, select stacker
		return nil, 0, usCE | usDE
	}
	u.sense = 0x80
	return nil, 0, usCE | usDE | usUnitCheck
}
