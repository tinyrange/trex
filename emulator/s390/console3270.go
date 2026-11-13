package s390

import (
	"fmt"
	"strings"
)

// 3270 attention identifiers.
const (
	AIDEnter = 0x7d
	AIDClear = 0x6d
	AIDPA1   = 0x6c
	AIDPA2   = 0x6e
	AIDPA3   = 0x6b
	AIDNone  = 0x60
)

var pfAIDs = [25]byte{0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0x7a, 0x7b, 0x7c,
	0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0x4a, 0x4b, 0x4c}

var addrCode = [64]byte{
	0x40, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
	0x50, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
	0x60, 0x61, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
	0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
}

// remoteCommand maps channel write commands to the command codes of the
// 3270 data stream on a remote (tn3270) connection.
var remoteCommand = [256]byte{0x01: 0xf1, 0x05: 0xf5, 0x0d: 0x7e, 0x0f: 0x6f, 0x11: 0xf3}

// Field attribute bits.
const (
	faProtected = 0x20
	faNumeric   = 0x10
	faDisplay   = 0x0c
	faMDT       = 0x01
)

// Console3270 is a locally attached non-SNA 3270 display station. Rows and
// Cols give the current screen size: the default size (24x80) after
// ERASE/WRITE and CLEAR, the alternate size (a model 3, 4 or 5 display's
// 32x80, 43x80 or 27x132) after ERASE/WRITE ALTERNATE.
type Console3270 struct {
	Rows, Cols int
	defRows    int
	defCols    int
	altRows    int
	altCols    int
	alt        bool
	buf        []byte // EBCDIC characters
	fa         []bool // position holds a field attribute
	// Extended attributes per position: on a field attribute position
	// the field's color and highlighting (SFE, MF), elsewhere the
	// character attribute (SA); zero is the default.
	color, hilite []byte
	cursor        int
	aid           byte
	devno         uint16
	css           *ChannelSubsystem
	sense         byte
	Writes        uint64
	locked        bool
	insert        bool
	alarms        uint64 // writes with the WCC sound-alarm bit
	transfer      *Transfer
	inboundSF     []byte // structured field reply awaiting the host's read
	edits         uint64 // operator changes, for Version
	queryPending  bool
	bufAddr       int // current buffer address: where the last write ended
	// Log keeps the text of every completed write for observation.
	Log      []string
	LogLimit int
	// observers receive each outbound write as a 3270 data-stream record
	// (remote command code, WCC, orders) for terminals that mirror the
	// device, such as tn3270 sessions.
	observers map[int]func([]byte)
	nextObs   int
}

func NewConsole3270(rows, cols int) *Console3270 {
	c := &Console3270{Rows: rows, Cols: cols, defRows: rows, defCols: cols, altRows: rows, altCols: cols,
		aid: AIDNone, LogLimit: 256}
	c.clear()
	return c
}

func (t *Console3270) size() int { return t.Rows * t.Cols }

func (t *Console3270) clear() {
	t.buf = make([]byte, t.size())
	t.fa = make([]bool, t.size())
	t.color = make([]byte, t.size())
	t.hilite = make([]byte, t.size())
	t.cursor = 0
	t.bufAddr = 0
}

func (t *Console3270) SenseID() []byte {
	return []byte{0xff, 0x31, 0x74, 0x1d, 0x32, 0x78, 0x02}
}

func (t *Console3270) Reset() { t.sense = 0 }

func (t *Console3270) encodeAddr(a int) []byte {
	if t.size() > 4096 {
		return []byte{byte(a >> 8 & 0x3f), byte(a)}
	}
	return []byte{addrCode[a>>6&0x3f], addrCode[a&0x3f]}
}

func (t *Console3270) decodeAddr(b0, b1 byte) int {
	var a int
	if b0&0xc0 == 0 {
		a = int(b0&0x3f)<<8 | int(b1)
	} else {
		a = int(b0&0x3f)<<6 | int(b1&0x3f)
	}
	return a % t.size()
}

// fieldStart returns the attribute position governing addr, or -1.
func (t *Console3270) fieldStart(a int) int {
	n := t.size()
	for i := 0; i < n; i++ {
		p := (a - i + n) % n
		if t.fa[p] {
			return p
		}
	}
	return -1
}

func (t *Console3270) Exec(cmd byte, data []byte, chained bool) ([]byte, int, byte) {
	switch cmd {
	case 0x03, 0x0b, 0x1b, 0x2b, 0x3b, 0x4b, 0x5b, 0x6b: // NOP, select variants
		return nil, len(data), usCE | usDE
	case 0x04:
		s := t.sense
		t.sense = 0
		return []byte{s}, 0, usCE | usDE
	case 0xe4:
		return t.SenseID(), 0, usCE | usDE
	case 0x11: // write structured field
		if !t.wsf(data) {
			t.sense = 0x80
			return nil, len(data), usCE | usDE | usUnitCheck
		}
		if t.queryPending && t.css != nil {
			// The query reply is solicited by attention; the program
			// retrieves it with READ MODIFIED.
			t.css.Unsolicited(t.devno, usAttention)
		}
		return nil, len(data), usCE | usDE
	case 0x01, 0x05, 0x0d, 0x0f:
		t.write(cmd, data)
		return nil, len(data), usCE | usDE
	case 0x02: // read buffer
		if t.queryPending {
			t.queryPending = false
			return t.queryReply(), 0, usCE | usDE
		}
		if t.aid == AIDStructuredField && t.inboundSF != nil {
			return t.inboundSF, 0, usCE | usDE
		}
		return t.readBuffer(), 0, usCE | usDE
	case 0x06, 0x0e: // read modified, read modified all
		if t.aid == AIDStructuredField && t.inboundSF != nil {
			// Read again until the next request: the host may retry.
			return t.inboundSF, 0, usCE | usDE
		}
		if t.queryPending {
			t.queryPending = false
			return t.queryReply(), 0, usCE | usDE
		}
		// The AID stays until a write restores the keyboard.
		return t.readModified(cmd == 0x0e), 0, usCE | usDE
	}
	t.sense = 0x80
	return nil, 0, usCE | usDE | usUnitCheck
}

func (t *Console3270) write(cmd byte, data []byte) {
	t.Writes++
	if len(t.observers) > 0 {
		rec := append([]byte{remoteCommand[cmd]}, data...)
		for _, f := range t.observers {
			f(rec)
		}
	}
	if cmd == 0x0f { // erase all unprotected
		for i := range t.buf {
			if !t.fa[i] {
				if f := t.fieldStart(i); f < 0 || t.buf[f]&faProtected == 0 {
					t.buf[i] = 0
				}
			}
		}
		first := -1
		for i := range t.buf {
			if t.fa[i] {
				t.buf[i] &^= faMDT
				if first < 0 && t.buf[i]&faProtected == 0 {
					first = (i + 1) % t.size()
				}
			}
		}
		// The cursor moves to the first unprotected character position.
		if first >= 0 {
			t.cursor = first
		} else {
			t.cursor = 0
		}
		t.aid = AIDNone
		t.locked = false
		return
	}
	if cmd == 0x11 { // write structured field: query reply not supported
		return
	}
	if cmd == 0x05 || cmd == 0x0d {
		t.useSize(cmd == 0x0d)
	}
	if len(data) == 0 {
		return
	}
	wcc := data[0]
	if wcc&0x01 != 0 {
		for i := range t.buf {
			if t.fa[i] {
				t.buf[i] &^= faMDT
			}
		}
	}
	if wcc&0x02 != 0 {
		t.aid = AIDNone
		t.locked = false
	}
	if wcc&0x04 != 0 {
		t.alarms++
	}
	pos := t.cursor
	if cmd == 0x05 || cmd == 0x0d {
		pos = 0
	}
	n := t.size()
	var saColor, saHilite byte // character attributes set by SA
	setChar := func(ch byte) {
		t.buf[pos] = ch
		t.fa[pos] = false
		t.color[pos], t.hilite[pos] = saColor, saHilite
		pos = (pos + 1) % n
	}
	for i := 1; i < len(data); i++ {
		b := data[i]
		switch b {
		case 0x1d: // SF
			if i+1 < len(data) {
				i++
				t.buf[pos] = data[i]
				t.fa[pos] = true
				t.color[pos], t.hilite[pos] = 0, 0
				pos = (pos + 1) % n
			}
		case 0x29, 0x2c: // SFE, MF
			if i+1 < len(data) {
				i++
				cnt := int(data[i])
				if b == 0x29 {
					t.buf[pos], t.color[pos], t.hilite[pos] = 0, 0, 0
					t.fa[pos] = true
				}
				for k := 0; k < cnt && i+2 < len(data); k++ {
					if t.fa[pos] {
						t.setExtended(pos, data[i+1], data[i+2])
					}
					i += 2
				}
				pos = (pos + 1) % n
			}
		case 0x11: // SBA
			if i+2 < len(data) {
				pos = t.decodeAddr(data[i+1], data[i+2])
				i += 2
			}
		case 0x13: // IC
			t.cursor = pos
		case 0x05: // PT
			start := pos
			for k := 0; k < n; k++ {
				p := (start + k) % n
				if t.fa[p] && t.buf[p]&faProtected == 0 {
					pos = (p + 1) % n
					break
				}
			}
		case 0x3c: // RA
			if i+3 < len(data) {
				stop := t.decodeAddr(data[i+1], data[i+2])
				ch := data[i+3]
				i += 3
				if ch == 0x08 && i+1 < len(data) {
					i++
					ch = data[i]
				}
				for {
					setChar(ch)
					if pos == stop {
						break
					}
				}
			}
		case 0x12: // EUA
			if i+2 < len(data) {
				stop := t.decodeAddr(data[i+1], data[i+2])
				i += 2
				for pos != stop {
					if !t.fa[pos] {
						if f := t.fieldStart(pos); f < 0 || t.buf[f]&faProtected == 0 {
							t.buf[pos] = 0
						}
					}
					pos = (pos + 1) % n
				}
			}
		case 0x28: // SA
			if i+2 < len(data) {
				switch data[i+1] {
				case 0x00:
					saColor, saHilite = 0, 0
				case 0x41:
					saHilite = data[i+2]
				case 0x42:
					saColor = data[i+2]
				}
			}
			i += 2
		case 0x08: // GE
			if i+1 < len(data) {
				i++
				setChar(data[i])
			}
		default:
			setChar(b)
		}
	}
	t.bufAddr = pos
	if len(t.Log) >= t.LogLimit {
		copy(t.Log, t.Log[1:])
		t.Log = t.Log[:len(t.Log)-1]
	}
	t.Log = append(t.Log, strings.TrimRight(t.Text(), " \n"))
}

// readBuffer transfers the buffer from the current buffer address (where
// the last write left it, 0 after an erase) to its end.
func (t *Console3270) readBuffer() []byte {
	out := []byte{t.aid}
	out = append(out, t.encodeAddr(t.cursor)...)
	for i := t.bufAddr; i < len(t.buf); i++ {
		if t.fa[i] {
			out = append(out, 0x1d, t.buf[i])
		} else {
			out = append(out, t.buf[i])
		}
	}
	return out
}

func (t *Console3270) readModified(all bool) []byte {
	out := []byte{t.aid}
	switch t.aid {
	case AIDClear, AIDPA1, AIDPA2, AIDPA3:
		if !all {
			return out
		}
	}
	out = append(out, t.encodeAddr(t.cursor)...)
	n := t.size()
	unformatted := true
	for i := 0; i < n; i++ {
		if t.fa[i] {
			unformatted = false
			break
		}
	}
	if unformatted {
		for _, b := range t.buf {
			if b != 0 {
				out = append(out, b)
			}
		}
		return out
	}
	for i := 0; i < n; i++ {
		if !t.fa[i] || t.buf[i]&faMDT == 0 {
			continue
		}
		start := (i + 1) % n
		out = append(out, 0x11)
		out = append(out, t.encodeAddr(start)...)
		for p := start; !t.fa[p]; p = (p + 1) % n {
			if t.buf[p] != 0 {
				out = append(out, t.buf[p])
			}
			if (p+1)%n == start {
				break
			}
		}
	}
	return out
}

// Text renders the screen as text rows.
func (t *Console3270) Text() string {
	var sb strings.Builder
	n := t.size()
	hidden := false
	if f := t.fieldStart(0); f >= 0 {
		hidden = t.buf[f]&faDisplay == faDisplay
	}
	for i := 0; i < n; i++ {
		if i > 0 && i%t.Cols == 0 {
			sb.WriteByte('\n')
		}
		if t.fa[i] {
			hidden = t.buf[i]&faDisplay == faDisplay
			sb.WriteByte(' ')
			continue
		}
		if hidden || t.buf[i] == 0 {
			sb.WriteByte(' ')
			continue
		}
		sb.WriteString(EBCDICString(t.buf[i : i+1]))
	}
	return sb.String()
}

// Cursor returns the cursor row and column.
func (t *Console3270) Cursor() (int, int) { return t.cursor / t.Cols, t.cursor % t.Cols }

// SetCursor moves the cursor.
func (t *Console3270) SetCursor(row, col int) {
	t.cursor = (row*t.Cols + col) % t.size()
	t.edits++
}

// Type enters text at the cursor into an unprotected field.
// In insert mode the rest of the field shifts right, which needs a null or
// blank in the field's last position.
func (t *Console3270) Type(s string) error {
	n := t.size()
	t.edits++
	for _, b := range EncodeEBCDIC(s) {
		f := t.fieldStart(t.cursor)
		if t.fa[t.cursor] || (f >= 0 && t.buf[f]&faProtected != 0) {
			return fmt.Errorf("3270: cursor at %d,%d is protected", t.cursor/t.Cols, t.cursor%t.Cols)
		}
		if t.insert {
			end := t.fieldEnd(t.cursor)
			last := (end - 1 + n) % n
			if last != t.cursor && t.buf[last] != 0 && t.buf[last] != 0x40 {
				return fmt.Errorf("3270: field full at %d,%d", t.cursor/t.Cols, t.cursor%t.Cols)
			}
			for p := last; p != t.cursor; p = (p - 1 + n) % n {
				t.buf[p] = t.buf[(p-1+n)%n]
			}
		}
		t.buf[t.cursor] = b
		if f >= 0 {
			t.buf[f] |= faMDT
		}
		t.cursor = (t.cursor + 1) % n
	}
	return nil
}

// Key presses an attention key ("ENTER", "CLEAR", "PA1".."PA3", "PF1".."PF24")
// and presents attention status to the channel subsystem.
//
// Editing keys move the cursor or change unprotected fields without
// attention: TAB, BACKTAB, HOME, NEWLINE, LEFT, RIGHT, UP, DOWN, BACKSPACE
// (erase left), DELETE, INSERT (toggle), RESET, ERASEEOF and ERASEINPUT.
func (t *Console3270) Key(name string) error {
	name = strings.ToUpper(name)
	t.edits++
	if t.edit(name) {
		return nil
	}
	switch {
	case name == "ENTER":
		t.aid = AIDEnter
	case name == "CLEAR":
		t.aid = AIDClear
		t.useSize(false)
	case name == "PA1":
		t.aid = AIDPA1
	case name == "PA2":
		t.aid = AIDPA2
	case name == "PA3":
		t.aid = AIDPA3
	case strings.HasPrefix(name, "PF"):
		var k int
		if _, err := fmt.Sscanf(name[2:], "%d", &k); err != nil || k < 1 || k > 24 {
			return fmt.Errorf("3270: unknown key %q", name)
		}
		t.aid = pfAIDs[k]
	case name == "TAB":
		n := t.size()
		for k := 1; k <= n; k++ {
			p := (t.cursor + k) % n
			if t.fa[p] && t.buf[p]&faProtected == 0 {
				t.cursor = (p + 1) % n
				return nil
			}
		}
		return nil
	case name == "ERASEINPUT":
		// Clears every unprotected field and moves the cursor to the
		// first unprotected position.
		n := t.size()
		first := -1
		for i := 0; i < n; i++ {
			if t.fa[i] {
				if t.buf[i]&faProtected == 0 {
					t.buf[i] &^= faMDT
					if first < 0 {
						first = (i + 1) % n
					}
				}
				continue
			}
			if f := t.fieldStart(i); f >= 0 && t.buf[f]&faProtected == 0 {
				t.buf[i] = 0
			}
		}
		if first >= 0 {
			t.cursor = first
		}
		return nil
	case name == "ERASEEOF":
		if !t.editable(t.cursor) {
			return nil
		}
		n := t.size()
		end := t.fieldEnd(t.cursor) % n
		for p := t.cursor; ; {
			t.buf[p] = 0
			if p = (p + 1) % n; p == end {
				break
			}
		}
		t.markModified(t.cursor)
		return nil
	default:
		return fmt.Errorf("3270: unknown key %q", name)
	}
	t.locked = true
	if t.css != nil {
		t.css.Unsolicited(t.devno, usAttention)
	}
	return nil
}

// AttachConsole binds a console to the channel subsystem for attention.
func (s *ChannelSubsystem) AttachConsole(devno uint16, t *Console3270) error {
	t.css = s
	t.devno = devno
	_, err := s.Attach(devno, t)
	return err
}

// wsf processes WRITE STRUCTURED FIELD: outbound 3270 data stream and
// read-partition query. It reports false for unsupported fields.
func (t *Console3270) wsf(data []byte) bool {
	for len(data) >= 3 {
		n := int(be.Uint16(data))
		if n == 0 {
			n = len(data)
		}
		if n < 3 || n > len(data) {
			return false
		}
		sf := data[:n]
		data = data[n:]
		switch sf[2] {
		case 0x01: // read partition
			if len(sf) >= 5 && sf[3] == 0xff && (sf[4] == 0x02 || sf[4] == 0x03) {
				t.queryPending = true
				continue
			}
			return false
		case 0x40: // outbound 3270DS: partition, command, WCC, orders
			if len(sf) < 5 {
				return false
			}
			var cmd byte
			switch sf[4] {
			case 0xf1:
				cmd = 0x01
			case 0xf5:
				cmd = 0x05
			case 0x7e:
				cmd = 0x0d
			case 0x6f:
				cmd = 0x0f
			default:
				return false
			}
			t.write(cmd, sf[5:])
		case 0xd0: // DFT file transfer (IND$FILE)
			t.inboundSF = nil
			if len(t.observers) > 0 {
				// A remote terminal answers through Inbound.
				rec := append([]byte{0xf3}, sf...)
				for _, f := range t.observers {
					f(rec)
				}
				continue
			}
			if reply := t.dft(sf); reply != nil {
				t.presentInbound(reply)
			}
		case 0x03: // erase/reset: flag X'80' selects the alternate size
			t.useSize(len(sf) > 3 && sf[3]&0x80 != 0)
			t.Writes++
			for _, f := range t.observers {
				f([]byte{0xf5, 0x00})
			}
		default:
			return false
		}
	}
	return true
}

// queryReply is the inbound structured field answering a query: summary,
// usable area and implicit partition for the configured screen.
func (t *Console3270) queryReply() []byte {
	out := []byte{0x88}
	sf := func(b ...byte) {
		out = append(out, byte((len(b)+2)>>8), byte(len(b)+2))
		out = append(out, b...)
	}
	sf(0x81, 0x80, 0x80, 0x81, 0x86, 0x87, 0x95, 0xa6)
	// The usable area is the largest (alternate) size.
	w, h := uint16(t.altCols), uint16(t.altRows)
	buffer := w * h
	sf(0x81, 0x81, 0x01, 0x00, byte(w>>8), byte(w), byte(h>>8), byte(h), 0x00,
		0x00, 0x0a, 0x02, 0xe5, 0x00, 0x02, 0x00, 0x6f, 0x09, 0x0c, byte(buffer>>8), byte(buffer))
	// Color: default green and the seven base colors.
	sf(0x81, 0x86, 0x00, 0x08, 0x00, 0xf4, 0xf1, 0xf1, 0xf2, 0xf2, 0xf3, 0xf3, 0xf4, 0xf4, 0xf5, 0xf5, 0xf6, 0xf6, 0xf7, 0xf7)
	// Distributed data management (DFT file transfer): INLIM, OUTLIM,
	// one subset.
	sf(0x81, 0x95, 0x00, 0x00, dftBuffer>>8, dftBuffer&0xff, dftBuffer>>8, dftBuffer&0xff, 0x01, 0x01)
	// Highlighting: default, blink, reverse video, underscore.
	sf(0x81, 0x87, 0x04, 0x00, 0xf0, 0xf1, 0xf1, 0xf2, 0xf2, 0xf4, 0xf4)
	dw, dh := uint16(t.defCols), uint16(t.defRows)
	sf(0x81, 0xa6, 0x00, 0x00, 0x0b, 0x01, 0x00, byte(dw>>8), byte(dw), byte(dh>>8), byte(dh), byte(w>>8), byte(w), byte(h>>8), byte(h))
	return out
}
