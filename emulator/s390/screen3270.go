package s390

import "fmt"

// Operator-side 3270 state for interactive frontends: a screen snapshot that
// never reveals nondisplay fields, and the cursor-movement and field-editing
// keys of a display station keyboard.

// Screen3270 is one snapshot of a 3270 presentation space. Text and Attr
// hold one character per buffer position, row-major, without separators.
//
// Attr classifies each position:
//
//	'a'  field attribute (displayed as a blank)
//	'p'  protected, normal intensity      'P'  protected, intensified
//	'u'  unprotected, normal intensity    'U'  unprotected, intensified
//	'n'  unprotected, nondisplay          'N'  protected, nondisplay
//
// Nondisplay positions are always blank in Text.
//
// Color and Hilite hold the effective extended attribute of each position,
// a character attribute (SA) overriding its field's (SFE, MF): Color '0'
// is the default and '1'-'7' the colors X'F1'-X'F7' (blue, red, pink,
// green, turquoise, yellow, white); Hilite '0' is the default, '1' blink,
// '2' reverse video and '4' underscore.
type Screen3270 struct {
	Rows, Cols int
	Cursor     int
	Locked     bool // keyboard inhibited until the program restores it
	Insert     bool
	Text       string
	Attr       string
	Color      string
	Hilite     string
	// Alarms counts writes that sounded the audible alarm.
	Alarms uint64
}

// Screen returns the current presentation space.
func (t *Console3270) Screen() Screen3270 {
	n := t.size()
	text := make([]rune, n)
	attr := make([]byte, n)
	color := make([]byte, n)
	hilite := make([]byte, n)
	cls := byte('u')
	var fc, fh byte
	if f := t.fieldStart(0); f >= 0 {
		cls, fc, fh = fieldClass(t.buf[f]), t.color[f], t.hilite[f]
	}
	for i := 0; i < n; i++ {
		color[i], hilite[i] = '0', '0'
		if t.fa[i] {
			cls, fc, fh = fieldClass(t.buf[i]), t.color[i], t.hilite[i]
			attr[i], text[i] = 'a', ' '
			continue
		}
		attr[i] = cls
		c, h := t.color[i], t.hilite[i]
		if c == 0 {
			c = fc
		}
		if h == 0 {
			h = fh
		}
		if c >= 0xf1 && c <= 0xf7 {
			color[i] = '0' + c - 0xf0
		}
		switch h {
		case 0xf1, 0xf2, 0xf4:
			hilite[i] = '0' + h - 0xf0
		}
		text[i] = ' '
		if cls != 'n' && cls != 'N' && t.buf[i] != 0 {
			if r := []rune(EBCDICString(t.buf[i : i+1])); len(r) == 1 && r[0] >= ' ' {
				text[i] = r[0]
			}
		}
	}
	return Screen3270{Rows: t.Rows, Cols: t.Cols, Cursor: t.cursor, Locked: t.locked, Insert: t.insert,
		Text: string(text), Attr: string(attr), Color: string(color), Hilite: string(hilite), Alarms: t.alarms}
}

func fieldClass(fa byte) byte {
	protected := fa&faProtected != 0
	switch fa & faDisplay {
	case faDisplay:
		if protected {
			return 'N'
		}
		return 'n'
	case 0x08:
		if protected {
			return 'P'
		}
		return 'U'
	}
	if protected {
		return 'p'
	}
	return 'u'
}

// Version changes whenever the program writes the screen or the operator
// changes it.
func (t *Console3270) Version() uint64 { return t.Writes + t.edits }

// Locked reports whether the keyboard is inhibited after an attention key.
func (t *Console3270) Locked() bool { return t.locked }

// fieldEnd returns the position of the next field attribute after p (the
// exclusive end of p's field), or the end of the buffer on an unformatted
// screen.
func (t *Console3270) fieldEnd(p int) int {
	n := t.size()
	for k := 1; k < n; k++ {
		q := (p + k) % n
		if t.fa[q] {
			return q
		}
	}
	return n
}

// editable reports whether p is a character position in an unprotected
// field.
func (t *Console3270) editable(p int) bool {
	if t.fa[p] {
		return false
	}
	f := t.fieldStart(p)
	return f < 0 || t.buf[f]&faProtected == 0
}

// firstEditable returns the first unprotected character position at or
// after p, scanning forward with wraparound.
func (t *Console3270) firstEditable(p int) (int, bool) {
	n := t.size()
	for k := 0; k < n; k++ {
		q := (p + k) % n
		if t.editable(q) {
			return q, true
		}
	}
	return 0, false
}

func (t *Console3270) markModified(p int) {
	if f := t.fieldStart(p); f >= 0 {
		t.buf[f] |= faMDT
	}
}

// edit performs a cursor-movement or editing key and reports whether name
// was one.
func (t *Console3270) edit(name string) bool {
	n := t.size()
	switch name {
	case "LEFT":
		t.cursor = (t.cursor - 1 + n) % n
	case "RIGHT":
		t.cursor = (t.cursor + 1) % n
	case "UP":
		t.cursor = (t.cursor - t.Cols + n) % n
	case "DOWN":
		t.cursor = (t.cursor + t.Cols) % n
	case "HOME":
		if p, ok := t.firstEditable(0); ok {
			t.cursor = p
		} else {
			t.cursor = 0
		}
	case "NEWLINE":
		row := (t.cursor/t.Cols + 1) % t.Rows
		if p, ok := t.firstEditable(row * t.Cols); ok {
			t.cursor = p
		}
	case "BACKTAB":
		// To the start of this field if the cursor is inside it, else to
		// the start of the previous unprotected field.
		for k := 1; k <= n; k++ {
			p := (t.cursor - k + n) % n
			if t.fa[p] && t.buf[p]&faProtected == 0 {
				start := (p + 1) % n
				if start != t.cursor && !t.fa[start] {
					t.cursor = start
					return true
				}
			}
		}
	case "INSERT":
		t.insert = !t.insert
	case "RESET":
		t.insert = false
		t.locked = false
	case "DELETE", "BACKSPACE":
		p := t.cursor
		if name == "BACKSPACE" {
			q := (p - 1 + n) % n
			if !t.editable(q) {
				return true
			}
			p = q
			t.cursor = p
		}
		if !t.editable(p) {
			return true
		}
		end := t.fieldEnd(p)
		for q := p; ; {
			next := (q + 1) % n
			if next == end%n {
				t.buf[q] = 0
				break
			}
			t.buf[q] = t.buf[next]
			q = next
		}
		t.markModified(p)
	default:
		return false
	}
	return true
}

// setExtended applies one SFE or MF attribute type/value pair to the field
// attribute at pos.
func (t *Console3270) setExtended(pos int, typ, value byte) {
	switch typ {
	case 0xc0:
		t.buf[pos] = value
	case 0x41:
		t.hilite[pos] = value
	case 0x42:
		t.color[pos] = value
	}
}

// Observe registers f to receive every outbound write as a remote 3270
// data-stream record (command code, WCC and orders), as a terminal
// attached through tn3270 would. It returns a function that removes f. f
// runs while the machine executes and must not block.
func (t *Console3270) Observe(f func(record []byte)) (cancel func()) {
	if t.observers == nil {
		t.observers = map[int]func([]byte){}
	}
	id := t.nextObs
	t.nextObs++
	t.observers[id] = f
	return func() { delete(t.observers, id) }
}

// DataStream returns an ERASE/WRITE record that reproduces the current
// presentation space, its field attributes and modified flags, and the
// cursor. Extended attributes are included when extended is set.
func (t *Console3270) DataStream(extended bool) []byte {
	wcc := byte(0xc2) // keyboard restore
	if t.locked {
		wcc = 0xc0
	}
	cmd := byte(0xf5)
	if t.alt {
		cmd = 0x7e
	}
	out := []byte{cmd, wcc}
	var curC, curH byte
	for i := 0; i < t.size(); i++ {
		if t.fa[i] {
			if extended && (t.color[i] != 0 || t.hilite[i] != 0) {
				out = append(out, 0x29, 3, 0xc0, t.buf[i], 0x41, t.hilite[i], 0x42, t.color[i])
			} else {
				out = append(out, 0x1d, t.buf[i])
			}
			continue
		}
		if extended && (t.color[i] != curC || t.hilite[i] != curH) {
			if t.color[i] == 0 && t.hilite[i] == 0 {
				out = append(out, 0x28, 0x00, 0x00)
			} else {
				out = append(out, 0x28, 0x42, t.color[i], 0x28, 0x41, t.hilite[i])
			}
			curC, curH = t.color[i], t.hilite[i]
		}
		b := t.buf[i]
		if b != 0 && b < 0x40 {
			b = 0x40 // would be read as an order
		}
		out = append(out, b)
	}
	out = append(out, 0x11)
	out = append(out, t.encodeAddr(t.cursor)...)
	return append(out, 0x13)
}

// Inbound applies an inbound record from a remote terminal (the AID,
// cursor address and modified fields of a read-modified response) and
// presents attention, as pressing the attention key on this terminal does.
func (t *Console3270) Inbound(rec []byte) {
	if len(rec) == 0 {
		return
	}
	if rec[0] == AIDStructuredField {
		// A remote terminal's reply to a structured field (file
		// transfer); query replies are answered by the display itself.
		if len(rec) >= 4 && rec[3] == 0xd0 {
			t.edits++
			t.presentInbound(rec)
		}
		return
	}
	t.edits++
	aid := rec[0]
	switch aid {
	case AIDClear:
		t.useSize(false)
	case AIDPA1, AIDPA2, AIDPA3:
	default:
		if len(rec) < 3 {
			break
		}
		t.cursor = t.decodeAddr(rec[1], rec[2])
		data := rec[3:]
		n := t.size()
		formatted := false
		for _, f := range t.fa {
			if f {
				formatted = true
				break
			}
		}
		if !formatted {
			for i := range t.buf {
				t.buf[i] = 0
			}
			copy(t.buf, data)
			break
		}
		for len(data) >= 3 && data[0] == 0x11 {
			start := t.decodeAddr(data[1], data[2])
			data = data[3:]
			k := 0
			for k < len(data) && data[k] != 0x11 {
				k++
			}
			field := data[:k]
			data = data[k:]
			if t.fa[start] || !t.editable(start) {
				continue
			}
			end := t.fieldEnd(start) % n
			for p, j := start, 0; ; j++ {
				t.buf[p] = 0
				if j < len(field) {
					t.buf[p] = field[j]
				}
				if p = (p + 1) % n; p == end {
					break
				}
			}
			t.markModified(start)
		}
	}
	t.aid = aid
	t.locked = true
	if t.css != nil {
		t.css.Unsolicited(t.devno, usAttention)
	}
}

// Model sizes: the alternate screen of a 3278/3279 model 2 to 5.
var modelSizes = map[int][2]int{2: {24, 80}, 3: {32, 80}, 4: {43, 80}, 5: {27, 132}}

// ModelSize returns the alternate screen size of a 3278/3279 model.
func ModelSize(model int) (rows, cols int, ok bool) {
	s, ok := modelSizes[model]
	return s[0], s[1], ok
}

// SetModel makes the display a 3278/3279 model 2-5: a 24x80 default
// screen and the model's alternate screen. Programs learn the alternate
// size from the query reply, normally when a user logs on. A display
// showing an alternate screen of another size is cleared to its default
// screen; otherwise the current screen is unchanged.
func (t *Console3270) SetModel(model int) error {
	rows, cols, ok := ModelSize(model)
	if !ok {
		return fmt.Errorf("3270: model must be 2, 3, 4 or 5")
	}
	resize := t.alt && (rows != t.altRows || cols != t.altCols) || !t.alt && (t.Rows != 24 || t.Cols != 80)
	t.defRows, t.defCols, t.altRows, t.altCols = 24, 80, rows, cols
	if resize {
		t.useSize(false)
		t.Writes++
	}
	return nil
}

// Model returns the display's model number (2 when the alternate size is
// not a standard model's).
func (t *Console3270) Model() int {
	for m, s := range modelSizes {
		if s[0] == t.altRows && s[1] == t.altCols {
			return m
		}
	}
	return 2
}

// Alternate reports whether the display shows its alternate screen.
func (t *Console3270) Alternate() bool { return t.alt }

// useSize selects the default or alternate screen and clears it.
func (t *Console3270) useSize(alt bool) {
	t.alt = alt
	if alt {
		t.Rows, t.Cols = t.altRows, t.altCols
	} else {
		t.Rows, t.Cols = t.defRows, t.defCols
	}
	t.clear()
}
