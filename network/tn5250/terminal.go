// Package tn5250 implements bounded Telnet negotiation and the5250 display
// stream over caller-supplied bytes. It has no socket or process dependency.
package tn5250

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"golang.org/x/text/encoding/charmap"
	"maps"
	"slices"
	"sort"
	"strings"
)

type Terminal struct {
	TerminalType        string
	Environment         map[string]string
	data                [1920]byte
	attributes          [1920]byte
	markers             [1920]bool
	position, cursor    int
	attribute           byte
	readMode            byte
	formatHeader        string
	inputCancelled      bool
	state, verb, option byte
	record, sub         []byte
	local, remote       [256]bool
	LastRecord          []byte
	Records             int
	Fields              []Field
	tap                 bool
	tapped              [][]byte // applied records, kept while tap is on
	forward             []byte   // the last applied record as a relay forwards it
	// Lenient skips a record that cannot be applied (counting it in
	// Skipped and keeping its error in SkipError) instead of failing Feed,
	// for an interactive session that should outlive one unsupported
	// display operation. Each record applies atomically, so a skipped one
	// leaves the display as it was.
	Lenient   bool
	Skipped   int
	SkipError string
}

type Field struct {
	Row, Column, Length int
	Format              uint16
	Attribute           byte
	Modified            bool
	offset              int
	controlWords        string
}

// checkpointCopy includes unconsumed input, partial records and protocol state.
func (t *Terminal) checkpointCopy() Terminal {
	copy := *t
	copy.record = slices.Clone(t.record)
	copy.sub = slices.Clone(t.sub)
	copy.Fields = slices.Clone(t.Fields)
	copy.LastRecord = slices.Clone(t.LastRecord)
	copy.tapped = slices.Clone(t.tapped)
	copy.Environment = maps.Clone(t.Environment)
	return copy
}

// CaptureCheckpoint returns a reusable rewind for this protocol endpoint.
func (t *Terminal) CaptureCheckpoint() (func() error, error) {
	saved := t.checkpointCopy()
	return func() error {
		*t = saved.checkpointCopy()
		return nil
	}, nil
}

func New() *Terminal {
	t := &Terminal{TerminalType: "IBM-3179-2"}
	t.clear()
	return t
}
func (t *Terminal) clear() {
	for i := range t.data {
		t.data[i] = 0x40
		t.attributes[i] = 0x20
		t.markers[i] = false
	}
	t.position, t.cursor, t.attribute = 0, 0, 0x20
	t.Fields = nil
	t.readMode = 0
	t.formatHeader = ""
}
func (t *Terminal) Rows() []string {
	rows := make([]string, 24)
	for y := range rows {
		var b strings.Builder
		for x := 0; x < 80; x++ {
			i := y*80 + x
			v := t.data[i]
			if v == 0 || t.attributes[i]&7 == 7 {
				b.WriteByte(' ')
			} else if v == 0x1f {
				b.WriteRune('█')
			} else {
				r := charmap.CodePage037.DecodeByte(v)
				if r < 32 {
					r = ' '
				}
				b.WriteRune(r)
			}
		}
		rows[y] = strings.TrimRight(b.String(), " ")
	}
	return rows
}
func (t *Terminal) normalizeAttributes() {
	attr := byte(0x20)
	for i := range t.data {
		if t.markers[i] {
			attr = t.attributes[i]
		} else {
			t.attributes[i] = attr
		}
	}
}
func (t *Terminal) Cursor() (int, int) { return t.cursor/80 + 1, t.cursor%80 + 1 }
func address(row, col byte) (int, error) {
	if row < 1 || row > 24 || col < 1 || col > 80 {
		return 0, fmt.Errorf("tn5250: invalid address%d/%d", row, col)
	}
	return (int(row)-1)*80 + int(col) - 1, nil
}
func (t *Terminal) put(v byte) error {
	if t.position >= len(t.data) {
		return fmt.Errorf("tn5250: write past screen")
	}
	if v >= 0x20 && v <= 0x3f {
		t.markers[t.position] = true
		t.attribute = v
		t.data[t.position] = 0x40
	} else {
		t.markers[t.position] = false
		t.data[t.position] = v
	}
	t.attributes[t.position] = t.attribute
	t.position++
	return nil
}

// Apply validates and applies one unescaped GDS record atomically. Unknown
// display commands/orders fail explicitly rather than inventing a screen.
func (t *Terminal) Apply(record []byte) error {
	return t.apply(record, nil)
}

func (t *Terminal) apply(record []byte, replies *[]byte) error {
	if len(record) < 10 || len(record) > 65535 || int(binary.BigEndian.Uint16(record)) != len(record) || binary.BigEndian.Uint16(record[2:]) != 0x12a0 || record[6] < 4 || 6+int(record[6]) > len(record) {
		return fmt.Errorf("tn5250: invalid GDS record")
	}
	if record[9] == 0x0b || record[9] == 0x0c {
		if len(record) != 10 {
			return fmt.Errorf("tn5250: invalid message-light record")
		}
		t.LastRecord = append([]byte(nil), record...)
		t.forward = t.LastRecord
		t.Records++
		return nil
	}
	if record[9] == 0x0a {
		if len(record) != 10 {
			return fmt.Errorf("tn5250: invalid cancel-invite record")
		}
		t.inputCancelled = true
		t.LastRecord = append([]byte(nil), record...)
		t.forward = t.LastRecord
		t.Records++
		return nil
	}
	if record[9] == 4 && bytes.Equal(record[6+int(record[6]):], []byte{4, 2}) {
		t.LastRecord = append([]byte(nil), record...)
		t.forward = t.LastRecord
		t.Records++
		return nil
	}
	if record[9] != 1 && record[9] != 2 && record[9] != 3 && record[9] != 5 {
		return fmt.Errorf("tn5250: unsupported GDS opcode%02x", record[9])
	}
	next := *t
	next.Fields = append([]Field(nil), t.Fields...)
	b := record[6+int(record[6]):]
	write := false
	// A record that defines input fields without placing the cursor leaves
	// it at the home position: the first input field the operator can key
	// (SA21-9247, Insert Cursor order). Other writes leave it alone.
	defined, placed := false, false
	// forward copies the record for other display stations, adding the
	// ending attributes this terminal supplies (see the SF order) so that
	// a client which does not supply them still ends each field there.
	// It also writes nulls outside input fields as blanks: they look the
	// same on a display station, and some clients draw a null with no width.
	forward := append([]byte(nil), record[:6+int(record[6])]...)
	fb := slices.Clone(b) // b as forwarded
	copied := 0
	inField := func(from, to int) bool { // any of positions from..to is field data
		for _, f := range next.Fields {
			if from < f.offset+f.Length && f.offset <= to {
				return true
			}
		}
		return false
	}
	for i := 0; i < len(b); {
		v := b[i]
		i++
		if v == 4 {
			if i == len(b) {
				return fmt.Errorf("tn5250: truncated command")
			}
			cmd := b[i]
			i++
			write = false
			switch cmd {
			case 0xf3: // Write Structured Field, RFC 1205 §5.3.
				if len(b)-i < 5 || !bytes.Equal(b[i:i+5], []byte{0, 5, 0xd9, 0x70, 0}) {
					return fmt.Errorf("tn5250: unsupported structured field")
				}
				i += 5
				reply, err := next.queryReply()
				if err != nil {
					return err
				}
				if replies != nil {
					*replies = append(*replies, reply...)
				}
			case 0x21: // Write Error Code (SA21-9247): text, attributes and an
				// optional insert-cursor order for the error line (row 24).
				// The host locks input until the operator resets; the next
				// key this client sends is that reset's following input.
				next.position = 23 * 80
				write = true
			case 0x12: // Restore Screen marker; actual state follows as WTD orders.
			case 0x40:
				next.clear()
			case 0x50:
				next.Fields = nil
				next.formatHeader = ""
			case 0x11:
				if i+2 > len(b) {
					return fmt.Errorf("tn5250: truncated WTD control")
				}
				i += 2
				write = true
			case 0x42, 0x52, 0x82:
				if i+2 > len(b) {
					return fmt.Errorf("tn5250: truncated read control")
				}
				i += 2
				next.readMode = cmd
				next.inputCancelled = false
			default:
				return fmt.Errorf("tn5250: unsupported display command%02x", cmd)
			}
			continue
		}
		if !write {
			return fmt.Errorf("tn5250: data outside WTD")
		}
		switch v {
		case 0x1d:
			if i+5 > len(b) {
				return fmt.Errorf("tn5250: truncated SF")
			}
			format := binary.BigEndian.Uint16(b[i:])
			i += 2
			if format&0xc000 != 0x4000 {
				return fmt.Errorf("tn5250: unsupported field format%04x", format)
			}
			// Standard keyboard (8100) and DBCS-open (8280) both allow
			// single-byte IBM037 input. Preserve the FCWs for Save Screen.
			start := i
			for i+2 <= len(b) {
				word := binary.BigEndian.Uint16(b[i:])
				if word != 0x8100 && word != 0x8280 {
					break
				}
				i += 2
			}
			controls := string(b[start:i])
			if i+3 > len(b) {
				return fmt.Errorf("tn5250: truncated SF attribute or length")
			}
			attr := b[i]
			i++
			if attr&0xe0 != 0x20 {
				return fmt.Errorf("tn5250: unsupported field control word %02x%02x", attr, b[i])
			}
			n := int(binary.BigEndian.Uint16(b[i:]))
			i += 2
			if n < 1 || next.position+1+n > 1920 {
				return fmt.Errorf("tn5250: field outside screen")
			}
			if err := next.put(attr); err != nil {
				return err
			}
			field := Field{Row: next.position/80 + 1, Column: next.position%80 + 1, Length: n, Format: format, Attribute: attr, offset: next.position, controlWords: controls}
			defined = true
			// The display station supplies the field's ending attribute
			// (X'20') at the position after the field (IBM i Set Field
			// API, QsnSetFld), unless an attribute is already there.
			if end := field.offset + n; end < 1920 && !next.markers[end] {
				next.markers[end] = true
				next.attributes[end] = 0x20
				next.data[end] = 0x40
				forward = append(forward, fb[copied:i]...)
				forward = append(forward, 0x11, byte(end/80+1), byte(end%80+1), 0x20, 0x11, byte(field.Row), byte(field.Column))
				copied = i
			}
			// A field written over part of an earlier one (a window or
			// overlay drawn without clearing the format table) replaces
			// it, as on a display station; the same position redefines it.
			replaced := false
			kept := next.Fields[:0]
			for _, f := range next.Fields {
				switch {
				case f.offset == field.offset:
					if !replaced {
						kept = append(kept, field)
						replaced = true
					}
				case field.offset-1 < f.offset+f.Length && f.offset-1 < field.offset+n:
					// overlapped (including attribute bytes): dropped
				default:
					kept = append(kept, f)
				}
			}
			next.Fields = kept
			if !replaced {
				if len(next.Fields) >= 256 {
					return fmt.Errorf("tn5250: too many fields")
				}
				next.Fields = append(next.Fields, field)
			}
		case 0x11, 0x13, 0x14:
			if i+2 > len(b) {
				return fmt.Errorf("tn5250: truncated address order")
			}
			at, err := address(b[i], b[i+1])
			if err != nil {
				return err
			}
			i += 2
			if v == 0x11 {
				next.position = at
			} else {
				next.cursor = at
				placed = true
			}
		case 0x02:
			if i+3 > len(b) {
				return fmt.Errorf("tn5250: truncated RA")
			}
			at, err := address(b[i], b[i+1])
			if err != nil {
				return err
			}
			value := b[i+2]
			if value == 0 && at >= next.position && !inField(next.position, at) {
				fb[i+2] = 0x40
			}
			i += 3
			if at < next.position {
				return fmt.Errorf("tn5250: backward RA")
			}
			for next.position <= at {
				if err := next.put(value); err != nil {
					return err
				}
			}
		case 0x01:
			if i == len(b) || int(b[i]) > len(b)-i-1 {
				return fmt.Errorf("tn5250: truncated SOH")
			}
			next.formatHeader = string(b[i+1 : i+1+int(b[i])])
			i += 1 + int(b[i])
		case 0x10:
			if i+2 > len(b) {
				return fmt.Errorf("tn5250: truncated TD")
			}
			n := int(binary.BigEndian.Uint16(b[i:]))
			i += 2
			if n > len(b)-i {
				return fmt.Errorf("tn5250: truncated TD bytes")
			}
			for k, value := range b[i : i+n] {
				if next.position >= 1920 {
					return fmt.Errorf("tn5250: TD past screen")
				}
				if value == 0 && !inField(next.position, next.position) {
					fb[i+k] = 0x40
				}
				next.data[next.position] = value
				next.markers[next.position] = false
				next.attributes[next.position] = next.attribute
				next.position++
			}
			i += n
		default:
			// DSPPFM uses 1f as a one-cell graphic for a byte it cannot
			// display. Keep it in the regeneration buffer for Save Screen.
			if v > 0 && v < 0x1f {
				return fmt.Errorf("tn5250: unsupported WTD order%02x", v)
			}
			if v == 0 && !inField(next.position, next.position) {
				fb[i-1] = 0x40
			}
			if err := next.put(v); err != nil {
				return err
			}
		}
	}
	forward = append(forward, fb[copied:]...)
	binary.BigEndian.PutUint16(forward, uint16(len(forward)))
	next.forward = forward
	if defined && !placed {
		for _, f := range next.Fields {
			if f.Format&0x2000 == 0 {
				next.cursor = f.offset
				break
			}
		}
	}
	next.LastRecord = append([]byte(nil), record...)
	next.Records++
	next.normalizeAttributes()
	*t = next
	return nil
}
func quote(data []byte) []byte { return bytes.ReplaceAll(data, []byte{255}, []byte{255, 255}) }
func subReply(option byte, data []byte) []byte {
	b := []byte{255, 250, option}
	b = append(b, quote(data)...)
	return append(b, 255, 240)
}
func (t *Terminal) subReply() ([]byte, error) {
	if len(t.sub) == 0 {
		return nil, fmt.Errorf("tn5250: empty subnegotiation")
	}
	if t.option == 24 && t.sub[0] == 1 {
		return subReply(24, append([]byte{0}, []byte(t.TerminalType)...)), nil
	}
	if t.option == 39 && t.sub[0] == 1 {
		b := []byte{0}
		keys := make([]string, 0, len(t.Environment))
		for k := range t.Environment {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i] == "USER" {
				return keys[j] != "USER"
			}
			if keys[j] == "USER" {
				return false
			}
			return keys[i] < keys[j]
		})
		for _, k := range keys {
			kind := byte(3)
			if k == "USER" {
				kind = 0
			}
			b = append(b, kind)
			for partIndex, part := range []string{k, t.Environment[k]} {
				for _, v := range []byte(part) {
					if v <= 3 {
						b = append(b, 2)
					}
					b = append(b, v)
				}
				if partIndex == 0 {
					b = append(b, 1)
				}
			}
		}
		return subReply(39, b), nil
	}
	return nil, nil
}

// Feed consumes a Telnet stream chunk, preserving split commands and records.
// It returns only genuine protocol replies to send through the byte channel.
// A failed chunk leaves terminal and parser state unchanged.
func (t *Terminal) Feed(data []byte) ([]byte, error) {
	if len(data) > 1<<20 {
		return nil, fmt.Errorf("tn5250: chunk exceeds1MiB")
	}
	n := *t
	n.record = append([]byte(nil), t.record...)
	n.sub = append([]byte(nil), t.sub...)
	var output []byte
	for _, v := range data {
		switch n.state {
		case 0:
			if v == 255 {
				n.state = 1
			} else {
				n.record = append(n.record, v)
			}
		case 1:
			switch v {
			case 255:
				n.record = append(n.record, 255)
				n.state = 0
			case 239:
				if len(n.record) > 0 {
					save := len(n.record) >= 10 && n.record[9] == 4 && 6+int(n.record[6]) <= len(n.record) && bytes.Equal(n.record[6+int(n.record[6]):], []byte{4, 2})
					if err := n.apply(n.record, &output); err != nil {
						if !n.Lenient {
							return nil, err
						}
						n.Skipped++
						n.SkipError = err.Error()
						n.record = nil
						n.state = 0
						continue
					}
					if n.tap && len(n.tapped) < 4096 {
						n.tapped = append(n.tapped, n.forward)
					}
					if save {
						output = append(output, n.saveReply()...)
					}
					if n.record[9] == 0x0a {
						// RFC1205 section4.2 reverses the normal flow. Reply
						// with Cancel Invite, then wait for another read command.
						output = append(output, 0, 10, 0x12, 0xa0, 0, 0, 4, 0, 0, 0x0a, 255, 239)
					}
					n.record = nil
				}
				n.state = 0
			case 250:
				n.state = 2
				n.sub = nil
			case 251, 252, 253, 254:
				n.verb = v
				n.state = 3
			default:
				n.state = 0
			}
		case 2:
			n.option = v
			n.state = 4
		case 3:
			accepted := v == 0 || v == 25 || n.verb == 253 && (v == 24 || v == 39)
			switch n.verb {
			case 253:
				if accepted {
					if !n.local[v] {
						output = append(output, 255, 251, v)
					}
					n.local[v] = true
				} else {
					output = append(output, 255, 252, v)
				}
			case 254:
				n.local[v] = false
			case 251:
				if accepted {
					if !n.remote[v] {
						output = append(output, 255, 253, v)
					}
					n.remote[v] = true
				} else {
					output = append(output, 255, 254, v)
				}
			case 252:
				n.remote[v] = false
			}
			n.state = 0
		case 4:
			if v == 255 {
				n.state = 5
			} else {
				n.sub = append(n.sub, v)
			}
		case 5:
			if v == 255 {
				n.sub = append(n.sub, 255)
				n.state = 4
			} else if v == 240 {
				reply, err := n.subReply()
				if err != nil {
					return nil, err
				}
				output = append(output, reply...)
				n.state = 0
				n.sub = nil
			} else {
				return nil, fmt.Errorf("tn5250: invalid subnegotiation escape")
			}
		}
		if len(n.record) > 65535 || len(n.sub) > 65535 {
			return nil, fmt.Errorf("tn5250: record/subnegotiation exceeds64KiB")
		}
	}
	*t = n
	return output, nil
}

// queryReply describes this terminal's screen, field limit and negotiated
// model in the byte positions defined by RFC 1205 §5.3.
func (t *Terminal) queryReply() ([]byte, error) {
	parts := strings.Split(strings.ToUpper(t.TerminalType), "-")
	if len(parts) != 3 || parts[0] != "IBM" || len(parts[1]) != 4 || len(parts[2]) < 1 || len(parts[2]) > 3 {
		return nil, fmt.Errorf("tn5250: cannot report device model %q", t.TerminalType)
	}
	model := parts[1] + strings.Repeat("0", 3-len(parts[2])) + parts[2]
	record := make([]byte, 10+61)
	copy(record, []byte{0, 71, 0x12, 0xa0, 0, 0, 4, 0, 0, 0})
	body := record[10:]
	copy(body[2:], []byte{0x88, 0, 58, 0xd9, 0x70, 0x80, 0x06, 0, 1, 0, 0})
	body[29] = 1 // display emulator
	for i := range len(model) {
		if model[i] < '0' || model[i] > '9' {
			return nil, fmt.Errorf("tn5250: nonnumeric device model %q", t.TerminalType)
		}
		body[30+i] = 0xf0 + model[i] - '0'
	}
	body[37] = 2 // standard keyboard
	binary.BigEndian.PutUint16(body[44:], 256)
	body[49] = 2    // Move Cursor order
	body[50] = 0x10 // 24×80 display
	if parts[1] == "3179" || parts[1] == "5292" {
		body[50] |= 1 // 3179-style color attributes
	}
	return append(quote(record), 255, 239), nil
}

// saveReply serializes the authoritative display as real5250 WTD orders.
// The server can return those bytes in a Restore Screen GDS record.
func (t *Terminal) saveReply() []byte {
	record := []byte{0, 0, 0x12, 0xa0, 0, 0, 4, 0, 0, 4}
	record = append(record, t.screenOrders(true)...)
	binary.BigEndian.PutUint16(record, uint16(len(record)))
	return append(quote(record), 255, 239)
}

// ScreenRecord encodes the current display as one escaped GDS record ending
// with IAC EOR: Clear Unit and a Write to Display that redraws the text,
// attributes, fields and cursor. It is a Put/Get operation (with the pending
// read command) when the host awaits input, else Output Only. A viewer that
// joins a session late starts from it.
func (t *Terminal) ScreenRecord() []byte {
	opcode := byte(2)
	if t.readMode != 0 {
		opcode = 3
	}
	record := []byte{0, 0, 0x12, 0xa0, 0, 0, 4, 0, 0, opcode}
	record = append(record, t.screenOrders(false)...)
	binary.BigEndian.PutUint16(record, uint16(len(record)))
	return append(quote(record), 255, 239)
}

// TapRecords keeps (or stops keeping) a copy of each record Feed applies,
// for a relay forwarding the host's display to another terminal.
func (t *Terminal) TapRecords(on bool) {
	t.tap = on
	if !on {
		t.tapped = nil
	}
}

// TakeRecords returns and forgets the records kept since the last call
// (unescaped GDS records without IAC EOR), oldest first.
func (t *Terminal) TakeRecords() [][]byte {
	r := t.tapped
	t.tapped = nil
	return r
}

// screenOrders is the Clear Unit and Write to Display data stream for the
// current display, preceded by the Restore Screen marker this terminal's
// save replies carry.
func (t *Terminal) screenOrders(restoreMarker bool) []byte {
	body := []byte{4, 0x40, 4, 0x11, 0, 0}
	data := t.data
	if restoreMarker {
		body = append([]byte{4, 0x12}, body...)
	} else {
		// For another display station: nulls outside input fields as
		// blanks (see apply's forwarded copy).
		for pos, v := range data {
			if v == 0 && !slices.ContainsFunc(t.Fields, func(f Field) bool { return pos >= f.offset && pos < f.offset+f.Length }) {
				data[pos] = 0x40
			}
		}
	}
	if t.formatHeader != "" {
		body = append(body, 1, byte(len(t.formatHeader)))
		body = append(body, t.formatHeader...)
	}
	fields := map[int]Field{}
	for _, f := range t.Fields {
		fields[f.offset-1] = f
	}
	for i := 0; i < 1920; {
		if f, ok := fields[i]; ok {
			body = append(body, 0x1d, byte(f.Format>>8), byte(f.Format))
			body = append(body, f.controlWords...)
			body = append(body, f.Attribute, byte(f.Length>>8), byte(f.Length))
			i++
			continue
		}
		if t.markers[i] {
			body = append(body, t.attributes[i])
			i++
			continue
		}
		// repeat is the length of the run of identical bytes at j.
		repeat := func(j int) int {
			end := j + 1
			for end < 1920 && !t.markers[end] && data[end] == data[j] {
				if _, ok := fields[end]; ok {
					break
				}
				end++
			}
			return end - j
		}
		if n := repeat(i); n >= 4 && (data[i] < 0x20 || data[i] > 0x3f) {
			at := i + n - 1
			body = append(body, 2, byte(at/80+1), byte(at%80+1), data[i])
			i += n
			continue
		}
		// Text up to the next attribute, field or repeated run. Plain
		// characters (0x40 and above) are written as data, as hosts do;
		// a run holding control-range bytes (nulls, for example) needs a
		// Transparent Data order so they are not read as orders.
		end := i + 1
		for end < 1920 && !t.markers[end] {
			if _, ok := fields[end]; ok {
				break
			}
			if repeat(end) >= 4 && (data[end] < 0x20 || data[end] > 0x3f) {
				break
			}
			end++
		}
		plain := true
		for _, v := range data[i:end] {
			if v < 0x40 || v == 0xff {
				plain = false
				break
			}
		}
		if !plain {
			body = append(body, 0x10, byte((end-i)>>8), byte(end-i))
		}
		body = append(body, data[i:end]...)
		i = end
	}
	row, col := t.Cursor()
	body = append(body, 0x13, byte(row), byte(col))
	if t.readMode != 0 {
		body = append(body, 4, t.readMode, 0, 0)
	}
	return body
}

// Key encodes cursor and AID as an RFC1205 Put/Get input record. No guest
// state is modified until the caller sends these actual terminal bytes.
func (t *Terminal) Key(aid byte) []byte {
	if t.inputCancelled {
		return nil
	}
	row, col := t.Cursor()
	b := []byte{0, 0, 0x12, 0xa0, 0, 0, 4, 0, 0, 3, byte(row), byte(col), aid}
	if t.readMode == 0x42 {
		b = t.appendReadInputFields(b, aid)
	} else {
		for _, f := range t.Fields {
			if f.Modified {
				b = append(b, 0x11, byte(f.Row), byte(f.Column))
				data := bytes.TrimRight(t.data[f.offset:f.offset+f.Length], "\x00")
				b = append(b, data...)
			}
		}
	}
	binary.BigEndian.PutUint16(b, uint16(len(b)))
	return append(quote(b), 255, 239)
}

// Read Input Fields returns fixed-width field contents in display order.
// SA21-9247, pp. 2-5 to 2-7. This reply has no set-buffer-address orders.
func (t *Terminal) appendReadInputFields(dst []byte, aid byte) []byte {
	switch {
	case aid == 0xf1 || aid == 0x3f || aid == 0xf4 || aid == 0xf5:
	case aid >= 0x31 && aid <= 0x3c || aid >= 0xb1 && aid <= 0xbc:
		key := int(aid - 0x31)
		if aid >= 0xb1 {
			key = 12 + int(aid-0xb1)
		}
		if len(t.formatHeader) >= 7 && t.formatHeader[6-key/8]&(1<<(key%8)) != 0 {
			return dst
		}
	default:
		return dst
	}
	if !slices.ContainsFunc(t.Fields, func(f Field) bool { return f.Modified || f.Format&0x0800 != 0 }) {
		return dst
	}
	fields := slices.Clone(t.Fields)
	slices.SortFunc(fields, func(a, b Field) int { return a.offset - b.offset })
	for _, f := range fields {
		end := f.offset + f.Length
		signed := f.Format&0x0700 == 0x0700
		if signed {
			end-- // The sign position itself is never transmitted.
		}
		for pos := f.offset; pos < end; pos++ {
			value := t.data[pos]
			if t.markers[pos] {
				value = t.attributes[pos]
			} else if value == 0 {
				value = 0x40
			}
			if signed && pos == end-1 && t.data[end] == 0x60 {
				value = 0xd0 | value&0x0f
			}
			dst = append(dst, value)
		}
	}
	return dst
}

// SetField replaces an input field with IBM037 text and marks it modified.
// Nondisplay fields remain hidden in Rows.
func (t *Terminal) SetField(index int, text string) error {
	if index < 0 || index >= len(t.Fields) {
		return fmt.Errorf("tn5250: invalid field index")
	}
	data, err := charmap.CodePage037.NewEncoder().Bytes([]byte(text))
	if err != nil {
		return err
	}
	f := &t.Fields[index]
	if len(data) > f.Length {
		return fmt.Errorf("tn5250: field value too long")
	}
	clear(t.data[f.offset : f.offset+f.Length])
	copy(t.data[f.offset:], data)
	f.Modified = true
	t.cursor = min(f.offset+len(data), f.offset+f.Length-1)
	return nil
}
