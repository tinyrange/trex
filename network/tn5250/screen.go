package tn5250

import (
	"encoding/binary"
	"fmt"
	"strings"

	"golang.org/x/text/encoding/charmap"
)

// Screen is a copy of the display for a viewer: the 24x80 character grid,
// each cell's display attribute and the input fields, independent of later
// records.
type Screen struct {
	// Rows are the 24 rows of 80 characters, as Rows shows them (attribute
	// positions and nondisplay cells are blanks) but untrimmed.
	Rows []string
	// Attributes holds each cell's 5250 display attribute (0x20..0x3f):
	// bit 0 reverse image, bit 1 high intensity, bit 2 underscore, 7 in
	// the low bits nondisplay; bits 3-4 select the colour group.
	// Positions that hold an attribute byte are marked by AttributeCell.
	Attributes    []byte
	AttributeCell []bool
	Fields        []ScreenField
	// CursorRow and CursorColumn are 1-based.
	CursorRow, CursorColumn int
	// Records counts the display records applied; a viewer's input is
	// meant for the screen with the same count.
	Records int
	// Inhibited reports that the host cancelled input (keyboard locked).
	Inhibited bool
}

// ScreenField is one input field of a Screen.
type ScreenField struct {
	Index               int // the SetField index
	Row, Column, Length int // 1-based start of the field's data
	Attribute           byte
	// Text is the field's current content (trailing nulls removed); for
	// nondisplay fields it is empty.
	Text     string
	Hidden   bool // nondisplay (passwords)
	Bypass   bool // the field format forbids keyboard entry
	Monocase bool // the display station translates typed lowercase to uppercase
}

// Screen returns a copy of the display.
func (t *Terminal) Screen() Screen {
	s := Screen{Attributes: make([]byte, len(t.data)), AttributeCell: make([]bool, len(t.data)), Records: t.Records, Inhibited: t.inputCancelled}
	// A field's attribute byte describes the field; the positions after it
	// up to the next attribute byte display normally rather than inheriting
	// the field's highlight (an error's reverse image, a password's
	// nondisplay).
	fieldEnd := map[int]int{} // attribute position -> first position after the field
	for _, f := range t.Fields {
		if f.offset > 0 {
			fieldEnd[f.offset-1] = f.offset + f.Length
		}
	}
	attr, end := byte(0x20), -1
	for i := range t.data {
		if t.markers[i] {
			attr = t.attributes[i]
			s.AttributeCell[i] = true
			end = -1
			if e, ok := fieldEnd[i]; ok {
				end = e
			}
		}
		if end >= 0 && i >= end {
			attr, end = 0x20, -1
		}
		s.Attributes[i] = attr
	}
	for y := 0; y < 24; y++ {
		var b strings.Builder
		for x := 0; x < 80; x++ {
			i := y*80 + x
			v := t.data[i]
			switch {
			case s.AttributeCell[i] || v == 0 || s.Attributes[i]&7 == 7:
				b.WriteByte(' ')
			case v == 0x1f:
				b.WriteRune('█')
			default:
				r := charmap.CodePage037.DecodeByte(v)
				if r < 32 {
					r = ' '
				}
				b.WriteRune(r)
			}
		}
		s.Rows = append(s.Rows, b.String())
	}
	for i, f := range t.Fields {
		sf := ScreenField{Index: i, Row: f.Row, Column: f.Column, Length: f.Length, Attribute: f.Attribute,
			Hidden: f.Attribute&7 == 7, Bypass: f.Format&0x2000 != 0, Monocase: f.Format&0x0020 != 0}
		if !sf.Hidden && f.offset >= 0 && f.offset+f.Length <= len(t.data) {
			var b strings.Builder
			for _, v := range t.data[f.offset : f.offset+f.Length] {
				r := ' '
				if v != 0 {
					r = charmap.CodePage037.DecodeByte(v)
					if r < 32 {
						r = ' '
					}
				}
				b.WriteRune(r)
			}
			sf.Text = strings.TrimRight(b.String(), " ")
		}
		s.Fields = append(s.Fields, sf)
	}
	s.CursorRow, s.CursorColumn = t.Cursor()
	return s
}

// SetCursor places the cursor at a 1-based row and column, as a terminal
// operator moving it before pressing an AID key.
func (t *Terminal) SetCursor(row, col int) error {
	if row < 1 || row > 24 || col < 1 || col > 80 {
		return fmt.Errorf("tn5250: invalid cursor %d/%d", row, col)
	}
	t.cursor = (row-1)*80 + col - 1
	return nil
}

// SystemRequest encodes the System Request key: an RFC1205 record with the
// SRQ header flag and no data.
func (t *Terminal) SystemRequest() []byte { return headerOnly(0x04) }

// Attention encodes the Attention key: an RFC1205 record with the ATN
// header flag and no data.
func (t *Terminal) Attention() []byte { return headerOnly(0x40) }

func headerOnly(flags byte) []byte {
	b := []byte{0, 0, 0x12, 0xa0, 0, 0, 4, flags, 0, 0}
	binary.BigEndian.PutUint16(b, uint16(len(b)))
	return append(quote(b), 255, 239)
}
