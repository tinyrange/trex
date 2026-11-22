package tn5250

import (
	"bytes"
	"encoding/binary"
	"slices"
	"strings"
	"testing"
)

func TestScreenCopiesFieldsAttributesAndCursor(t *testing.T) {
	x := New()
	body := []byte{4, 0x40, 4, 0x11, 0, 0, 0x11, 8, 46, 0x1d, 0x40, 0, 0x26, 0, 10}
	body = append(body, bytes.Repeat([]byte{0x40}, 10)...)
	body = append(body, 0x11, 9, 46, 0x1d, 0x40, 0, 0x27, 0, 33)
	body = append(body, bytes.Repeat([]byte{0x40}, 33)...)
	if err := x.Apply(gds(body)); err != nil {
		t.Fatal(err)
	}
	if err := x.SetField(0, "QSECOFR"); err != nil {
		t.Fatal(err)
	}
	if err := x.SetField(1, "SECRET"); err != nil {
		t.Fatal(err)
	}
	s := x.Screen()
	if len(s.Rows) != 24 || len(s.Rows[7]) != 80 || !strings.Contains(s.Rows[7], "QSECOFR") || strings.Contains(s.Rows[8], "SECRET") {
		t.Fatalf("rows %q", s.Rows[7:9])
	}
	if len(s.Fields) != 2 || s.Fields[0].Text != "QSECOFR" || s.Fields[0].Hidden || s.Fields[0].Row != 8 || s.Fields[0].Column != 47 ||
		!s.Fields[1].Hidden || s.Fields[1].Text != "" || s.Fields[1].Length != 33 {
		t.Fatalf("fields %+v", s.Fields)
	}
	at := 7*80 + 45 // the field attribute byte before row 8 column 47
	if !s.AttributeCell[at] || s.Attributes[at+1] != 0x26 || s.Attributes[8*80+46]&7 != 7 || s.Records != 1 {
		t.Fatalf("attributes %x cell %v records %d", s.Attributes[at:at+2], s.AttributeCell[at], s.Records)
	}
	if err := x.SetCursor(8, 50); err != nil {
		t.Fatal(err)
	}
	if s := x.Screen(); s.CursorRow != 8 || s.CursorColumn != 50 {
		t.Fatalf("cursor %d/%d", s.CursorRow, s.CursorColumn)
	}
	if key := x.Key(0xf1); !bytes.Equal(key[10:13], []byte{8, 50, 0xf1}) {
		t.Fatalf("key record %x", key)
	}
	if x.SetCursor(25, 1) == nil || x.SetCursor(1, 0) == nil {
		t.Fatal("cursor outside the display accepted")
	}
	if !bytes.Equal(x.SystemRequest(), []byte{0, 0x0a, 0x12, 0xa0, 0, 0, 4, 4, 0, 0, 255, 239}) ||
		!bytes.Equal(x.Attention(), []byte{0, 0x0a, 0x12, 0xa0, 0, 0, 4, 0x40, 0, 0, 255, 239}) {
		t.Fatalf("system request %x attention %x", x.SystemRequest(), x.Attention())
	}
}

func TestScreenEndsFieldAttributesAtTheField(t *testing.T) {
	x := New()
	// A reverse-image monocase field at row 6 column 53 (FFW 0x4020), then
	// a label further on, with no ending attribute byte after the field.
	body := []byte{4, 0x40, 4, 0x11, 0, 0, 0x11, 6, 52, 0x1d, 0x40, 0x20, 0x25, 0, 10}
	body = append(body, bytes.Repeat([]byte{0x40}, 10)...)
	body = append(body, 0x11, 7, 15, 0x20, 0xd7) // attribute 0x20 then "P" at row 7 column 16
	if err := x.Apply(gds(body)); err != nil {
		t.Fatal(err)
	}
	s := x.Screen()
	field := 5*80 + 52
	if s.Attributes[field] != 0x25 || s.Attributes[field+9] != 0x25 || s.Attributes[field+10] != 0x20 || s.Attributes[6*80+5] != 0x20 {
		t.Fatalf("attributes field %x end %x after %x next row %x", s.Attributes[field], s.Attributes[field+9], s.Attributes[field+10], s.Attributes[6*80+5])
	}
	if len(s.Fields) != 1 || !s.Fields[0].Monocase || s.Fields[0].Bypass {
		t.Fatalf("field %+v", s.Fields)
	}
}

func TestFieldsWithoutInsertCursorHomeTheCursor(t *testing.T) {
	x := New()
	// A bypass field then an input field at row 6 column 53, and no IC order.
	body := []byte{4, 0x40, 4, 0x11, 0, 0, 0x11, 4, 52, 0x1d, 0x60, 0, 0x20, 0, 5}
	body = append(body, bytes.Repeat([]byte{0x40}, 5)...)
	body = append(body, 0x11, 6, 52, 0x1d, 0x40, 0x20, 0x24, 0, 10)
	body = append(body, bytes.Repeat([]byte{0x40}, 10)...)
	if err := x.Apply(gds(body)); err != nil {
		t.Fatal(err)
	}
	if row, col := x.Cursor(); row != 6 || col != 53 {
		t.Fatalf("cursor %d/%d, want the first input field 6/53", row, col)
	}
	// A later write without fields keeps the operator's cursor.
	if err := x.SetCursor(6, 56); err != nil {
		t.Fatal(err)
	}
	if err := x.Apply(gds([]byte{4, 0x11, 0, 0, 0x11, 24, 1, 0xc1})); err != nil {
		t.Fatal(err)
	}
	if row, col := x.Cursor(); row != 6 || col != 56 {
		t.Fatalf("status write moved the cursor to %d/%d", row, col)
	}
	// An explicit Insert Cursor wins.
	body = append([]byte{4, 0x40}, body[2:]...)
	body = append(body, 0x13, 2, 3)
	if err := x.Apply(gds(body)); err != nil {
		t.Fatal(err)
	}
	if row, col := x.Cursor(); row != 2 || col != 3 {
		t.Fatalf("insert cursor ignored: %d/%d", row, col)
	}
}

func TestOverlappingFieldReplacesEarlierFields(t *testing.T) {
	x := New()
	// A 20-character field at row 5 column 11, then (without clearing the
	// format table) a window writes a 5-character field inside it and
	// another field elsewhere.
	first := []byte{4, 0x40, 4, 0x11, 0, 0, 0x11, 5, 10, 0x1d, 0x40, 0, 0x24, 0, 20}
	first = append(first, bytes.Repeat([]byte{0x40}, 20)...)
	first = append(first, 0x11, 9, 10, 0x1d, 0x40, 0, 0x24, 0, 3, 0x40, 0x40, 0x40)
	if err := x.Apply(gds(first)); err != nil {
		t.Fatal(err)
	}
	window := []byte{4, 0x11, 0, 0, 0x11, 5, 15, 0x1d, 0x40, 0, 0x24, 0, 5, 0x40, 0x40, 0x40, 0x40, 0x40}
	if err := x.Apply(gds(window)); err != nil {
		t.Fatalf("overlapping field rejected: %v", err)
	}
	if len(x.Fields) != 2 || x.Fields[0].Row != 9 || x.Fields[1].Row != 5 || x.Fields[1].Column != 16 || x.Fields[1].Length != 5 {
		t.Fatalf("fields %+v", x.Fields)
	}
}

func TestLenientFeedSkipsUnsupportedRecords(t *testing.T) {
	x := New()
	bad := append(gds([]byte{4, 0x11, 0, 0, 0x05}), 255, 239) // unsupported WTD order 05
	good := append(gds([]byte{4, 0x11, 0, 0, 0x11, 1, 1, 0xc1}), 255, 239)
	if _, err := x.Feed(bad); err == nil {
		t.Fatal("strict terminal accepted an unsupported order")
	}
	x.Lenient = true
	if _, err := x.Feed(append(bad, good...)); err != nil {
		t.Fatal(err)
	}
	if x.Skipped != 1 || !strings.Contains(x.SkipError, "unsupported WTD order") || !strings.HasPrefix(x.Rows()[0], "A") || x.Records != 1 {
		t.Fatalf("skipped %d %q rows %q records %d", x.Skipped, x.SkipError, x.Rows()[0], x.Records)
	}
}

func TestFieldsGetEndingAttributesInTheModelAndForwardedRecords(t *testing.T) {
	x := New()
	x.TapRecords(true)
	// The IBM i Sign On shape: an underlined field followed directly by
	// the next row's address, with no ending attribute in the stream.
	body := []byte{4, 0x40, 4, 0x11, 0, 0, 0x11, 6, 52, 0x1d, 0x40, 0x20, 0x24, 0, 10}
	body = append(body, bytes.Repeat([]byte{0}, 10)...)
	body = append(body, 0x11, 8, 16, 0x20, 0xd7)
	wire := append(gds(body), 255, 239)
	if _, err := x.Feed(wire); err != nil {
		t.Fatal(err)
	}
	end := 5*80 + 62 // row 6, column 63: the position after the field
	if !x.markers[end] || x.attributes[end] != 0x20 || x.attributes[end+1] != 0x20 || x.attributes[end-1] != 0x24 {
		t.Fatalf("ending attribute: marker %v attrs %x %x %x", x.markers[end], x.attributes[end-1], x.attributes[end], x.attributes[end+1])
	}
	records := x.TakeRecords()
	if len(records) != 1 {
		t.Fatalf("tapped %d records", len(records))
	}
	fwd := records[0]
	inject := []byte{0x11, 6, 63, 0x20, 0x11, 6, 53}
	if !bytes.Contains(fwd, append([]byte{0x24, 0, 10}, inject...)) || int(binary.BigEndian.Uint16(fwd)) != len(fwd) || len(fwd) != len(gds(body))+len(inject) {
		t.Fatalf("forwarded record %x", fwd)
	}
	// Another display station applying the forwarded record ends the
	// field in the same place.
	y := New()
	if err := y.Apply(fwd); err != nil {
		t.Fatal(err)
	}
	if y.Screen().Rows[5] != x.Screen().Rows[5] || !slices.Equal(y.attributes[:], x.attributes[:]) || len(y.Fields) != 1 {
		t.Fatalf("forwarded record renders differently")
	}
}

func TestForwardedRecordsBlankNullsOutsideFields(t *testing.T) {
	x := New()
	x.TapRecords(true)
	// "MAIN", nulls repeated to column 11, then a field whose data is nulls.
	body := []byte{4, 0x40, 4, 0x11, 0, 0, 0x11, 1, 1, 0xd4, 0xc1, 0xc9, 0xd5, 2, 1, 11, 0, 0x11, 20, 6, 0x1d, 0x40, 0, 0x24, 0, 3, 0, 0, 0, 0x10, 0, 1, 0}
	if _, err := x.Feed(append(gds(body), 255, 239)); err != nil {
		t.Fatal(err)
	}
	fwd := x.TakeRecords()[0]
	if !bytes.Contains(fwd, []byte{2, 1, 11, 0x40}) {
		t.Fatalf("repeated nulls outside a field not blanked: %x", fwd)
	}
	if !bytes.Contains(fwd, []byte{0x11, 20, 7, 0, 0, 0}) {
		t.Fatalf("field nulls changed: %x", fwd)
	}
	if !bytes.HasSuffix(fwd, []byte{0x10, 0, 1, 0x40}) {
		t.Fatalf("transparent null after the field not blanked: %x", fwd)
	}
	if x.data[0*80+5] != 0 {
		t.Fatal("the terminal's own display lost its nulls")
	}
}
