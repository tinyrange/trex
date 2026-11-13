package s390

import (
	"bytes"
	"strings"
	"testing"
)

// loginScreen writes a protected label, an 8-character input field, and a
// nondisplay 8-character password field on row 1.
func loginScreen(t *testing.T) *Console3270 {
	t.Helper()
	c := NewConsole3270(24, 80)
	data := []byte{0xc3, 0x1d, 0xe8}
	data = append(data, EncodeEBCDIC("USERID")...)
	data = append(data, 0x1d, 0x40, 0x13) // unprotected field 8..15, cursor at 8
	data = append(data, 0x11)
	data = append(data, c.encodeAddr(16)...)
	data = append(data, 0x1d, 0x60, 0x11)
	data = append(data, c.encodeAddr(80)...)
	data = append(data, 0x1d, 0x4c) // unprotected nondisplay 81..88
	data = append(data, 0x11)
	data = append(data, c.encodeAddr(89)...)
	data = append(data, 0x1d, 0x60)
	if _, _, st := c.Exec(0x05, data, false); st != usCE|usDE {
		t.Fatal(st)
	}
	return c
}

func TestScreen3270ClassesAndHiddenFields(t *testing.T) {
	c := loginScreen(t)
	if err := c.Type("IBMUSER"); err != nil {
		t.Fatal(err)
	}
	c.SetCursor(1, 1)
	if err := c.Type("SECRET"); err != nil {
		t.Fatal(err)
	}
	s := c.Screen()
	if len(s.Text) != 24*80 || len(s.Attr) != 24*80 {
		t.Fatalf("sizes %d %d", len(s.Text), len(s.Attr))
	}
	if got := s.Text[1:7] + "|" + s.Text[8:15]; got != "USERID|IBMUSER" {
		t.Fatalf("text %q", got)
	}
	if got := s.Attr[0:9] + s.Attr[16:18] + s.Attr[80:82]; got != "aPPPPPPau"+"ap"+"an" {
		t.Fatalf("attr %q", s.Attr[0:20])
	}
	if strings.Contains(s.Text, "SECRET") || strings.TrimSpace(s.Text[81:89]) != "" {
		t.Fatalf("nondisplay field leaked: %q", s.Text[80:90])
	}
	if s.Cursor != 87 || s.Locked {
		t.Fatalf("cursor %d locked %v", s.Cursor, s.Locked)
	}
	c.Key("ENTER")
	if !c.Screen().Locked {
		t.Fatal("ENTER did not inhibit the keyboard")
	}
	c.Key("RESET")
	if c.Locked() {
		t.Fatal("RESET did not restore the keyboard")
	}
}

func field(c *Console3270, from, to int) string { return EBCDICString(c.buf[from:to]) }

func TestConsole3270EditingKeys(t *testing.T) {
	c := loginScreen(t)
	v := c.Version()
	c.Type("ABCD")
	if c.Version() == v {
		t.Fatal("typing did not change the version")
	}
	c.SetCursor(0, 9)
	c.Key("INSERT")
	c.Type("X") // A X B C D
	if got := field(c, 8, 13); got != "AXBCD" {
		t.Fatalf("insert %q", got)
	}
	c.Key("BACKSPACE") // removes X
	if got := field(c, 8, 12); got != "ABCD" || c.cursor != 9 {
		t.Fatalf("backspace %q cursor %d", got, c.cursor)
	}
	c.Key("DELETE") // removes B
	if got := field(c, 8, 11); got != "ACD" || c.buf[15] != 0 {
		t.Fatalf("delete %q", got)
	}
	c.Type("12345") // A 1 2 3 4 5 C D fills the 8-position field
	if err := c.Type("Z"); err == nil || !strings.Contains(err.Error(), "full") {
		t.Fatalf("insert into a full field: %v", err)
	}
	c.Key("RESET")
	c.SetCursor(0, 10)
	c.Key("ERASEEOF")
	if got := field(c, 8, 10); got != "A1" || c.buf[10] != 0 || c.buf[15] != 0 || c.buf[16] == 0 {
		t.Fatalf("erase EOF %X", c.buf[8:17])
	}
	c.Key("TAB")
	if c.cursor != 81 {
		t.Fatalf("tab to %d", c.cursor)
	}
	c.Key("BACKTAB")
	if c.cursor != 8 {
		t.Fatalf("backtab to %d", c.cursor)
	}
	c.SetCursor(0, 5)
	if err := c.Type("Q"); err == nil {
		t.Fatal("typed into a protected field")
	}
	c.Key("HOME")
	if c.cursor != 8 {
		t.Fatalf("home to %d", c.cursor)
	}
	c.Key("NEWLINE")
	if c.cursor != 81 {
		t.Fatalf("newline to %d", c.cursor)
	}
	c.Key("UP")
	c.Key("LEFT")
	if c.cursor != 0 {
		t.Fatalf("arrows to %d", c.cursor)
	}
}

// ERASE EOF on an unformatted screen clears to the end of the buffer.
func TestConsole3270EraseEOFUnformatted(t *testing.T) {
	c := NewConsole3270(24, 80)
	c.Type("HELLO")
	c.SetCursor(0, 2)
	c.Key("ERASEEOF")
	if got := strings.TrimRight(c.Screen().Text, " "); got != "HE" {
		t.Fatalf("%q", got)
	}
}

// SFE and MF set a field's color and highlighting, SA a character's; the
// snapshot resolves character over field, and the query reply advertises
// color and highlighting.
func TestConsole3270ExtendedAttributes(t *testing.T) {
	c := NewConsole3270(24, 80)
	data := []byte{0xc3, 0x29, 0x03, 0xc0, 0x60, 0x42, 0xf2, 0x41, 0xf4} // SFE protected red underscore
	data = append(data, EncodeEBCDIC("AB")...)
	data = append(data, 0x28, 0x42, 0xf6) // SA yellow
	data = append(data, EncodeEBCDIC("C")...)
	data = append(data, 0x28, 0x00, 0x00) // SA reset
	data = append(data, EncodeEBCDIC("D")...)
	data = append(data, 0x1d, 0x40) // plain unprotected field at 5
	data = append(data, EncodeEBCDIC("E")...)
	data = append(data, 0x11, 0x40, 0x45, 0x2c, 0x01, 0x42, 0xf5) // MF at 5: turquoise
	c.Exec(0x05, data, false)
	s := c.Screen()
	if s.Text[1:5] != "ABCD" || s.Color[1:7] != "226205" || s.Hilite[1:7] != "444400" {
		t.Fatalf("text %q color %q hilite %q", s.Text[:7], s.Color[:7], s.Hilite[:7])
	}
	if c.buf[5] != 0x40 || !c.fa[5] {
		t.Fatalf("MF changed the basic attribute: %X", c.buf[5])
	}
	c.Exec(0x11, []byte{0, 5, 1, 0xff, 2}, false)
	reply, _, _ := c.Exec(0x02, nil, false)
	if !bytes.Contains(reply, []byte{0x81, 0x86, 0x00, 0x08, 0x00, 0xf4}) || !bytes.Contains(reply, []byte{0x81, 0x87, 0x04}) {
		t.Fatalf("query reply lacks color/highlighting: %X", reply)
	}
}

// DataStream reproduces the screen: replaying it into a second terminal
// yields the same snapshot, modified flags included.
func TestConsole3270DataStreamRoundTrip(t *testing.T) {
	c := loginScreen(t)
	c.Exec(0x01, []byte{0xc2, 0x11, 0x40, 0x5a, 0x28, 0x42, 0xf6, 0xc1, 0xc2}, false) // yellow "AB" at 26
	c.Type("IBMUSER")
	c.SetCursor(1, 3)
	for _, extended := range []bool{true, false} {
		d := NewConsole3270(24, 80)
		rec := c.DataStream(extended)
		if rec[0] != 0xf5 {
			t.Fatalf("command %X", rec[0])
		}
		d.Exec(0x05, rec[1:], false)
		got, want := d.Screen(), c.Screen()
		if !extended {
			want.Color = strings.Repeat("0", len(want.Color))
		}
		if got.Text != want.Text || got.Attr != want.Attr || got.Color != want.Color || got.Cursor != want.Cursor {
			t.Fatalf("extended %v: replay differs\n%q\n%q", extended, got.Text[:30], want.Text[:30])
		}
		if !bytes.Equal(d.readModified(true)[3:], c.readModified(true)[3:]) {
			t.Fatalf("modified fields differ")
		}
	}
}

// Inbound applies a remote read-modified record: field text replaces the
// field, the MDT is set, and the AID is presented with the keyboard locked.
func TestConsole3270Inbound(t *testing.T) {
	c := loginScreen(t)
	c.Type("OLDNAME!")
	in := append([]byte{AIDEnter, 0x40, 0xd1, 0x11, 0x40, 0xc8}, EncodeEBCDIC("NEW")...)
	in = append(in, 0x11, 0xc1, 0xd1) // password field at 81
	in = append(in, EncodeEBCDIC("PW")...)
	c.Inbound(in)
	if !c.Locked() || c.aid != AIDEnter || c.cursor != 17 {
		t.Fatalf("locked %v aid %X cursor %d", c.Locked(), c.aid, c.cursor)
	}
	rm := c.readModified(false)
	want := append([]byte{AIDEnter, 0x40, 0xd1, 0x11, 0x40, 0xc8}, EncodeEBCDIC("NEW")...)
	want = append(append(want, 0x11, 0xc1, 0xd1), EncodeEBCDIC("PW")...)
	if !bytes.Equal(rm, want) {
		t.Fatalf("read modified %X\nwant %X", rm, want)
	}
	c.Inbound([]byte{AIDClear})
	if strings.TrimSpace(c.Screen().Text) != "" || c.aid != AIDClear {
		t.Fatal("CLEAR did not clear")
	}
}
