package tn5250

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func gds(body []byte) []byte {
	b := []byte{0, 0, 0x12, 0xa0, 0, 0, 4, 0, 0, 3}
	b = append(b, body...)
	binary.BigEndian.PutUint16(b, uint16(len(b)))
	return b
}
func TestDeviceQuery(t *testing.T) {
	wire := append(gds([]byte{4, 0xf3, 0, 5, 0xd9, 0x70, 0}), 255, 239)
	want := make([]byte, 73)
	copy(want, []byte{0, 0x47, 0x12, 0xa0, 0, 0, 4, 0, 0, 0, 0, 0, 0x88, 0, 0x3a, 0xd9, 0x70, 0x80, 6, 0, 1})
	copy(want[39:], []byte{1, 0xf3, 0xf1, 0xf7, 0xf9, 0xf0, 0xf0, 0xf2, 2})
	want[54], want[59], want[60] = 1, 2, 0x11
	want[71], want[72] = 255, 239
	for split := range len(wire) + 1 {
		term := New()
		a, err := term.Feed(wire[:split])
		if err != nil {
			t.Fatal(err)
		}
		b, err := term.Feed(wire[split:])
		if err != nil || !bytes.Equal(append(a, b...), want) || term.Records != 1 {
			t.Fatalf("split %d: reply %x %x, error %v", split, a, b, err)
		}
	}
	term := New()
	wire[16] = 1 // reserved query flag
	if reply, err := term.Feed(wire); err == nil || len(reply) != 0 || term.Records != 0 {
		t.Fatalf("invalid query: reply %x, error %v", reply, err)
	}
}

func TestDisplayChunkingAndAtomicValidation(t *testing.T) {
	// CU, WTD, IC and SBA, text, RA, nondisplay attribute, and Read MDT.
	record := gds([]byte{4, 0x40, 4, 0x11, 0, 0, 0x13, 2, 4, 0x11, 1, 1, 0xc1, 0xc2, 0x02, 1, 5, 0x40, 0xc3, 0x27, 0xe7, 0x20, 4, 0x52, 0, 0})
	wire := append(quote(record), 255, 239)
	for split := range len(wire) + 1 {
		x := New()
		if _, err := x.Feed(wire[:split]); err != nil {
			t.Fatal(err)
		}
		if _, err := x.Feed(wire[split:]); err != nil {
			t.Fatalf("split%d: %v", split, err)
		}
		if x.Rows()[0] != "AB   C" || x.Records != 1 {
			t.Fatalf("split%d row=%q records=%d", split, x.Rows()[0], x.Records)
		}
		r, c := x.Cursor()
		if r != 2 || c != 4 {
			t.Fatal("cursor lost")
		}
		before := x.Rows()
		bad := gds([]byte{4, 0x40, 4, 0x11, 0, 0, 0x11, 25, 1})
		if x.Apply(bad) == nil || strings.Join(before, "\n") != strings.Join(x.Rows(), "\n") {
			t.Fatal("malformed record mutated screen")
		}
		key := x.Key(0x3c)
		if !bytes.Equal(key, []byte{0, 13, 0x12, 0xa0, 0, 0, 4, 0, 0, 3, 2, 4, 0x3c, 255, 239}) {
			t.Fatalf("key=%x", key)
		}
	}
}
func TestNegotiationSplitSubcommands(t *testing.T) {
	x := New()
	x.Environment = map[string]string{"USER": "TEST", "IBMRSEED": ""}
	wire := []byte{255, 253, 24, 255, 250, 24, 1, 255, 240, 255, 253, 25, 255, 251, 25, 255, 253, 0, 255, 251, 0, 255, 250, 39, 1, 3, 'I', 'B', 'M', 'R', 'S', 'E', 'E', 'D', 1, 255, 255, 255, 240}
	var output []byte
	for _, v := range wire {
		b, err := x.Feed([]byte{v})
		if err != nil {
			t.Fatal(err)
		}
		output = append(output, b...)
	}
	if !bytes.Contains(output, []byte("IBM-3179-2")) || !bytes.Contains(output, []byte{255, 251, 25}) || !bytes.Contains(output, []byte{255, 253, 0}) || !bytes.Contains(output, []byte("TEST")) {
		t.Fatalf("negotiation=%x", output)
	}
	if b, err := x.Feed([]byte{255, 253, 24}); err != nil || len(b) != 0 {
		t.Fatal("duplicate option renegotiated")
	}
}

func TestCancelInviteReplyAndInputFlow(t *testing.T) {
	// RFC1205 section4.2.
	wire := []byte{0, 10, 0x12, 0xa0, 0, 0, 4, 0, 0, 0x0a, 255, 239}
	for split := 0; split <= len(wire); split++ {
		x := New()
		if err := x.Apply(gds([]byte{4, 0x11, 0, 0, 0xc1, 0xc2, 0x13, 2, 4, 4, 0x52, 0, 0})); err != nil {
			t.Fatal(err)
		}
		before, row, col := x.Rows(), 2, 4
		a, err := x.Feed(wire[:split])
		if err != nil {
			t.Fatal(err)
		}
		b, err := x.Feed(wire[split:])
		if err != nil || !bytes.Equal(append(a, b...), wire) {
			t.Fatalf("split%d reply=%x/%x err=%v", split, a, b, err)
		}
		r, c := x.Cursor()
		if r != row || c != col || strings.Join(before, "\n") != strings.Join(x.Rows(), "\n") || x.Records != 2 || len(x.Key(0xf1)) != 0 {
			t.Fatal("Cancel Invite changed display or allowed keyboard input")
		}
		// Display-only traffic does not reinvite the workstation.
		if err := x.Apply(gds([]byte{4, 0x11, 0, 0, 0xc3})); err != nil || len(x.Key(0xf1)) != 0 {
			t.Fatal("display output reenabled input")
		}
		if err := x.Apply(gds([]byte{4, 0x52, 0, 0})); err != nil || len(x.Key(0xf1)) == 0 {
			t.Fatal("read command did not reinvite input")
		}
		bad := gds([]byte{0})
		bad[9] = 0x0a
		if _, err := x.Feed(append(bad, 255, 239)); err == nil || len(x.Key(0xf1)) == 0 {
			t.Fatal("malformed Cancel Invite mutated input state")
		}
	}
}

func TestSingleByteInputFieldControlWords(t *testing.T) {
	prefix := []byte{4, 0x11, 0, 0, 0x11, 20, 17, 0x1d, 0x40, 0}
	for _, words := range [][]byte{nil, {0x81, 0}, {0x81, 0, 0x81, 0}, {0x82, 0x80}, {0x81, 0, 0x82, 0x80}} {
		x := New()
		record := append(bytes.Clone(prefix), words...)
		record = append(record, 0x24, 0, 142, 4, 0x52, 0, 0)
		if err := x.Apply(gds(record)); err != nil {
			t.Fatal(err)
		}
		if len(x.Fields) != 1 || x.Fields[0].Row != 20 || x.Fields[0].Column != 18 || x.Fields[0].Length != 142 {
			t.Fatalf("wrong operator reply field: %+v", x.Fields)
		}
		if err := x.SetField(0, "G"); err != nil || !bytes.Contains(x.Key(0xf1), []byte{0x11, 20, 18, 0xc7}) {
			t.Fatalf("reply missing: %v", err)
		}
		saved := x.saveReply()
		fieldOrder := append([]byte{0x1d, 0x40, 0}, words...)
		if !bytes.Contains(saved, append(fieldOrder, 0x24, 0, 142)) {
			t.Fatalf("saved field lost control words %x", words)
		}
		for _, tail := range [][]byte{{0x81, 0}, {0x81, 0, 0x24, 0}, {0x81, 1, 0x24, 0, 142}} {
			if err := x.Apply(gds(append(bytes.Clone(prefix), tail...))); err == nil || len(x.Fields) != 1 {
				t.Fatal("invalid SF changed display", tail)
			}
		}
	}
}

func TestReadInputFieldsUsesFixedWidthsAndScreenOrder(t *testing.T) {
	x := New()
	// Define the 128-character hidden field first. An unchanged input field
	// earlier on screen must precede it in the Read Input Fields reply.
	body := []byte{4, 0x40, 4, 0x11, 0, 0, 1, 7, 0, 0, 0, 0, 0, 1, 0,
		0x11, 22, 11, 0x1d, 0x40, 0, 0x27, 0, 128,
		0x11, 2, 4, 0x1d, 0x40, 0, 0x20, 0, 2, 0xc1, 0,
		4, 0x42, 0, 0}
	if err := x.Apply(gds(body)); err != nil {
		t.Fatal(err)
	}
	if got := x.Key(0xf1); len(got) != 15 {
		t.Fatalf("unmodified read returned field data: %x", got)
	}
	if err := x.SetField(0, "Ab9"); err != nil {
		t.Fatal(err)
	}
	want := append([]byte{0xc1, 0x40, 0xc1, 0x82, 0xf9}, bytes.Repeat([]byte{0x40}, 125)...)
	for _, aid := range []byte{0xf1, 0x3a} {
		got := x.Key(aid)
		if !bytes.Equal(got[13:len(got)-2], want) || int(binary.BigEndian.Uint16(got)) != len(want)+13 {
			t.Fatalf("aid %x returned wrong field contents: %x", aid, got)
		}
	}
	for _, aid := range []byte{0x39, 0xf3} {
		if got := x.Key(aid); len(got) != 15 {
			t.Fatalf("aid %x unexpectedly returned field data: %x", aid, got)
		}
	}
	if err := x.Apply(gds([]byte{4, 0x52, 0, 0})); err != nil {
		t.Fatal(err)
	}
	got := x.Key(0xf1)
	if !bytes.Equal(got[13:len(got)-2], []byte{0x11, 22, 12, 0xc1, 0x82, 0xf9}) {
		t.Fatalf("MDT read lost the modified field address: %x", got)
	}
}

func TestReadInputFieldsSignedNumericAndHostMDT(t *testing.T) {
	x := New()
	body := []byte{4, 0x40, 4, 0x11, 0, 0,
		0x11, 1, 1, 0x1d, 0x4f, 0, 0x20, 0, 3, 0xf1, 0xf2, 0x60,
		0x11, 2, 1, 0x1d, 0x47, 0, 0x20, 0, 3, 0xf3, 0xf4, 0x40,
		4, 0x42, 0, 0}
	if err := x.Apply(gds(body)); err != nil {
		t.Fatal(err)
	}
	got := x.Key(0xf1)
	if !bytes.Equal(got[13:len(got)-2], []byte{0xf1, 0xd2, 0xf3, 0xf4}) {
		t.Fatalf("wrong signed fields: %x", got)
	}
}

func TestInputFieldsHidePasswordsAndEncodeModifiedData(t *testing.T) {
	x := New()
	body := []byte{4, 0x40, 4, 0x11, 0, 0, 0x11, 8, 46, 0x1d, 0x40, 0, 0x26, 0, 10}
	body = append(body, bytes.Repeat([]byte{0x40}, 10)...)
	body = append(body, 0x11, 9, 46, 0x1d, 0x40, 0, 0x27, 0, 33)
	body = append(body, bytes.Repeat([]byte{0x40}, 33)...)
	if err := x.Apply(gds(body)); err != nil {
		t.Fatal(err)
	}
	if len(x.Fields) != 2 || x.Fields[0].Row != 8 || x.Fields[0].Column != 47 || x.Fields[1].Length != 33 {
		t.Fatalf("fields=%+v", x.Fields)
	}
	if err := x.SetField(0, "QSECOFR"); err != nil {
		t.Fatal(err)
	}
	if err := x.SetField(1, "QSECOFR"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(x.Rows()[7], "QSECOFR") || strings.Contains(x.Rows()[8], "QSECOFR") {
		t.Fatal("field rendering exposes hidden input")
	}
	key := x.Key(0xf1)
	if binary.BigEndian.Uint16(key) != 33 || !bytes.Equal(key[13:16], []byte{0x11, 8, 47}) || !bytes.Equal(key[23:26], []byte{0x11, 9, 47}) {
		t.Fatalf("input record=%x", key)
	}
	before := append([]byte(nil), x.data[:]...)
	if x.SetField(0, strings.Repeat("X", 11)) == nil || !bytes.Equal(before, x.data[:]) {
		t.Fatal("oversized field mutated display")
	}
}

func TestSaveRestorePreservesActualDisplay(t *testing.T) {
	x := New()
	body := []byte{4, 0x40, 4, 0x11, 0, 0, 0x11, 2, 5, 0x22, 0xc1, 0xc2, 0x1f, 0x1f, 0x1f, 0x4b, 0x11, 4, 1, 0x1d, 0x40, 0, 0x27, 0, 10}
	body = append(body, bytes.Repeat([]byte{0x40}, 10)...)
	body = append(body, 0x13, 4, 2, 4, 0x52, 0, 0)
	if err := x.Apply(gds(body)); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(x.Rows()[1], "AB███.") {
		t.Fatalf("physical member data rendered as %q", x.Rows()[1])
	}
	x.SetField(0, "SECRET")
	request := gds([]byte{4, 2})
	request[9] = 4
	reply, err := x.Feed(append(request, 255, 239))
	if err != nil {
		t.Fatal(err)
	}
	if len(reply) == 0 {
		t.Fatal("save produced no real terminal reply")
	}
	saved := bytes.ReplaceAll(reply[:len(reply)-2], []byte{255, 255}, []byte{255})
	if !bytes.Equal(saved[10:14], []byte{4, 0x12, 4, 0x40}) {
		t.Fatal("saved display lacks Restore Screen marker")
	}
	saved[9] = 5
	y := New()
	if err := y.Apply(saved); err != nil {
		t.Fatal(err)
	}
	if x.data != y.data || x.attributes != y.attributes || x.markers != y.markers || x.cursor != y.cursor || len(y.Fields) != 1 || y.Fields[0].Length != 10 || y.readMode != x.readMode {
		t.Fatal("saved screen did not restore terminal state")
	}
	if strings.Contains(strings.Join(y.Rows(), "\n"), "SECRET") {
		t.Fatal("restore exposed nondisplay field")
	}
	malformed := []byte{0, 10, 0x12, 0xa0, 0, 0, 255, 0, 0, 4, 255, 239}
	if _, err := y.Feed(malformed); err == nil {
		t.Fatal("invalid variable header accepted")
	}
}

// TestWriteErrorCode renders WEC text on the error line, keeping the rest of
// the display, as when a roll key passes the last page of a list.
func TestWriteErrorCode(t *testing.T) {
	term := New()
	// Clear unit, then WTD "TOP" at row 1 column 2.
	if err := term.Apply(gds([]byte{4, 0x40, 4, 0x11, 0, 0, 0x11, 1, 2, 0xe3, 0xd6, 0xd7})); err != nil {
		t.Fatal(err)
	}
	// WEC: IC row 24 column 2, then attribute and "END" (EBCDIC).
	if err := term.Apply(gds([]byte{4, 0x21, 0x13, 24, 2, 0x22, 0xc5, 0xd5, 0xc4})); err != nil {
		t.Fatalf("write error code: %v", err)
	}
	rows := term.Rows()
	if !strings.Contains(rows[0], "TOP") || !strings.Contains(rows[23], "END") {
		t.Fatalf("rows %q / %q", rows[0], rows[23])
	}
	if row, col := term.Cursor(); row != 24 || col != 2 {
		t.Fatalf("cursor %d,%d", row, col)
	}
}
