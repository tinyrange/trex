package ckd

import (
	"bytes"
	"testing"
)

func card(b []byte) []byte {
	r := bytes.Repeat([]byte{0x40}, 80)
	copy(r, b)
	return r
}

// libpds builds a LIBPDS library from members (each a list of 80-byte cards)
// and directory entries naming a member index.
func libpds(members [][][]byte, entries []struct {
	name   string
	member int
}) []byte {
	var body [][]byte
	starts := make([]uint32, len(members))
	for i, m := range members {
		starts[i] = uint32(len(body) + 2)
		body = append(body, m...)
		body = append(body, card(cmsLibraryDelimiter))
	}
	var dir []byte
	for _, e := range entries {
		x := make([]byte, 16)
		copy(x, eb(e.name, 8))
		be.PutUint32(x[8:], 0x80)
		be.PutUint32(x[12:], starts[e.member])
		dir = append(dir, x...)
	}
	header := make([]byte, 80)
	copy(header, cmsLibraryMagic)
	be.PutUint32(header[8:], uint32(len(dir)))
	be.PutUint32(header[12:], uint32(len(body)+2))
	be.PutUint32(header[16:], 32)
	be.PutUint32(header[20:], 2)
	out := append(header, bytes.Join(body, nil)...)
	for len(dir)%80 != 0 {
		dir = append(dir, 0)
	}
	return append(out, dir...)
}

func TestCMSLibraryMembersAndAliases(t *testing.T) {
	members := [][][]byte{{card(eb("FIRST", 5)), card(eb("LINE2", 5))}, {card(eb("SECOND", 6))}, {}}
	b := libpds(members, []struct {
		name   string
		member int
	}{{"FIRST", 0}, {"ENTRY1", 0}, {"SECOND", 1}, {"EMPTY", 2}, {"ALIAS2", 1}, {"LAST", 0}})
	l, err := ParseCMSLibrary(b, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Entries) != 6 || l.Reserved != [2]uint32{32, 2} {
		t.Fatalf("library %+v", l)
	}
	want := map[string][]byte{"FIRST": bytes.Join(members[0], nil), "ENTRY1": bytes.Join(members[0], nil), "SECOND": members[1][0], "ALIAS2": members[1][0], "EMPTY": {}}
	for i, e := range l.Entries[:5] {
		if !bytes.Equal(l.Member(i), want[e.Name]) || e.Flags != 0x80 {
			t.Fatalf("%s: %x", e.Name, l.Member(i))
		}
	}
	if _, err := ParseCMSLibrary(b, 5); err == nil {
		t.Fatal("ignored entry limit")
	}
	cases := map[string]func([]byte){
		"magic":         func(b []byte) { b[0] = 0 },
		"partial":       func(b []byte) {},
		"dir-length":    func(b []byte) { be.PutUint32(b[8:], 17) },
		"dir-not-final": func(b []byte) { be.PutUint32(b[12:], be.Uint32(b[12:])-1) },
		"entry-range": func(b []byte) {
			be.PutUint32(b[int(be.Uint32(b[12:])-1)*80+12:], be.Uint32(b[12:]))
		},
		"no-delimiter": func(b []byte) { b[6*80] = 0x40 }, // the final member's delimiter
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := bytes.Clone(b)
			mutate(c)
			if name == "partial" {
				c = c[:len(c)-1]
			}
			if _, err := ParseCMSLibrary(c, 100); err == nil {
				t.Fatal("accepted malformed library")
			}
		})
	}
}

func packed(recfm byte, lrecl uint32, codes ...[]byte) []byte {
	b := []byte{0, 1, 0x40, recfm}
	b = be.AppendUint32(b, lrecl)
	return append(b, bytes.Join(codes, nil)...)
}

func TestUnpackCMSFixedAndVariable(t *testing.T) {
	// F 10: "  ABC" + 5 blanks, then 10 x 'Z', then 300 blanks + "0123456789"
	// split across records via the long forms.
	lit := []byte("0123456789")
	f := packed(0xc6, 10,
		[]byte{0x01}, []byte{0x82, 'A', 'B', 'C'}, []byte{0x78, 0x04},
		[]byte{0x7a, 0x09, 'Z'},
		[]byte{0x79, 0x01, 0x2b}, // 300 blanks
		append([]byte{0xf8, 0x09}, lit...),
		[]byte{0x7b, 0x00, 0x09, 'Y'},
		append([]byte{0xf9, 0x00, 0x09}, lit...),
		[]byte{0xff, 0x40, 0x40})
	u, err := UnpackCMS(f, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	want := append(append(append(append(append([]byte("\x40\x40ABC\x40\x40\x40\x40\x40"), bytes.Repeat([]byte("Z"), 10)...), bytes.Repeat([]byte{0x40}, 300)...), lit...), bytes.Repeat([]byte("Y"), 10)...), lit...)
	if u.RecordFormat != 0xc6 || u.Records != 35 || !bytes.Equal(u.Data, want) {
		t.Fatalf("fixed: %d records %q", u.Records, u.Data)
	}
	// V 20: "AB" ending with literal, 3 blanks ending with blanks, "xxQQQ"
	// ending with a repeat.
	v := packed(0xe5, 20, []byte{0xfc, 0x01, 'A', 'B'}, []byte{0x7c, 0x02}, []byte{0x81, 'x', 'x', 0x7e, 0x02, 'Q'}, []byte{0xff})
	u, err = UnpackCMS(v, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if u.Records != 3 || u.MaximumRecord != 5 || !bytes.Equal(u.Data, []byte("\x00\x02AB\x00\x03\x40\x40\x40\x00\x05xxQQQ")) {
		t.Fatalf("variable: %+v %q", u, u.Data)
	}
	// A final record may carry the previous 1024-byte record's leftover bytes.
	stale := packed(0xc6, 1, append([]byte{0xf8, 0xff}, bytes.Repeat([]byte("S"), 256)...))
	for len(stale) < 1024 {
		stale = append(stale, 0x00) // 1-blank codes
	}
	end := len(stale)
	stale = append(stale, 0xff)
	stale = append(stale, stale[end+1-1024:end]...)
	stale = stale[:2048]
	if u, err = UnpackCMS(stale, 1<<20); err != nil || u.Records != 256+(1024-8-258) {
		t.Fatal("stale tail", err)
	}
	bad := map[string][]byte{
		"magic":         {0, 2, 0x40, 0xc6, 0, 0, 0, 1, 0xff},
		"no-end":        packed(0xc6, 1, []byte{0x00}),
		"partial":       packed(0xc6, 2, []byte{0x00, 0xff}),
		"after-end":     packed(0xc6, 1, []byte{0x00, 0xff, 0x41}),
		"unknown":       packed(0xc6, 1, []byte{0x7d, 0x00, 0xff}),
		"fixed-eor":     packed(0xc6, 1, []byte{0xfc, 0x00, 'a', 0xff}),
		"variable-long": packed(0xe5, 2, []byte{0xfc, 0x02, 'a', 'b', 'c', 0xff}),
		"truncated":     packed(0xc6, 1, []byte{0xf9, 0x00}),
		"limit":         packed(0xc6, 1, []byte{0x79, 0xff, 0xff, 0xff}),
	}
	for name, b := range bad {
		if _, err := UnpackCMS(b, 1000); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func FuzzUnpackCMS(f *testing.F) {
	f.Add(packed(0xe5, 20, []byte{0xfc, 0x01, 'A', 'B', 0x7c, 0x02, 0xff}))
	f.Add(packed(0xc6, 10, []byte{0x79, 0x01, 0x2b, 0x7b, 0x00, 0x09, 'Y', 0xff}))
	f.Fuzz(func(t *testing.T, b []byte) {
		if u, err := UnpackCMS(b, 1<<20); err == nil && len(u.Data) > 1<<20 {
			t.Fatal("exceeded limit")
		}
	})
}

func FuzzParseCMSLibrary(f *testing.F) {
	f.Add(libpds([][][]byte{{card([]byte("A"))}}, []struct {
		name   string
		member int
	}{{"A", 0}}))
	f.Fuzz(func(t *testing.T, b []byte) {
		if l, err := ParseCMSLibrary(b, 1000); err == nil {
			for i := range l.Entries {
				_ = l.Member(i)
			}
		}
	})
}
