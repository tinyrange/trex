package ckd

import (
	"bytes"
	"testing"
)

func objCard(kind []byte, cols func(c []byte)) []byte {
	c := bytes.Repeat([]byte{0x40}, 80)
	c[0] = 0x02
	copy(c[1:], kind)
	cols(c)
	return c
}

func esdCard(first uint16, items ...[]byte) []byte {
	return objCard(ebcdicESD, func(c []byte) {
		be.PutUint16(c[10:], uint16(16*len(items)))
		be.PutUint16(c[14:], first)
		for i, it := range items {
			copy(c[16+16*i:], it)
		}
	})
}

func esdItem(name string, typ byte, address, value uint32) []byte {
	it := make([]byte, 16)
	copy(it, eb(name, 8))
	it[8] = typ
	it[9], it[10], it[11] = byte(address>>16), byte(address>>8), byte(address)
	it[13], it[14], it[15] = byte(value>>16), byte(value>>8), byte(value)
	return it
}

func txtCard(id uint16, address uint32, data []byte) []byte {
	return objCard(ebcdicTXT, func(c []byte) {
		c[5], c[6], c[7] = byte(address>>16), byte(address>>8), byte(address)
		be.PutUint16(c[10:], uint16(len(data)))
		be.PutUint16(c[14:], id)
		copy(c[16:], data)
	})
}

func xsdCard(kind, id uint16, total, offset int, piece []byte) []byte {
	return objCard(ebcdicXSD, func(c []byte) {
		be.PutUint16(c[10:], uint16(16+len(piece)))
		be.PutUint16(c[12:], kind)
		be.PutUint16(c[14:], id)
		be.PutUint32(c[16:], uint32(total))
		be.PutUint32(c[20:], uint32(offset))
		copy(c[32:], piece)
	})
}

func TestObjectDeck(t *testing.T) {
	rld := objCard(ebcdicRLD, func(c []byte) {
		items := []byte{0, 2, 0, 1, 0x0d, 0, 0, 0x10, 0x0c, 0, 0, 0x14, 0, 1, 0, 1, 0x0d, 0, 0, 0x18} // last flag continues but card ends
		be.PutUint16(c[10:], uint16(len(items)))
		copy(c[16:], items)
	})
	long := []byte("averyveryveryveryverylongname_more_than_forty_bytes")
	deck := bytes.Join([][]byte{
		card([]byte("* comment card")),
		esdCard(1, esdItem("MAIN", 0x00, 0, 0x30), esdItem("ENTRY", 0x01, 0x08, 1), esdItem("EXT", 0x02, 0, 0)),
		txtCard(1, 0x00, []byte("ABCDEFGH")),
		txtCard(1, 0x20, []byte("XY")),
		rld,
		objCard(ebcdicEND, func(c []byte) { be.PutUint16(c[14:], 1) }),
		// Second module: ESDIDs restart; an XSD name spans two cards.
		xsdCard(0, 1, len(long), 1, long[:40]),
		xsdCard(0, 1, len(long), 41, long[40:]),
		txtCard(1, 0, []byte("Z")),
		objCard(ebcdicEND, func(c []byte) {}),
	}, nil)
	d, err := ParseObjectDeck(deck, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Symbols) != 4 || d.Symbols[1].Owner != 1 || d.Symbols[2].ID != 2 || d.Symbols[3].Name != Identifier(long) || !d.Symbols[3].Extended || d.Symbols[3].Module != 1 {
		t.Fatalf("symbols %+v", d.Symbols)
	}
	if len(d.Relocations) != 3 || d.Relocations[1].Relocation != 2 || d.Relocations[2].Relocation != 1 || len(d.Ends) != 2 || len(d.Others) != 1 {
		t.Fatalf("relocations %+v ends %+v", d.Relocations, d.Ends)
	}
	s, err := d.Sections(1 << 20)
	if err != nil || len(s) != 1 || len(s[0].Data) != 0x30 || !bytes.HasPrefix(s[0].Data, []byte("ABCDEFGH")) || string(s[0].Data[0x20:0x22]) != "XY" {
		t.Fatalf("sections %+v %v", s, err)
	}
	bad := map[string][]byte{
		"undefined-txt": txtCard(5, 0, []byte("A")),
		"partial":       deck[:79],
		"xsd-order":     xsdCard(0, 1, len(long), 2, long[:10]),
		"xsd-open":      xsdCard(0, 1, len(long), 1, long[:40]),
		"txt-beyond":    append(esdCard(1, esdItem("S", 0, 0, 4)), txtCard(1, 2, []byte("ABCD"))...),
	}
	for name, b := range bad {
		d, err := ParseObjectDeck(b, 100)
		if err == nil {
			_, err = d.Sections(1 << 20)
		}
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCMSLoadLibrary(t *testing.T) {
	member := [][]byte{{0x20, 0x80, 0, 0}, bytes.Repeat([]byte{0x47}, 40)}
	entry := func(name string, c byte, record uint32, user int) []byte {
		e := make([]byte, (16+user+15)&^15)
		copy(e, eb(name, 8))
		e[11] = c
		be.PutUint32(e[12:], record)
		return e
	}
	dir := append(entry("PROG", 0x2c, 2, 24), entry("ALIAS", 0xb1, 2, 34)...)
	dir2 := entry("OTHER", 0x2e, 5, 28)
	header := make([]byte, 64)
	copy(header, cmsLibraryMagic)
	be.PutUint32(header[8:], uint32(len(dir)+len(dir2)))
	be.PutUint32(header[12:], 7)
	be.PutUint32(header[16:], 16)
	copy(header[20:], cmsLibraryMagic)
	be.PutUint16(header[26:], 7)
	records := [][]byte{header, member[0], member[1], cmsLibraryDelimiter, member[1], cmsLibraryDelimiter, append(dir, 0, 0, 0, 0, 0, 0, 0, 0), dir2}
	l, err := ParseCMSLoadLibrary(vstream(records...), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Entries) != 3 || !l.Entries[1].Alias || len(l.Entries[1].UserData) != 34 || len(l.Entries[0].Records) != 2 || len(l.Entries[2].Records) != 1 || l.Entries[2].Name != "OTHER" {
		t.Fatalf("entries %+v", l.Entries)
	}
	records[5] = []byte{0x40} // the final member's delimiter
	if _, err := ParseCMSLoadLibrary(vstream(records...), 100); err == nil {
		t.Fatal("accepted member without delimiter")
	}
}

func TestCMSCallableLibraryAndDMSLIB(t *testing.T) {
	h := make([]byte, 56)
	copy(h, eb("VMLIB", 8))
	copy(h[8:], []byte{0xf0, 0xf6, 0x61, 0xf1, 0xf5, 0x61, 0xf0, 0xf3})
	image := bytes.Repeat([]byte{0x07}, 16)
	r1 := moduleSpec{origin: 0x1f00000, image: image, coreSplit: []int{16}, loader: []string{"RTN1"}, loaderSize: 24, relocations: []uint32{0x1f00004}, width: 5, extra: [][]byte{make([]byte, 30)}}
	r2 := moduleSpec{origin: 0x1f00000, image: image, coreSplit: []int{16}, loader: []string{"RTN2"}, loaderSize: 24, width: 5, relocations: []uint32{0x1f00008}, extra: [][]byte{make([]byte, 10), card(eb("INDEX", 5))}}
	l, err := ParseCMSCallableLibrary(vstream(append(append([][]byte{h}, r1.records()...), r2.records()...)...), 100)
	if err != nil {
		t.Fatal(err)
	}
	if l.Name != "VMLIB" || l.Date != "06/15/03" || len(l.Segments) != 2 || l.Segments[1].LoaderTable[0].Name != "RTN2" || len(l.Segments[1].Extra) != 90 {
		t.Fatalf("csllib %+v", l)
	}

	// DMSLIB: header, two members (the first with an entry point alias),
	// delimiter, directory record.
	hdr := card(cmsOldLibraryMagic)
	be.PutUint16(hdr[6:], 6)
	be.PutUint32(hdr[8:], 36)
	be.PutUint32(hdr[12:], 1)
	be.PutUint32(hdr[16:], 12)
	dir := make([]byte, 80)
	for i, e := range []struct {
		name  string
		start uint16
	}{{"FIRST", 2}, {"ENTRY", 2}, {"SECOND", 4}} {
		copy(dir[12*i:], eb(e.name, 8))
		be.PutUint16(dir[12*i+8:], e.start)
		be.PutUint16(dir[12*i+10:], 0x80)
	}
	data := bytes.Join([][]byte{hdr, card([]byte("a")), card([]byte("b")), card([]byte("c")), card(cmsLibraryDelimiter), dir}, nil)
	lib, err := ParseCMSLibrary(data, 10)
	if err != nil {
		t.Fatal(err)
	}
	if lib.Format != "DMSLIB" || len(lib.Entries) != 3 || lib.Entries[1].Records != 2 || lib.Entries[2].Records != 1 || !bytes.Equal(lib.Member(2), card([]byte("c"))) {
		t.Fatalf("dmslib %+v", lib.Entries)
	}
	data[4*80] = 0x40 // remove the delimiter
	if _, err := ParseCMSLibrary(data, 10); err == nil {
		t.Fatal("accepted DMSLIB without delimiter")
	}
}

func FuzzParseObjectDeck(f *testing.F) {
	f.Add(bytes.Join([][]byte{esdCard(1, esdItem("A", 0, 0, 8)), txtCard(1, 0, []byte("x"))}, nil))
	f.Fuzz(func(t *testing.T, b []byte) {
		b = b[:len(b)/80*80]
		if d, err := ParseObjectDeck(b, 1000); err == nil {
			_, _ = d.Sections(1 << 20)
		}
	})
}

func FuzzParseCMSLoadLibrary(f *testing.F) {
	f.Add([]byte{0, 4, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ParseCMSLoadLibrary(b, 1000)
	})
}
