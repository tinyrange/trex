package xcoff

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
)

func loaderFixture() []byte {
	b := make([]byte, 512)
	be := binary.BigEndian
	be.PutUint16(b, 0x01df)
	be.PutUint16(b[2:], 3)
	sections := []struct {
		name                string
		offset, size, flags uint32
	}{{".text", 160, 32, 0x20}, {".data", 192, 32, 0x40}, {".loader", 256, 87, 0x1000}}
	for i, s := range sections {
		row := b[20+i*40 : 60+i*40]
		copy(row, s.name)
		be.PutUint32(row[16:], s.size)
		be.PutUint32(row[20:], s.offset)
		be.PutUint32(row[36:], s.flags)
	}
	be.PutUint32(b[24+40:], 0x1000)
	be.PutUint32(b[28+40:], 0x1000)
	h := b[256:]
	for i, v := range []uint32{1, 1, 1, 7, 1, 68, 12, 75} {
		be.PutUint32(h[i*4:], v)
	}
	sym := h[32:56]
	be.PutUint32(sym[4:], 2)
	be.PutUint32(sym[8:], 0x1004)
	be.PutUint16(sym[12:], 2)
	sym[14] = 0x31
	sym[15] = 5
	rel := h[56:68]
	be.PutUint32(rel, 0x1004)
	be.PutUint32(rel[4:], 1)
	be.PutUint16(rel[8:], 0x1f00)
	be.PutUint16(rel[10:], 2)
	copy(h[68:], []byte("/lib\x00\x00\x00"))
	be.PutUint16(h[75:], 10)
	copy(h[77:], []byte("entryData\x00"))
	copy(b[192:], "DATA IS NOT RELOCATED")
	return b
}

func TestLoaderSymbolsImportsAndRelocationIdentity(t *testing.T) {
	raw := loaderFixture()
	before := append([]byte{}, raw...)
	f, err := Open(&starfile.Bytes{Data: raw}, 8)
	if err != nil {
		t.Fatal(err)
	}
	l, err := f.ReadLoader(8, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Symbols) != 1 || l.Symbols[0].Name != "entryData" || !l.Symbols[0].EntryDescriptor || !l.Symbols[0].Exported || l.Symbols[0].Imported {
		t.Fatal(l.Symbols)
	}
	if len(l.Imports) != 1 || l.Imports[0].Path != "/lib" {
		t.Fatal(l.Imports)
	}
	r := l.Relocations[0]
	if r.Symbol != ".data" || r.SectionOffset != 4 || r.Bits != 32 || r.Type != 0x1f00 {
		t.Fatal(r)
	}
	if !bytes.Equal(raw, before) {
		t.Fatal("inspection modified stored data")
	}
	binary.BigEndian.PutUint32(raw[256+60:], 3)
	f, err = Open(&starfile.Bytes{Data: raw}, 8)
	if err != nil {
		t.Fatal(err)
	}
	l, err = f.ReadLoader(8, 4096)
	if err != nil || l.Relocations[0].Symbol != "entryData" {
		t.Fatal(l, err)
	}
	identified, err := auto.Identify(&starfile.Bytes{Data: raw}, auto.Options{})
	if err != nil {
		t.Fatal(err)
	}
	entries, err := identified.View.Entries()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name == "loader" {
			children, err := e.View.Entries()
			if err != nil || len(children) != 4 {
				t.Fatal(children, err)
			}
			return
		}
	}
	t.Fatal("missing lazy loader view")
}

func TestLoaderMalformedTablesReferencesAndBudget(t *testing.T) {
	be := binary.BigEndian
	for name, mutate := range map[string]func([]byte){
		"version":            func(h []byte) { be.PutUint32(h, 2) },
		"huge counts":        func(h []byte) { be.PutUint32(h[8:], 0xffffffff) },
		"name offset":        func(h []byte) { be.PutUint32(h[36:], 0xffffffff) },
		"name count":         func(h []byte) { be.PutUint16(h[75:], 0xffff) },
		"name terminator":    func(h []byte) { h[86] = 0x41 },
		"import terminator":  func(h []byte) { h[72] = 0x41 },
		"import count":       func(h []byte) { be.PutUint32(h[16:], 2) },
		"table overlap":      func(h []byte) { be.PutUint32(h[28:], 68) },
		"symbol section":     func(h []byte) { be.PutUint16(h[44:], 8) },
		"symbol import":      func(h []byte) { be.PutUint32(h[48:], 2) },
		"relocation section": func(h []byte) { be.PutUint16(h[66:], 0) },
		"relocation index":   func(h []byte) { be.PutUint32(h[60:], 4) },
		"relocation address": func(h []byte) { be.PutUint32(h[56:], 0x101f) },
		"relocation width":   func(h []byte) { be.PutUint16(h[64:], 0x3f00) },
	} {
		t.Run(name, func(t *testing.T) {
			raw := loaderFixture()
			mutate(raw[256:])
			f, err := Open(&starfile.Bytes{Data: raw}, 8)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.ReadLoader(100, 4096); err == nil {
				t.Fatal("accepted malformed loader")
			}
		})
	}
	f, err := Open(&starfile.Bytes{Data: loaderFixture()}, 8)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.ReadLoader(8, 86); err == nil {
		t.Fatal("metadata byte budget ignored")
	}
	if _, err := loaderView(f, auto.Options{MaxEntries: 20, MaxExpandedBytes: 100}).Entries(); err == nil {
		t.Fatal("loader JSON byte budget ignored")
	}
	if _, err := f.ReadLoader(2, 4096); err == nil {
		t.Fatal("record budget ignored")
	}
}
