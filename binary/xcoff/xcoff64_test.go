package xcoff

import (
	"bytes"
	"encoding/binary"
	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func fixture64() []byte {
	b := make([]byte, 644)
	be := binary.BigEndian
	be.PutUint16(b, 0x01f7)
	be.PutUint16(b[2:], 2)
	be.PutUint64(b[8:], 600)
	be.PutUint16(b[16:], 120)
	be.PutUint32(b[20:], 2)
	o := b[24:144]
	be.PutUint16(o, 0x10b)
	be.PutUint64(o[24:], 0x100000100)
	be.PutUint16(o[32:], 1)
	be.PutUint16(o[38:], 1)
	be.PutUint64(o[80:], 0x100000108)
	s := b[144:216]
	copy(s, ".text")
	be.PutUint64(s[8:], 0x100000100)
	be.PutUint64(s[16:], 0x100000100)
	be.PutUint64(s[24:], 16)
	be.PutUint64(s[32:], 288)
	be.PutUint64(s[40:], 550)
	be.PutUint32(s[56:], 1)
	be.PutUint32(s[64:], 32)
	s = b[216:288]
	copy(s, ".loader")
	be.PutUint64(s[24:], 106)
	be.PutUint64(s[32:], 400)
	be.PutUint32(s[64:], 0x1000)
	copy(b[288:], "sixteen rawbytes!")
	l := b[400:506]
	be.PutUint32(l, 2)
	be.PutUint32(l[4:], 1)
	be.PutUint32(l[8:], 1)
	be.PutUint32(l[12:], 4)
	be.PutUint32(l[16:], 1)
	be.PutUint32(l[20:], 6)
	be.PutUint64(l[24:], 96)
	be.PutUint64(l[32:], 100)
	be.PutUint64(l[40:], 56)
	be.PutUint64(l[48:], 80)
	sym := l[56:80]
	be.PutUint64(sym, 0x100000108)
	be.PutUint32(sym[8:], 2)
	be.PutUint16(sym[12:], 1)
	sym[14] = 0x10
	sym[15] = 7
	rel := l[80:96]
	be.PutUint64(rel, 0x100000108)
	be.PutUint16(rel[8:], 0x3f00)
	be.PutUint16(rel[10:], 1)
	be.PutUint32(rel[12:], 3)
	copy(l[96:], "/\x00\x00\x00")
	be.PutUint16(l[100:], 4)
	copy(l[102:], "foo\x00")
	rel = b[550:564]
	be.PutUint64(rel, 0x100000108)
	rel[12] = 63
	sym = b[600:618]
	be.PutUint64(sym, 0x100000108)
	be.PutUint32(sym[8:], 4)
	be.PutUint16(sym[12:], 1)
	sym[16] = 2
	sym[17] = 1
	aux := b[618:636]
	be.PutUint32(aux, 7)
	be.PutUint32(aux[12:], 1)
	aux[10] = 3<<3 | 1
	aux[11] = 7
	aux[17] = 251
	be.PutUint32(b[636:], 8)
	copy(b[640:], "foo\x00")
	return b
}
func TestXCOFF64TablesAndNativeNesting(t *testing.T) {
	b := fixture64()
	f, err := Open64(&starfile.Bytes{Data: b}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if f.EntryPoint != 0x100000108 || f.TOC != 0x100000100 || f.EntrySection != 1 {
		t.Fatal(f)
	}
	f.SymbolOffset = 0
	f.Symbols = 0
	f.Sections[0].Size = 0 // Public metadata does not change validated table references.
	symbols, err := f.ReadSymbols(10, 1000)
	if err != nil || len(symbols) != 1 || symbols[0].Name != "foo" || symbols[0].Csect.LengthOrIndex != 0x100000007 {
		t.Fatal(symbols, err)
	}
	rels, err := f.ReadRelocations(1, 10, 1000)
	if err != nil || len(rels) != 1 || rels[0].Bits != 64 || rels[0].SectionOffset != 8 {
		t.Fatal(rels, err)
	}
	l, err := f.ReadLoader(10, 1000)
	if err != nil || l.Version != 2 || l.Symbols[0].Value != 0x100000108 || l.Relocations[0].SectionOffset != 8 || l.Relocations[0].Symbol != "foo" {
		t.Fatal(l, err)
	}
	b[403] = 1
	l, err = f.ReadLoader(10, 1000)
	if err != nil || l.Version != 1 {
		t.Fatal(l, err)
	}
	n := auto.Open(&starfile.Bytes{Data: b}, "", auto.Options{})
	child, err := n.Resolve("loader/relocations.json")
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, child.Reader().Size())
	if _, err := child.Reader().ReadAt(raw, 0); err != nil || !bytes.Contains(raw, []byte("4294967560")) {
		t.Fatal(string(raw), err)
	}
}
func TestXCOFF64MalformedTables(t *testing.T) {
	for name, edit := range map[string]func([]byte){
		"symbol aux overrun":  func(b []byte) { b[617] = 4 },
		"symbol unterminated": func(b []byte) { b[643] = 65 },
		"loader overlap":      func(b []byte) { binary.BigEndian.PutUint64(b[448:], 56) },
		"loader section":      func(b []byte) { binary.BigEndian.PutUint16(b[490:], 3) },
		"loader symbol":       func(b []byte) { binary.BigEndian.PutUint32(b[492:], 4) },
		"section symbol aux":  func(b []byte) { binary.BigEndian.PutUint32(b[558:], 1) },
		"section width":       func(b []byte) { binary.BigEndian.PutUint64(b[550:], 0x10000010f) },
	} {
		t.Run(name, func(t *testing.T) {
			b := fixture64()
			edit(b)
			f, e := Open64(&starfile.Bytes{Data: b}, 10)
			if e != nil {
				return
			}
			_, e1 := f.ReadSymbols(10, 1000)
			_, e2 := f.ReadRelocations(1, 10, 1000)
			_, e3 := f.ReadLoader(10, 1000)
			if e1 == nil && e2 == nil && e3 == nil {
				t.Fatal("accepted malformed table")
			}
		})
	}
	for _, edit := range []func([]byte){func(b []byte) { binary.BigEndian.PutUint64(b[176:], ^uint64(0)) }, func(b []byte) { binary.BigEndian.PutUint64(b[168:], ^uint64(0)) }, func(b []byte) { binary.BigEndian.PutUint64(b[8:], ^uint64(0)) }} {
		b := fixture64()
		edit(b)
		if _, err := Open64(&starfile.Bytes{Data: b}, 10); err == nil {
			t.Fatal("accepted header overflow")
		}
	}
	f, _ := Open64(&starfile.Bytes{Data: fixture64()}, 10)
	if _, err := f.ReadSymbols(1, 1000); err == nil {
		t.Fatal("symbol budget")
	}
	if _, err := f.ReadLoader(10, 56); err == nil {
		t.Fatal("loader budget")
	}
}
func FuzzXCOFF64(f *testing.F) {
	f.Add(fixture64())
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := Open64(&starfile.Bytes{Data: b}, 64)
		if err == nil {
			p.ReadSymbols(1024, 65536)
			p.ReadLoader(1024, 65536)
			for i := range p.Sections {
				p.ReadRelocations(i+1, 1024, 65536)
			}
		}
	})
}
