package hunk

import (
	"encoding/binary"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

func words(v ...uint32) []byte {
	b := make([]byte, len(v)*4)
	for i, x := range v {
		binary.BigEndian.PutUint32(b[i*4:], x)
	}
	return b
}
func objectFixture() []byte {
	return words(UnitTag, 1, 0x6f626a00, NameTag, 1, 0x74657874,
		CodeTag, 2, 0x12345678, 0x9abcdef0,
		Reloc32Tag, 1, 1, 4, 0,
		ExtTag, 0x01000001, 0x666f6f00, 4, 0x81000001, 0x62617200, 1, 0, 0,
		SymbolTag, 1, 0x666f6f00, 4, 0,
		DebugTag, 1, 0xabcdef00, EndTag,
		BSSTag, 32, EndTag)
}
func TestObjectViews(t *testing.T) {
	b := objectFixture()
	a, err := OpenObjects(&starfile.Bytes{Data: b}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Units) != 1 || len(a.Units[0].Records) != 10 {
		t.Fatalf("unexpected units: %+v", a)
	}
	u := a.Units[0]
	if u.Raw.Size() != int64(len(b)) {
		t.Fatal("unit length")
	}
	code := u.Records[2]
	got, err := starfile.ReadAll(code.Payload)
	if err != nil || string(got) != string(words(0x12345678, 0x9abcdef0)) {
		t.Fatal(got, err)
	}
	if code.MemorySize != 8 || u.Records[8].MemorySize != 128 || u.Records[8].Payload != nil {
		t.Fatal("section sizes")
	}
	if len(u.Records[3].Relocations) != 1 || u.Records[3].Relocations[0].Target != 1 {
		t.Fatal("relocations")
	}
	s := u.Records[4].Symbols
	if len(s) != 2 || s[0].Kind != 1 || s[0].Value != 4 || s[1].Kind != 129 || s[1].Offsets.Size() != 4 {
		t.Fatal(s)
	}
	// Borrowing is intentional: neither code nor whole-unit views copy input.
	b[32] ^= 1
	changed, _ := starfile.ReadAll(code.Payload)
	if string(changed) == string(got) {
		t.Fatal("copied code")
	}
}
func TestMalformed(t *testing.T) {
	b := objectFixture()
	for n := 0; n < len(b); n++ {
		// The complete first section is itself a valid standalone unit.
		if n == len(b)-12 {
			continue
		}
		if _, err := OpenObjects(&starfile.Bytes{Data: b[:n]}, 100); err == nil {
			t.Fatalf("accepted prefix %d", n)
		}
	}
	for _, bad := range [][]byte{
		words(UnitTag, 0), words(UnitTag, 0, EndTag),
		words(UnitTag, 0, CodeTag, 0, CodeTag, 0, EndTag),
		words(UnitTag, 0, NameTag, 0, NameTag, 0),
		words(UnitTag, 0, CodeTag, 0, SymbolTag, 0x01000001, 0, 0, 0, EndTag),
		words(UnitTag, 0, CodeTag, 0, ExtTag, 0xff000001, 0, 0, EndTag),
		words(UnitTag, 0, CodeTag, 0xffffffff),
		words(UnitTag, 0, CodeTag, 0, Reloc32Tag, 0xffffffff),
		append(append([]byte(nil), b...), 1),
	} {
		if _, err := OpenObjects(&starfile.Bytes{Data: bad}, 100); err == nil {
			t.Fatalf("accepted malformed %x", bad)
		}
	}
	if _, err := OpenObjects(&starfile.Bytes{Data: b}, 1); err == nil {
		t.Fatal("record limit")
	}
	joined := append(append([]byte(nil), b...), b...)
	a, err := OpenObjects(&starfile.Bytes{Data: joined}, 100)
	if err != nil || len(a.Units) != 2 || a.Units[1].Records[0].Offset != int64(len(b)) {
		t.Fatal(a, err)
	}
}
func FuzzObjects(f *testing.F) {
	f.Add(objectFixture())
	f.Add(ppcFixture())
	f.Fuzz(func(t *testing.T, b []byte) {
		a, err := OpenObjects(&starfile.Bytes{Data: b}, 1000)
		if err != nil {
			return
		}
		for _, u := range a.Units {
			for _, r := range u.Records {
				if _, err := starfile.ReadAll(r.Raw); err != nil {
					t.Fatal(err)
				}
			}
		}
	})
}

func ppcFixture() []byte {
	return words(UnitTag, 0, PPCCodeTag, 1, 0x48000001,
		ExtTag, 0xe5000001, 0x666f6f00, 1, 0, 0,
		Reloc26Tag, 1, 0, 0, 0, EndTag)
}

func TestPPCObjects(t *testing.T) {
	b := ppcFixture()
	a, err := OpenObjects(&starfile.Bytes{Data: b}, 100)
	if err != nil {
		t.Fatal(err)
	}
	r := a.Units[0].Records
	if r[1].Tag != PPCCodeTag || r[1].Payload.Size() != 4 || r[2].Symbols[0].Kind != 229 || r[2].Symbols[0].Offsets.Size() != 4 || r[3].Tag != Reloc26Tag {
		t.Fatal(r)
	}
	for n := 0; n < len(b); n++ {
		if _, err := OpenObjects(&starfile.Bytes{Data: b[:n]}, 100); err == nil {
			t.Fatal("accepted PPC prefix", n)
		}
	}
}
