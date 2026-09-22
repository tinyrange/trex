package windows

import (
	"encoding/binary"
	"testing"
)

// A two-block library whose directory order differs from physical order.
func syntheticSLTG() []byte {
	lib := make([]byte, 0x400)
	p := 0
	w := func(v uint16) { binary.LittleEndian.PutUint16(lib[p:], v); p += 2 }
	d := func(v uint32) { binary.LittleEndian.PutUint32(lib[p:], v); p += 4 }
	s := func(v string) { w(uint16(len(v))); copy(lib[p:], v); p += len(v) }
	w(0x51cc)
	w(3)
	w(0)
	w(0xffff)
	s("Example library")
	w(0xffff)
	d(0)
	w(1)
	w(0x409)
	d(0)
	w(1)
	w(2)
	w(3)
	guid, _ := parseWindowsGUID("{A5064420-D541-11D4-9523-00B0D022CA64}")
	copy(lib[p:], guid[:])
	p += 16 + 0x40
	w(1)
	s("AAAAAAAAAA")
	w(0xffff)
	w(0xffff)
	w(8)
	w(0)
	w(0xffff)
	d(0)
	w(0xffff)
	copy(lib[p:], guid[:])
	p += 16
	w(3)
	d(0x180)
	binary.LittleEndian.PutUint16(lib[0x180:], 0x200)
	copy(lib[0x180+0x20+0x218:], "Example\x00ITest\x00")
	lib = lib[:0x180+0x20+0x218+14]
	data := make([]byte, 0x24+16+13+11+9+0x22+len(lib))
	copy(data, "SLTG")
	binary.LittleEndian.PutUint16(data[4:], 3)
	binary.LittleEndian.PutUint16(data[10:], 2)
	binary.LittleEndian.PutUint32(data[0x24:], uint32(len(lib)))
	binary.LittleEndian.PutUint16(data[0x28:], 9) // dir
	binary.LittleEndian.PutUint32(data[0x2c:], 0x22)
	binary.LittleEndian.PutUint16(data[0x30:], 13)
	binary.LittleEndian.PutUint16(data[0x32:], 1)
	copy(data[0x34:], "\x01CompObj\x00dir\x00AAAAAAAAAA\x00")
	start := 0x24 + 16 + 13 + 11 + 9
	binary.LittleEndian.PutUint16(data[start:], 0x501)
	data[start+0x1a] = 2
	data[start+0x1b] = 10
	data[start+0x1c] = 2
	data[start+0x1d] = 3
	copy(data[start+0x22:], lib)
	return data
}

func TestParseSLTGTypeLib(t *testing.T) {
	data := syntheticSLTG()
	lib, err := parseSLTGTypeLib(data)
	if err != nil {
		t.Fatal(err)
	}
	if lib.name != "Example" || lib.description != "Example library" || lib.major != 2 || lib.minor != 3 || lib.language != 0x409 || lib.lcid != 0 || lib.flags != 1 || lib.syskind != 1 || lib.guid != "{A5064420-D541-11D4-9523-00B0D022CA64}" {
		t.Fatalf("library: %#v", lib)
	}
	if len(lib.typeInfo) != 1 || lib.typeInfo[0].name != "ITest" || lib.typeInfo[0].kind != 4 || lib.typeInfo[0].flags != 0x140 {
		t.Fatalf("types: %#v", lib.typeInfo)
	}
	// Every truncation must produce an error, never a panic or partial result.
	for n := 0; n < len(data)-1; n++ {
		if _, err := parseSLTGTypeLib(data[:n]); err == nil {
			t.Fatalf("accepted truncation at %d", n)
		}
	}
}

func TestParseSLTGRejectsCycleAndBadLengths(t *testing.T) {
	for _, mutation := range []func([]byte){
		func(b []byte) { binary.LittleEndian.PutUint16(b[0x32:], 2) },
		func(b []byte) { binary.LittleEndian.PutUint16(b[10:], 0) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[0x2c:], 0xffffffff) },
		func(b []byte) { binary.LittleEndian.PutUint16(b[0x30:], 0xffff) },
	} {
		data := syntheticSLTG()
		mutation(data)
		if _, err := parseSLTGTypeLib(data); err == nil {
			t.Fatal("accepted malformed library")
		}
	}
}
