package windows

import (
	"debug/pe"
	"encoding/binary"
	"testing"
)

func TestBoundedSymbolNeverCrossesFunctionOrGap(t *testing.T) {
	symbols := []pdbSymbol{{name: "first", rva: 100}, {name: "next", rva: 200}}
	for _, tt := range []struct {
		ip          uint32
		fn          amd64RuntimeFunction
		found, want bool
	}{
		{99, amd64RuntimeFunction{}, false, false},
		{100, amd64RuntimeFunction{}, false, true},
		{101, amd64RuntimeFunction{}, false, false},
		{110, amd64RuntimeFunction{begin: 100, end: 120}, true, true},
		{130, amd64RuntimeFunction{begin: 125, end: 140}, true, false},
		{120, amd64RuntimeFunction{begin: 100, end: 120}, true, false},
		{205, amd64RuntimeFunction{begin: 200, end: 250}, true, true},
	} {
		_, ok := boundedSymbol(symbols, tt.ip, tt.fn, tt.found)
		if ok != tt.want {
			t.Errorf("ip=%d found=%v want=%v", tt.ip, ok, tt.want)
		}
	}
}
func TestSymbolIdentityUsesDBIAgeAndGUID(t *testing.T) {
	cv := &peCodeViewInfo{guid: "ABC", age: 2}
	p := &pdbValue{guid: "abc", age: 3, dbiAge: 2}
	if err := validateSymbolIdentity(cv, p); err != nil {
		t.Fatal(err)
	}
	p.dbiAge = 1
	if validateSymbolIdentity(cv, p) == nil {
		t.Fatal("accepted mismatched DBI age")
	}
	p.dbiAge = 2
	p.guid = "DEF"
	if validateSymbolIdentity(cv, p) == nil {
		t.Fatal("accepted mismatched GUID")
	}
	if validateSymbolIdentity(nil, p) == nil {
		t.Fatal("accepted absent identity")
	}
}

func TestChainedFunctionOwnershipAndCycle(t *testing.T) {
	image := &pe.File{Sections: []*pe.Section{{SectionHeader: pe.SectionHeader{VirtualAddress: 0x1000, VirtualSize: 128, Size: 128}}}}
	data := make([]byte, 128)
	data[0] = 1 | (4 << 3)
	data[2] = 1 // odd unwind code count; aligned chain starts at 8
	binary.LittleEndian.PutUint32(data[8:], 0x2000)
	binary.LittleEndian.PutUint32(data[12:], 0x2040)
	binary.LittleEndian.PutUint32(data[16:], 0x1040)
	data[64] = 1
	child := amd64RuntimeFunction{begin: 0x2100, end: 0x2140, unwind: 0x1000}
	owner, err := amd64SymbolOwner(image, data, child)
	if err != nil || owner.begin != 0x2000 {
		t.Fatalf("owner=%+v error=%v", owner, err)
	}
	data[64] = 1 | (4 << 3)
	binary.LittleEndian.PutUint32(data[68:], 0x2100)
	binary.LittleEndian.PutUint32(data[72:], 0x2140)
	binary.LittleEndian.PutUint32(data[76:], 0x1000)
	if _, err := amd64SymbolOwner(image, data, child); err == nil {
		t.Fatal("accepted cycle")
	}
	if _, err := amd64SymbolOwner(image, data[:12], child); err == nil {
		t.Fatal("accepted truncated chain")
	}
}
