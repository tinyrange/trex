package ckd

import (
	"bytes"
	"testing"
)

func TestAlternateReferencesReorderAndExpandNonuniqueKeys(t *testing.T) {
	// Alternate key A refers to primary keys 3 and 1, B refers to primary key 2.
	// Retain base RBAs and bytes; do not emit the AIX reference records themselves.
	alternate := []VSAMRecord{{Data: []byte{1, 1, 0, 2, 1, 'A', '3', '1'}}, {Data: []byte{1, 1, 0, 1, 1, 'B', '2'}}}
	primary := []VSAMRecord{{RBA: 100, Data: []byte("x1one")}, {RBA: 200, Data: []byte("x2two")}, {RBA: 300, Data: []byte("x3three")}}
	out, err := ResolveAlternateRecords(alternate, primary, 1, 1, 1, 3, 100)
	if err != nil || len(out) != 3 || out[0].RBA != 300 || out[1].RBA != 100 || out[2].RBA != 200 || string(out[0].Data) != "x3three" || out[2].Number != 3 {
		t.Fatal(out, err)
	}
	if _, err := ResolveAlternateRecords(alternate, primary[:2], 1, 1, 1, 3, 100); err == nil {
		t.Fatal("dangling primary reference accepted")
	}
	if _, err := ResolveAlternateRecords(alternate, primary, 1, 1, 1, 2, 100); err == nil {
		t.Fatal("record budget ignored")
	}
	if _, err := ResolveAlternateRecords(alternate, primary, 1, 1, 1, 3, 5); err == nil {
		t.Fatal("byte budget ignored")
	}
	if _, err := ResolveAlternateRecords([]VSAMRecord{alternate[1], alternate[0]}, primary, 1, 1, 1, 3, 100); err == nil {
		t.Fatal("unordered alternate keys accepted")
	}
	bad := bytes.Clone(alternate[0].Data)
	bad[len(bad)-1] = '3'
	if _, err := ParseAlternateIndexRecord(bad); err == nil {
		t.Fatal("duplicate primary key accepted")
	}
	for _, at := range []int{0, 1, 2, 3, 4} {
		bad := bytes.Clone(alternate[0].Data)
		bad[at] = 255
		if _, err := ParseAlternateIndexRecord(bad); err == nil {
			t.Fatal("bad AIX header accepted", at)
		}
	}
}

func TestCatalogTrueNameReferences(t *testing.T) {
	b := make([]byte, 54)
	be.PutUint16(b[2:], 52)
	b[4], b[8] = 0xe3, 45
	copy(b[9:], eb("AIX.DATA", 44))
	// Two counted NUL-terminated names: base cluster, then alternate cluster.
	b = append(b, 0, 18, 3, 0, 2, 0, 5)
	b = append(b, eb("BASE", 4)...)
	b = append(b, 0, 0, 4)
	b = append(b, eb("AIX", 3)...)
	b = append(b, 0)
	be.PutUint16(b, uint16(len(b)))
	r, err := ParseCatalogRecord(b)
	if err != nil || len(r.References) != 2 || r.References[0] != "BASE" || r.References[1] != "AIX" {
		t.Fatal(r, err)
	}
	b[len(b)-1] = 1
	if _, err := ParseCatalogRecord(b); err == nil {
		t.Fatal("unterminated catalog name accepted")
	}
}
