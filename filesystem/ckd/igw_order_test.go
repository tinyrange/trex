package ckd

import "testing"

func TestAttributePageRejectsDescendingKey(t *testing.T) {
	b := attributeFixture()
	b[30] = 1 // Leaf keys, unlike shortened internal separators, are ordered.
	// Second cell: keep only four leading zeros, supply zero, then suppress
	// fifteen trailing zeros. The reconstructed key precedes the nonzero anchor.
	b[94], b[95], b[96] = 4, 15, 0
	if _, err := ParseAttributePage(b); err == nil {
		t.Fatal("descending key accepted")
	}
}

func TestAttributeInternalSeparatorMayBeShortened(t *testing.T) {
	b := attributeFixture()
	// The first child begins in metadata for namespace 3; the next separator
	// is only the namespace prefix, as in the JVB500 active root.
	b[66], b[67], b[70] = 0x70, 4, 0x5a
	b[94], b[95], b[96] = 6, 13, 0
	p, err := ParseAttributePage(b)
	if err != nil || p.Level != 2 || len(p.Cells) != 2 || p.Cells[1].Key[5] != 3 || p.Cells[1].Key[14] != 0 {
		t.Fatal(p, err)
	}
	// The same encoding is not valid as descending leaf data.
	b[30] = 1
	if _, err := ParseAttributePage(b); err == nil {
		t.Fatal("descending leaf accepted")
	}
}
