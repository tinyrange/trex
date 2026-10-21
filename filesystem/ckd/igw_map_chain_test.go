package ckd

import (
	"bytes"
	"testing"
)

func TestIGWChainedMapPreservesHolesAndLogicalIDs(t *testing.T) {
	b := make([]byte, 4*4096)
	testVDF(b, 1)
	be.PutUint32(b[100:], 498)
	be.PutUint64(b[16:], (2+256)<<8)
	testVDF(b[2*4096:], 3)
	child := make([]byte, 4)
	be.PutUint32(child, 498)
	copy(b[4096:], testAD(2, []AttributeCell{{Key: [20]byte{}, Value: child}}))
	copy(b[3*4096:], testAD(1, []AttributeCell{{Key: testKey(4, 0x9001), Value: []byte("continued")}}))
	g, err := OpenIGW(raw(b))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := g.Attributes(1)
	if err != nil || len(rows) != 1 || string(rows[0].Value) != "continued" {
		t.Fatal(rows, err)
	}
	// Returning to VDF page zero must not loop, even though zero is a valid
	// physical page address encoded as a nonzero token.
	bad := bytes.Clone(b)
	be.PutUint32(bad[2*4096+100:], 498)
	be.PutUint64(bad[2*4096+16:], 256<<8)
	if _, err := OpenIGW(raw(bad)); err == nil {
		t.Fatal("map cycle accepted")
	}
	for _, offset := range []int{16, 100, 4095, 2 * 4096, 2*4096 + 4095} {
		bad := bytes.Clone(b)
		bad[offset] = 255
		if _, err := OpenIGW(raw(bad)); err == nil {
			t.Fatal("bad continuation accepted", offset)
		}
	}
	bad = bytes.Clone(b)
	be.PutUint64(bad[2*4096+104:], (2+256)<<8)
	if _, err := OpenIGW(raw(bad)); err == nil {
		t.Fatal("map page as attribute accepted")
	}
}
