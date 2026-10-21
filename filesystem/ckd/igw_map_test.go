package ckd

import (
	"bytes"
	"testing"
)

func testVDF(b []byte, mapping ...uint64) {
	copy(b, []byte{0xc9, 0xc7, 0xe6, 0xe5, 0xc4, 0xc6, 0x40, 0x40})
	be.PutUint32(b[8:], 4096)
	b[12] = 1
	be.PutUint16(b[4094:], 0xa55a)
	be.PutUint32(b[100:], uint32(len(mapping)))
	for i, page := range mapping {
		be.PutUint64(b[104+8*i:], (page+256)<<8)
	}
}
func testAD(level byte, cells []AttributeCell) []byte {
	b := make([]byte, 4096)
	b[0], b[1], b[11], b[12], b[25], b[30] = 52, 1, 0xc1, 0xc4, 20, level
	pos := 77
	for _, c := range cells {
		size := 25 + len(c.Value)
		be.PutUint16(b[pos:], uint16(size))
		b[pos+2] = 0xc0
		copy(b[pos+5:], c.Key[:])
		copy(b[pos+25:], c.Value)
		pos += size
	}
	be.PutUint16(b[72:], uint16(pos-72))
	be.PutUint16(b[74:], uint16(pos-72))
	b[76] = byte(len(cells))
	be.PutUint16(b[48:], uint16(4094-pos))
	be.PutUint16(b[50:], 4094)
	be.PutUint16(b[4094:], 0xa55a)
	return b
}
func testKey(object byte, kind uint16) [20]byte {
	var k [20]byte
	k[5] = 3
	k[11] = object
	be.PutUint16(k[14:], kind)
	return k
}
func testRun(start uint64, count byte) []byte {
	b := make([]byte, 23)
	b[0], b[2] = 1, 1
	be.PutUint64(b[13:], (start+256)<<8|uint64(count-1))
	return b
}
func TestIGWMappedTreeShortenedSeparators(t *testing.T) {
	b := make([]byte, 4*4096)
	testVDF(b, 1, 3, 2)
	child := func(id uint32) []byte { v := make([]byte, 4); be.PutUint32(v, id); return v }
	copy(b[4096:], testAD(2, []AttributeCell{
		{Key: [20]byte{}, Value: child(1)},
		{Key: testKey(4, 0x4000), Value: child(2)},
	}))
	copy(b[3*4096:], testAD(1, []AttributeCell{{Key: testKey(4, 0x4004), Value: []byte("first")}}))
	copy(b[2*4096:], testAD(1, []AttributeCell{{Key: testKey(4, 0x5001), Value: []byte("second")}}))
	g, err := OpenIGW(raw(b))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := g.Attributes(2)
	if err != nil || len(rows) != 2 || string(rows[0].Value) != "first" || string(rows[1].Value) != "second" {
		t.Fatal(rows, err)
	}
	if _, err := g.Attributes(1); err == nil {
		t.Fatal("cell limit ignored")
	}
	// Replace first child with the root: must reject cycles rather than loop.
	be.PutUint32(b[4096+77+25:], 0)
	if _, err := g.Attributes(2); err == nil {
		t.Fatal("cycle accepted")
	}
}
func TestIGWRunOrderingAndBounds(t *testing.T) {
	b := make([]byte, 4*4096)
	testVDF(b, 1)
	for i := 1; i < 4; i++ {
		for j := 0; j < 4096; j++ {
			b[i*4096+j] = byte(i)
		}
	}
	g, err := OpenIGW(raw(b))
	if err != nil {
		t.Fatal(err)
	}
	run := append(testRun(3, 1), testRun(1, 1)[13:]...)
	run[2] = 2
	content, err := g.Allocation(run)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if n, err := content.ReadAt(buf, 4094); n != 4 || err != nil || !bytes.Equal(buf, []byte{3, 3, 1, 1}) {
		t.Fatal(buf, n, err)
	}
	for _, bad := range [][]byte{run[:len(run)-1], testRun(4, 1), testRun(3, 2)} {
		if _, err := g.Allocation(bad); err == nil {
			t.Fatal("bad allocation accepted")
		}
	}
	run[21] = 1
	if _, err := g.Allocation(run); err == nil {
		t.Fatal("unknown placement accepted")
	}
}
func TestIGWRejectsMapBounds(t *testing.T) {
	for _, page := range []uint64{2, 1000} {
		b := make([]byte, 8192)
		testVDF(b, page)
		if _, err := OpenIGW(raw(b)); err == nil {
			t.Fatal("outside map accepted")
		}
	}
	b := make([]byte, 8192)
	testVDF(b, 1)
	be.PutUint32(b[100:], 500)
	if _, err := OpenIGW(raw(b)); err == nil {
		t.Fatal("non-inline map accepted")
	}
}
