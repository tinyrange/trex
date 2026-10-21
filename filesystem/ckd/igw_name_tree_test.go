package ckd

import (
	"bytes"
	"testing"
)

func treeNamePage(level byte, names []string, values [][]byte) []byte {
	b := make([]byte, 4096)
	b[0], b[1], b[11], b[12], b[25], b[30] = 52, 1, 0xd5, 0xc4, 64, level
	pos := 121
	for i, name := range names {
		size := 5 + len(name) + len(values[i])
		be.PutUint16(b[pos:], uint16(size))
		b[pos+2], b[pos+4] = 0xc0, byte(64-len(name))
		copy(b[pos+5:], eb(name, len(name)))
		copy(b[pos+5+len(name):], values[i])
		pos += size
	}
	be.PutUint16(b[116:], uint16(pos-116))
	be.PutUint16(b[118:], uint16(pos-116))
	b[120] = byte(len(names))
	be.PutUint16(b[48:], uint16(3950-pos))
	be.PutUint16(b[50:], 3950)
	be.PutUint16(b[4094:], 0xa55a)
	return b
}

func TestNameTreeSparseActiveChildren(t *testing.T) {
	// Logical pages: root, hole, leaf. A stale physical leaf is deliberately
	// allocated but not reached. Compaction of the hole would misdirect child 2.
	b := make([]byte, 3*4096)
	root := treeNamePage(2, []string{"A"}, [][]byte{{0, 0, 0, 2}})
	leaf := treeNamePage(1, []string{"ALIAS", "MEMBER"}, [][]byte{{1}, {2}})
	copy(b, root)
	copy(b[4096:], leaf)
	copy(b[8192:], treeNamePage(1, []string{"STALE"}, [][]byte{{3}}))
	value := make([]byte, 13+3*10)
	value[0] = 1
	be.PutUint16(value[1:], 3)
	copy(value[13:], testRun(0, 1)[13:])
	copy(value[33:], testRun(1, 2)[13:])
	g := &IGW{source: raw(b)}
	if _, e := g.Allocation(value); e == nil {
		t.Fatal("unqualified hole accepted")
	}
	a, e := g.allocation(value, true)
	if e != nil {
		t.Fatal(e)
	}
	d := make([]byte, 64)
	d[0] = 1
	copy(d[1:20], root[2:21])
	got, e := readNameDirectory(a, d, 64, 10)
	if e != nil || len(got) != 2 || !bytes.Equal(got[1].Name[:6], eb("MEMBER", 6)) {
		t.Fatalf("%+v %v", got, e)
	}
	if _, e := readNameDirectory(a, d, 64, 1); e == nil {
		t.Fatal("limit ignored")
	}
	for _, tc := range []struct {
		name  string
		child uint32
	}{{"cycle", 0}, {"hole", 1}, {"outside", 99}} {
		t.Run(tc.name, func(t *testing.T) {
			bad := bytes.Clone(b)
			be.PutUint32(bad[127:], tc.child)
			gg := &IGW{source: raw(bad)}
			aa, e := gg.allocation(value, true)
			if e != nil {
				t.Fatal(e)
			}
			if _, e := readNameDirectory(aa, d, 64, 10); e == nil {
				t.Fatal("bad child accepted")
			}
		})
	}
}
