package ckd

import "testing"

func indexFixture(level byte, pointers []uint32, keys []string) []byte {
	b := make([]byte, 512)
	ll := 505
	width := 5
	be.PutUint16(b, uint16(ll))
	b[2], b[3], b[16] = byte(width), 7, level
	be.PutUint16(b[18:], 24)
	pos := ll - width
	for i, p := range pointers {
		key := keys[i]
		b[pos+1] = byte(len(key))
		b[pos+2], b[pos+3], b[pos+4] = byte(p>>16), byte(p>>8), byte(p)
		copy(b[pos-len(key):], key)
		if i == len(pointers)-1 {
			be.PutUint16(b[20:], uint16(pos))
			be.PutUint16(b[22:], uint16(pos))
			be.PutUint16(b[pos-len(key)-2:], 0)
		}
		pos -= width + len(key)
	}
	be.PutUint16(b[506:], uint16(ll))
	be.PutUint16(b[508:], uint16(ll))
	return b
}
func TestVSAMIndexTraversal(t *testing.T) {
	root := indexFixture(2, []uint32{1, 2}, []string{"M", "Z"})
	a := indexFixture(1, []uint32{1, 0}, []string{"A", "M"})
	z := indexFixture(1, []uint32{2}, []string{"Z"})
	b := append(append(root, a...), z...)
	ids, e := VSAMIndexOrder(raw(b), 512, 1536, 0, 512, 1536, 4, 20)
	if e != nil || len(ids) != 3 || ids[0] != 1 || ids[1] != 0 || ids[2] != 2 {
		t.Fatal(ids, e)
	}
	for _, tc := range []struct {
		name  string
		off   int
		value byte
	}{
		{"cycle", 504, 0}, {"bad level", 512 + 16, 2}, {"bad compression", 512 + 500, 255},
		{"bad section", 512 + 23, 255}, {"free array overlap", 512 + 18, 255},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := append([]byte(nil), b...)
			bad[tc.off] = tc.value
			if _, e := VSAMIndexOrder(raw(bad), 512, 1536, 0, 512, 1536, 4, 20); e == nil {
				t.Fatal("accepted malformed index")
			}
		})
	}
}
func TestVSAMIndexSectionPrefix(t *testing.T) {
	b := indexFixture(1, []uint32{3, 1, 2}, []string{"AB", "AC", "AD"})
	// A non-section-high compressed key refers to its predecessor.
	copy(b[483:492], b[482:491])
	b[493], b[494], b[492] = 1, 1, 'C'
	be.PutUint16(b[20:], 487)
	be.PutUint16(b[22:], 487)
	rec, e := ParseVSAMIndex(b, 4)
	if e != nil || len(rec.Entries) != 3 || string(rec.Entries[1].HighKey[:2]) != "AC" {
		t.Fatal(rec, e)
	}
}
