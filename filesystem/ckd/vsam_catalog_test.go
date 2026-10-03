package ckd

import "testing"

func vvrFixture() []byte {
	// Three independent counted names, plus uninterpreted primary header tail.
	h := []byte{0, 0, 0, 0, 0xe9, 0x20, 0, 0, 0, 0, 5}
	h = append(h, eb("DATA", 4)...)
	h = append(h, 0, 8)
	h = append(h, eb("CLUSTER", 7)...)
	h = append(h, 0, 3)
	h = append(h, eb("CAT", 3)...)
	be.PutUint16(h[2:], uint16(len(h)-2))
	common := make([]byte, 85)
	be.PutUint16(common, 85)
	common[2] = 0x21
	component := make([]byte, 98)
	be.PutUint16(component, 98)
	component[2], component[3] = 0x60, 0x80
	be.PutUint16(component[8:], 9)
	be.PutUint16(component[10:], 45)
	volume := make([]byte, 62)
	be.PutUint16(volume, 62)
	volume[2] = 0x23
	be.PutUint32(volume[9:], 737280)
	be.PutUint32(volume[13:], 7372800)
	be.PutUint32(volume[17:], 4096)
	be.PutUint16(volume[21:], 12)
	be.PutUint16(volume[23:], 15)
	out := append(append(append(h, common...), component...), volume...)
	be.PutUint16(out, uint16(len(out)))
	return out
}
func TestVVRGeometryAndBounds(t *testing.T) {
	b := vvrFixture()
	v, e := ParseVVR(b)
	if e != nil || v.Name != "DATA" || v.Cluster != "CLUSTER" || v.Catalog != "CAT" || v.CIBytes != 4096 || v.UsedBytes != 737280 || v.KeyOffset != 9 || v.KeyLength != 45 || v.Index {
		t.Fatal(v, e)
	}
	for _, at := range []int{0, 2, 4, 10, len(b) - 62 + 17, len(b) - 62 + 9} {
		bad := append([]byte(nil), b...)
		bad[at] = 255
		if _, e := ParseVVR(bad); e == nil {
			t.Fatal("bad VVR accepted", at)
		}
	}
}
func TestCatalogNestedComponents(t *testing.T) {
	b := make([]byte, 54)
	be.PutUint16(b[2:], 52)
	b[4], b[8] = 0xc3, 45
	copy(b[9:53], eb("CLUSTER", 44))
	c := make([]byte, 12)
	be.PutUint16(c, 12)
	c[2] = 0xc4
	be.PutUint16(c[3:], 17)
	be.PutUint16(c[5:], 5)
	copy(c[7:], eb("DATA", 4))
	b = append(b, c...)
	b = append(b, 0, 5, 4, 0, 0)
	be.PutUint16(b, uint16(len(b)))
	r, e := ParseCatalogRecord(b)
	if e != nil || r.Name != "CLUSTER" || len(r.Cells) != 1 || r.Cells[0].Name != "DATA" || len(r.Cells[0].Children) != 1 {
		t.Fatal(r, e)
	}
	for _, at := range []int{0, 2, 8, 55, 58, 60, 65, 67} {
		bad := append([]byte(nil), b...)
		bad[at] = 255
		if _, e := ParseCatalogRecord(bad); e == nil {
			t.Fatal("bad BCS accepted", at)
		}
	}
}

func TestVVRIndexIdentityAndRoot(t *testing.T) {
	b := vvrFixture()
	b[5] |= 8
	start := int(be.Uint16(b[2:])) + 2
	component := start + 85
	b[component+3] = 0
	be.PutUint32(b[component+30:], 8192)
	v, err := ParseVVR(b)
	if err != nil || !v.Index || v.IndexRootRBA != 8192 {
		t.Fatal(v, err)
	}
	// The low bit of the common cell is not the component-type flag.
	b[5] &= ^byte(8)
	b[start+3] |= 1
	v, err = ParseVVR(b)
	if err != nil || v.Index || v.IndexRootRBA != 0 {
		t.Fatal(v, err)
	}
}
