package os2

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func lxFixture() []byte {
	// MZ stub, one object spanning raw/iterated/EXEPACK2/zero pages,
	// and a resource which crosses the raw/iterated boundary.
	d := make([]byte, 0x500)
	copy(d, "MZ")
	binary.LittleEndian.PutUint32(d[60:], 0x80)
	h := d[0x80:]
	copy(h, "LX")
	put := func(o int, v uint32) { binary.LittleEndian.PutUint32(h[o:], v) }
	put(0x14, 4)
	put(0x28, 4096)
	put(0x40, 0xc0)
	put(0x44, 1)
	put(0x48, 0xe0)
	put(0x50, 0x110)
	put(0x54, 1)
	put(0x80, 0x400)
	put(0xc0, 4*4096)
	put(0xc4, 0x10000)
	put(0xc8, 3)
	put(0xcc, 1)
	put(0xd0, 4)
	pages := [][]byte{[]byte("raw"), {3, 0, 2, 0, 'a', 'b'}, {12, 'a', 'b', 'c', 0x32, 0, 0, 0}, nil}
	flags := []uint16{0, 1, 5, 3}
	off := 0
	for i, p := range pages {
		row := h[0xe0+i*8:]
		binary.LittleEndian.PutUint32(row, uint32(off))
		binary.LittleEndian.PutUint16(row[4:], uint16(len(p)))
		binary.LittleEndian.PutUint16(row[6:], flags[i])
		copy(d[0x400+off:], p)
		off += len(p)
	}
	r := h[0x110:]
	binary.LittleEndian.PutUint16(r, 9)
	binary.LittleEndian.PutUint16(r[2:], 42)
	binary.LittleEndian.PutUint32(r[4:], 5)
	binary.LittleEndian.PutUint16(r[8:], 1)
	binary.LittleEndian.PutUint32(r[10:], 4094)
	return d
}

func TestLXObjectsPagesAndCrossPageResource(t *testing.T) {
	img, err := DecodeLX(lxFixture(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(img.Objects) != 1 || len(img.Resources) != 1 {
		t.Fatalf("bad tables: %+v", img)
	}
	o := img.Objects[0]
	if o.Base != 0x10000 || o.Flags != 3 || len(o.Data) != 16384 {
		t.Fatalf("bad object metadata")
	}
	if string(o.Data[:3]) != "raw" || string(o.Data[4096:4102]) != "ababab" || string(o.Data[8192:8198]) != "abcabc" {
		t.Fatal("incorrect page expansion")
	}
	if !bytes.Equal(o.Data[12288:], make([]byte, 4096)) {
		t.Fatal("zero page not zero")
	}
	r := img.Resources[0]
	if r.Type != 9 || r.ID != 42 || !bytes.Equal(o.Data[r.Offset:r.Offset+r.Size], []byte{0, 0, 'a', 'b', 'a'}) {
		t.Fatal("incorrect cross-page resource")
	}
	// Header-only LX uses the same file-absolute data-page location.
	plain := append([]byte(nil), lxFixture()[0x80:]...)
	binary.LittleEndian.PutUint32(plain[0x80:], 0x380)
	if _, err := DecodeLX(plain, 1<<20); err != nil {
		t.Fatal(err)
	}
}

func TestLXMalformedTablesAndExpansionLimits(t *testing.T) {
	for _, change := range []func([]byte){
		func(d []byte) { d[0x82] = 1 },
		func(d []byte) { binary.LittleEndian.PutUint32(d[0xc4:], 0xffffffff) },  // object count
		func(d []byte) { binary.LittleEndian.PutUint32(d[0x14c:], 0) },          // object first page
		func(d []byte) { binary.LittleEndian.PutUint16(d[0x166:], 4) },          // unsupported range page
		func(d []byte) { binary.LittleEndian.PutUint16(d[0x198:], 2) },          // resource object
		func(d []byte) { binary.LittleEndian.PutUint32(d[0x19a:], 16384) },      // resource end
		func(d []byte) { binary.LittleEndian.PutUint32(d[0x160:], 0xffffffff) }, // page file offset
	} {
		d := lxFixture()
		change(d)
		if _, err := DecodeLX(d, 1<<20); err == nil {
			t.Fatal("accepted malformed LX")
		}
	}
	if _, err := DecodeLX(lxFixture(), 16383); err == nil {
		t.Fatal("ignored expansion bound")
	}
	for _, n := range []int{0, 2, 63, 128, 200, 300} {
		if _, err := DecodeLX(lxFixture()[:n], 1<<20); err == nil {
			t.Fatalf("accepted truncated input %d", n)
		}
	}
}

func TestLXPack2TagsOverlapsAndBounds(t *testing.T) {
	for _, tc := range []struct {
		src  []byte
		want string
	}{
		{[]byte{0, 4, 'x', 0, 0}, "xxxx"},
		{[]byte{0x85, 0, 'x'}, "xxxx"},        // tag1: one literal, distance1, length3
		{[]byte{4, 'x', 0x1e, 0}, "xxxxxxx"},  // tag2: overlapping length6
		{[]byte{0x07, 0x11, 0, 'x'}, "xxxxx"}, // tag3: one literal, distance1, length4
	} {
		got, err := expandLXPack2(tc.src, 64)
		if err != nil || string(got) != tc.want {
			t.Fatalf("%x -> %q (%v), want %q", tc.src, got, err, tc.want)
		}
	}
	for _, src := range [][]byte{{0}, {0, 1}, {4}, {1}, {2}, {3, 0}, {2, 0}, {0, 255, 'x'}, {0, 0, 1}} {
		if _, err := expandLXPack2(src, 64); err == nil {
			t.Fatalf("accepted invalid pack2 %x", src)
		}
	}
	if _, err := expandLXIterated([]byte{255, 255, 2, 0, 'a', 'b'}, 4096); err == nil {
		t.Fatal("iterated output overflow")
	}
}

func FuzzLX(f *testing.F) {
	f.Add(lxFixture())
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		_, _ = DecodeLX(data, 1<<20)
		_, _ = expandLXPack2(data, 4096)
		_, _ = expandLXIterated(data, 4096)
	})
}
