package berkeleydb

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func fixture(order binary.ByteOrder) []byte {
	b := make([]byte, 4*512)
	order.PutUint32(b, 0x53162)
	order.PutUint32(b[4:], 3)
	order.PutUint32(b[8:], 512)
	order.PutUint32(b[20:], 0x20)
	for page := 1; page <= 3; page++ {
		p := b[page*512 : (page+1)*512]
		order.PutUint32(p, uint32(page))
		order.PutUint32(p[12:], 2)
		order.PutUint16(p[16:], 22)
		order.PutUint16(p[18:], 496)
		order.PutUint16(p[20:], 496)
		order.PutUint32(p[496:], 1)
		order.PutUint32(p[500:], 1)
		p[505], p[506] = byte('a'+page-2), byte('A'+page-2)
	}
	root := b[512:1024]
	order.PutUint32(root[12:], 1)
	order.PutUint16(root[16:], 24)
	order.PutUint16(root[18:], 480)
	order.PutUint16(root[20:], 480)
	order.PutUint16(root[22:], 496)
	order.PutUint32(root[480:], 0)
	order.PutUint32(root[484:], 2)
	order.PutUint32(root[496:], 1)
	order.PutUint32(root[500:], 3)
	root[505] = 'b'
	order.PutUint32(b[1024+8:], 3)
	order.PutUint32(b[1536+4:], 2)
	return b
}

func TestTreeTraversalAndEndian(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		f, err := Open(bytes.NewReader(fixture(order)), 2)
		if err != nil {
			t.Fatal(err)
		}
		if f.PageSize != 512 || len(f.Entries) != 2 {
			t.Fatal(f)
		}
		for i, e := range f.Entries {
			var k, v [1]byte
			e.Key.ReadAt(k[:], 0)
			e.Value.ReadAt(v[:], 0)
			if k[0] != byte('a'+i) || v[0] != byte('A'+i) {
				t.Fatalf("entry %q %q", k, v)
			}
		}
	}
}

func TestMalformedTree(t *testing.T) {
	le := binary.LittleEndian
	cases := map[string]func([]byte){
		"page-cycle":     func(b []byte) { le.PutUint32(b[512+484:], 1) },
		"record-bound":   func(b []byte) { le.PutUint32(b[1024+496:], 0xfffffff0) },
		"record-overlap": func(b []byte) { le.PutUint16(b[512+22:], 480) },
		"overflow":       func(b []byte) { b[1024+504] = 1 },
		"leaf-link":      func(b []byte) { le.PutUint32(b[1536+4:], 0) },
		"wrong-page":     func(b []byte) { le.PutUint32(b[1024:], 3) },
		"record-number":  func(b []byte) { le.PutUint32(b[20:], 0x80) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			b := fixture(le)
			mutate(b)
			if _, err := Open(bytes.NewReader(b), 10); err == nil {
				t.Fatal("accepted malformed tree")
			}
		})
	}
	if _, err := Open(bytes.NewReader(fixture(le)), 1); err == nil {
		t.Fatal("ignored entry bound")
	}
}
