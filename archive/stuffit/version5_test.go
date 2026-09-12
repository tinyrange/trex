package stuffit

import (
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func seal5(b []byte, at int) { b[at], b[at+1] = 0, 0; binary.BigEndian.PutUint16(b[at:], crc16(b)) }
func fixture5() []byte {
	be := binary.BigEndian
	b := make([]byte, 247)
	copy(b, "StuffIt ")
	b[80] = 0x1a
	b[82] = 5
	be.PutUint32(b[84:], uint32(len(b)))
	be.PutUint32(b[88:], 114)
	be.PutUint16(b[92:], 1)
	be.PutUint32(b[94:], 114)
	seal5(b[:114], 98)
	h := b[114:163]
	be.PutUint32(h, 0xa5a5a5a5)
	h[4] = 1
	be.PutUint16(h[6:], 49)
	be.PutUint16(h[8:], 64)
	be.PutUint16(h[30:], 1)
	be.PutUint32(h[34:], 199)
	h[48] = 'd'
	seal5(h, 32)
	seal5(b[163:199], 2)
	h = b[199:]
	be.PutUint32(h, 0xa5a5a5a5)
	h[4] = 1
	be.PutUint16(h[6:], 48)
	be.PutUint16(h[8:], 64)
	be.PutUint32(h[18:], 114)
	be.PutUint32(h[26:], 114)
	be.PutUint32(h[34:], 0xffffffff)
	seal5(h, 32)
	return b
}
func TestVersion5Directory(t *testing.T) {
	a, err := Open(&starfile.Bytes{Data: fixture5()}, 10, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if a.Version != 5 || len(a.Entries) != 1 || a.Entries[0].Path != "/d" || !a.Entries[0].Directory || !a.RootCountVerified {
		t.Fatal(a)
	}
}
func TestVersion5Reject(t *testing.T) {
	for _, offset := range []int{98, 114 + 32, 163 + 2, 199 + 32} {
		b := fixture5()
		b[offset] ^= 1
		if _, err := Open(&starfile.Bytes{Data: b}, 10, 1024); err == nil {
			t.Fatal("accepted CRC", offset)
		}
	}
	b := fixture5()
	binary.BigEndian.PutUint32(b[199+26:], 0)
	seal5(b[199:], 32)
	if _, err := Open(&starfile.Bytes{Data: b}, 10, 1024); err == nil {
		t.Fatal("accepted parent")
	}
	b = fixture5()
	binary.BigEndian.PutUint16(b[114+46:], 1)
	seal5(b[114:163], 32)
	if _, err := Open(&starfile.Bytes{Data: b}, 10, 1024); err == nil {
		t.Fatal("accepted child count")
	}
}

func FuzzVersion5(f *testing.F) {
	f.Add(fixture5())
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		_, _ = Open(&starfile.Bytes{Data: data}, 100, 1<<20)
	})
}
