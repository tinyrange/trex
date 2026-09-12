package macresource

import (
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func sample() []byte {
	b := make([]byte, 600)
	be := binary.BigEndian
	be.PutUint32(b, 256)
	be.PutUint32(b[4:], 512)
	be.PutUint32(b[8:], 11)
	be.PutUint32(b[12:], 88)
	be.PutUint32(b[256:], 3)
	copy(b[260:], "abc")
	be.PutUint32(b[263:], 0)
	m := b[512:]
	be.PutUint16(m[24:], 28)
	be.PutUint16(m[26:], 70)
	be.PutUint16(m[28:], 0)
	copy(m[30:], "TEST")
	be.PutUint16(m[34:], 1)
	be.PutUint16(m[36:], 10)
	// Negative ID with an empty name, followed by an unnamed zero-length item.
	be.PutUint16(m[38:], 65534)
	be.PutUint16(m[40:], 0)
	be.PutUint16(m[50:], 128)
	be.PutUint16(m[52:], 65535)
	m[57] = 7
	return b
}
func TestOpen(t *testing.T) {
	f, err := Open(&starfile.Bytes{Data: sample()}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Entries) != 2 || f.Entries[0].ID != -2 || f.Entries[0].Name == nil || len(f.Entries[0].Name) != 0 || f.Entries[1].Name != nil {
		t.Fatalf("entries: %+v", f.Entries)
	}
	b, err := starfile.ReadAll(f.Entries[0].Data)
	if err != nil || string(b) != "abc" {
		t.Fatalf("%q %v", b, err)
	}
	if f.Entries[1].Data.Size() != 0 {
		t.Fatal("nonempty second resource")
	}
}
func TestMalformed(t *testing.T) {
	be := binary.BigEndian
	for name, change := range map[string]func([]byte){
		"map outside":          func(b []byte) { be.PutUint32(b[4:], 590) },
		"overlapping sections": func(b []byte) { be.PutUint32(b[8:], 300) },
		"type count":           func(b []byte) { be.PutUint16(b[540:], 500) },
		"reference list":       func(b []byte) { be.PutUint16(b[548:], 0) },
		"name":                 func(b []byte) { be.PutUint16(b[552:], 65534) },
		"data length":          func(b []byte) { be.PutUint32(b[256:], 1000) },
		"data offset":          func(b []byte) { b[557] = 255 },
		"compression": func(b []byte) {
			b[554] = 1
			be.PutUint16(b[546:], 0)
			be.PutUint32(b[256:], 4)
			be.PutUint32(b[260:], 0xa89f6572)
		},
		"overlapping payloads": func(b []byte) { b[569] = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			b := sample()
			change(b)
			if _, err := Open(&starfile.Bytes{Data: b}, 1000); err == nil {
				t.Fatal("accepted malformed resource")
			}
		})
	}
	if _, err := Open(&starfile.Bytes{Data: sample()}, 1); err == nil {
		t.Fatal("limit ignored")
	}
}

func TestCompressionRequiresMarker(t *testing.T) {
	for _, size := range []uint32{0, 3, 7} {
		b := sample()
		binary.BigEndian.PutUint16(b[546:], 0)
		binary.BigEndian.PutUint32(b[256:], size)
		copy(b[260:], "plain!!")
		b[554] = 1
		f, err := Open(&starfile.Bytes{Data: b}, 10)
		if err != nil {
			t.Fatal(err)
		}
		e := f.Entries[0]
		got, err := starfile.ReadAll(e.Data)
		if err != nil || string(got) != "plain!!"[:size] || e.Compressed || e.Attributes != 1 {
			t.Fatalf("%q %+v %v", got, e, err)
		}
	}
}

func TestDuplicateIDsPreserveRecords(t *testing.T) {
	b := sample()
	binary.BigEndian.PutUint16(b[562:], 65534)
	f, err := Open(&starfile.Bytes{Data: b}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !f.DuplicateIDs || len(f.Entries) != 2 || f.Entries[0].Occurrence != 1 || f.Entries[1].Occurrence != 2 || f.Entries[0].Data.Size() != 3 || f.Entries[1].Data.Size() != 0 {
		t.Fatalf("lost duplicate records: %+v", f)
	}
}
func TestEmptyMap(t *testing.T) {
	b := sample()
	binary.BigEndian.PutUint16(b[540:], 65535)
	f, err := Open(&starfile.Bytes{Data: b}, 1)
	if err != nil || len(f.Entries) != 0 {
		t.Fatalf("%+v %v", f, err)
	}
}
