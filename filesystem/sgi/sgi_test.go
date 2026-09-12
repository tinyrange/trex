package sgi

import (
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func TestHeader(t *testing.T) {
	b := make([]byte, 4096)
	be := binary.BigEndian
	be.PutUint32(b, 0x0be5a941)
	be.PutUint32(b[312:], 7)
	be.PutUint32(b[316:], 1)
	be.PutUint32(b[320:], 5)
	copy(b[72:], "sash")
	be.PutUint32(b[80:], 2)
	be.PutUint32(b[84:], 3)
	copy(b[1024:], "abc")
	var sum uint32
	for i := 0; i < 512; i += 4 {
		sum += be.Uint32(b[i:])
	}
	be.PutUint32(b[504:], 0-sum)
	h, err := Open(&starfile.Bytes{Data: b})
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Partitions) != 1 || h.Partitions[0].Start != 1 || h.Partitions[0].Data.Size() != 3584 {
		t.Fatalf("%+v", h.Partitions)
	}
	data, err := starfile.ReadAll(h.Files[0].Data)
	if err != nil || string(data) != "abc" {
		t.Fatalf("%q %v", data, err)
	}
	b[6] ^= 1
	if _, err := Open(&starfile.Bytes{Data: b}); err == nil {
		t.Fatal("accepted checksum corruption")
	}
}

func TestWholeVolumeBeyondCDImage(t *testing.T) {
	b := make([]byte, 4096)
	be := binary.BigEndian
	be.PutUint32(b, 0x0be5a941)
	be.PutUint32(b[312+10*12:], 24)
	be.PutUint32(b[320+10*12:], 6)
	fixChecksum := func() {
		be.PutUint32(b[504:], 0)
		var sum uint32
		for i := 0; i < 512; i += 4 {
			sum += be.Uint32(b[i:])
		}
		be.PutUint32(b[504:], -sum)
	}
	fixChecksum()
	h, err := Open(&starfile.Bytes{Data: b})
	if err != nil || len(h.Partitions) != 1 {
		t.Fatalf("%v %v", h, err)
	}
	p := h.Partitions[0]
	if p.Complete || p.Blocks != 24 || p.Data.Size() != 4096 {
		t.Fatal("lost declared or available range")
	}
	be.PutUint32(b[320+10*12:], 5)
	fixChecksum()
	if _, err := Open(&starfile.Bytes{Data: b}); err == nil {
		t.Fatal("accepted truncated filesystem partition")
	}
}
