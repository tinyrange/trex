package sgi

import (
	"encoding/binary"
	"github.com/tinyrange/trex/auto"
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
	node, err := auto.Open(&starfile.Bytes{Data: b}, "", auto.Options{}).Resolve("boot/sash")
	if err != nil || node.Reader().Size() != 3 {
		t.Fatal(node, err)
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

func TestBuildDisk(t *testing.T) {
	first := &starfile.Bytes{Data: make([]byte, 512)}
	second := &starfile.Bytes{Data: make([]byte, 1024)}
	first.Data[18], second.Data[19] = 42, 99
	parts := []DiskPartition{{1, 3, first}, {0, 7, second}}
	image, err := Build(parts, 0, 1, "unix.IP12", 64)
	if err != nil {
		t.Fatal(err)
	}
	header, err := Open(image)
	if err != nil {
		t.Fatal(err)
	}
	want := [][4]uint32{{0, 7, 65, 2}, {1, 3, 64, 1}, {8, 0, 0, 64}, {10, 6, 0, 67}}
	if len(header.Partitions) != len(want) {
		t.Fatalf("partition count = %d", len(header.Partitions))
	}
	for i, p := range header.Partitions {
		if got := [4]uint32{uint32(p.Index), p.Type, p.Start, p.Blocks}; got != want[i] {
			t.Fatalf("partition %d = %v, want %v", i, got, want[i])
		}
	}
	var b [1]byte
	if _, err := header.Partitions[1].Data.ReadAt(b[:], 18); err != nil || b[0] != 42 {
		t.Fatalf("partition payload = %v, %v", b, err)
	}
	if _, err := image.ReadAt(b[:], 512); err != nil || b[0] != 0 {
		t.Fatalf("volume header padding = %v, %v", b, err)
	}
	if _, err := Build(append(parts, parts[0]), 0, 1, "", 64); err == nil {
		t.Fatal("duplicate partition accepted")
	}
}

func TestBuildVolumeHeaderFiles(t *testing.T) {
	parts := []DiskPartition{{0, 10, &starfile.Bytes{Data: make([]byte, 512)}}}
	sash := BootFile{Name: "sash", Data: &starfile.Bytes{Data: []byte("stock boot program")}}
	ide := BootFile{Name: "ide", Data: &starfile.Bytes{Data: []byte("stock diagnostics")}}
	img, err := Build(parts, 0, 0, "unix", 3, sash, ide)
	if err != nil {
		t.Fatal(err)
	}
	header, err := Open(img)
	if err != nil {
		t.Fatal(err)
	}
	if len(header.Files) != 2 || header.Files[0].Name != "sash" || header.Files[1].Name != "ide" {
		t.Fatalf("volume files %+v", header.Files)
	}
	data, err := starfile.ReadAll(header.Files[0].Data)
	if err != nil || string(data) != "stock boot program" {
		t.Fatalf("sash contents %q, %v", data, err)
	}
	if _, err := Build(parts, 0, 0, "unix", 2, sash, ide); err == nil {
		t.Fatal("accepted a boot program beyond the header partition")
	}
	if _, err := Build(parts, 0, 0, "unix", 3, sash, sash); err == nil {
		t.Fatal("accepted a duplicate volume-header name")
	}
}
