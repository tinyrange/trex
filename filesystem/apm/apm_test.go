package apm

import (
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func fixture(block int) []byte {
	b := make([]byte, 16*block)
	copy(b, "ER")
	binary.BigEndian.PutUint16(b[2:], 2048)
	for i, kind := range []string{"Apple_partition_map", "Apple_HFS", "Apple_Free"} {
		p := b[(i+1)*block:]
		copy(p, "PM")
		binary.BigEndian.PutUint32(p[4:], 3)
		start, size := uint32(1), uint32(3)
		if i == 1 {
			start, size = 4, 4
		}
		if i == 2 {
			start, size = 8, 40
		}
		binary.BigEndian.PutUint32(p[8:], start)
		binary.BigEndian.PutUint32(p[12:], size)
		copy(p[16:], "name")
		copy(p[48:], kind)
	}
	copy(b[4*block:], "data")
	return b
}
func TestLogicalViews(t *testing.T) {
	for _, block := range []int{512, 1024, 2048} {
		m, err := Open(&starfile.Bytes{Data: fixture(block)}, block, 3)
		if err != nil {
			t.Fatal(err)
		}
		if m.DeviceBlockSize != 2048 || len(m.Partitions) != 3 || m.Partitions[2].Data != nil {
			t.Fatal("geometry/free-space metadata lost")
		}
		got := make([]byte, 4)
		if _, err := m.Partitions[1].Data.ReadAt(got, 0); err != nil || string(got) != "data" {
			t.Fatalf("%q %v", got, err)
		}
	}
}
func TestRejectsMalformed(t *testing.T) {
	for _, mutate := range []func([]byte) []byte{
		func(b []byte) []byte { return b[:600] },
		func(b []byte) []byte { b[0] = 0; return b },
		func(b []byte) []byte { b[1024] = 0; return b },
		func(b []byte) []byte { binary.BigEndian.PutUint32(b[1028:], 4); return b },
		func(b []byte) []byte { binary.BigEndian.PutUint32(b[1032:], 2); return b },
		func(b []byte) []byte { binary.BigEndian.PutUint32(b[1036:], 100); return b },
	} {
		if _, err := Open(&starfile.Bytes{Data: mutate(fixture(512))}, 512, 10); err == nil {
			t.Fatal("accepted malformed map")
		}
	}
	if _, err := Open(&starfile.Bytes{Data: fixture(512)}, 4096, 10); err == nil {
		t.Fatal("invalid sector size")
	}
	if _, err := Open(&starfile.Bytes{Data: fixture(512)}, 512, 2); err == nil {
		t.Fatal("ignored entry limit")
	}
}

func cdFixture() []byte {
	b := fixture(512)
	// The 512-byte map occupies blocks1..3. The CD driver starts at
	// device block1 (byte2048), not at byte512 inside the map itself.
	binary.BigEndian.PutUint16(b[16:], 1)
	binary.BigEndian.PutUint32(b[18:], 1)
	p := b[1024:1536]
	clear(p[48:80])
	copy(p[48:], "Apple_Driver43_CD")
	copy(p[136:], "CDvr")
	binary.BigEndian.PutUint32(p[8:], 1)
	binary.BigEndian.PutUint32(p[12:], 1)
	return b
}

func TestMixedCDDriverGeometry(t *testing.T) {
	m, err := Open(&starfile.Bytes{Data: cdFixture()}, 512, 3)
	if err != nil {
		t.Fatal(err)
	}
	p := m.Partitions[1]
	if p.Start != 1 || p.Blocks != 1 || p.BlockSize != 2048 || p.Data.Size() != 2048 || m.Partitions[0].BlockSize != 512 {
		t.Fatal("raw or effective geometry lost")
	}
	got := make([]byte, 4)
	if _, err := p.Data.ReadAt(got, 0); err != nil || string(got) != "data" {
		t.Fatalf("wrong driver view: %q %v", got, err)
	}
	for _, mutate := range []func([]byte){
		func(b []byte) { b[1024+136] = 0 }, // Type alone must not change units.
		func(b []byte) { binary.BigEndian.PutUint16(b[16:], 0) },
		func(b []byte) { binary.BigEndian.PutUint32(b[18:], 2) },
		func(b []byte) { binary.BigEndian.PutUint16(b[2:], 512) },
		func(b []byte) { binary.BigEndian.PutUint32(b[1024+12:], 100) },
		func(b []byte) { binary.BigEndian.PutUint32(b[512+12:], 5) }, // True overlap.
		func(b []byte) { binary.BigEndian.PutUint16(b[16:], 62) },
	} {
		b := cdFixture()
		mutate(b)
		if _, err := Open(&starfile.Bytes{Data: b}, 512, 3); err == nil {
			t.Fatal("accepted malformed mixed geometry")
		}
	}
}
func FuzzMap(f *testing.F) {
	f.Add(fixture(512))
	f.Add(cdFixture())
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := Open(&starfile.Bytes{Data: b}, 512, 32)
		if err != nil {
			return
		}
		for _, p := range m.Partitions {
			if p.Data != nil && p.Data.Size() > int64(len(b)) {
				t.Fatal("unbounded partition")
			}
		}
	})
}
