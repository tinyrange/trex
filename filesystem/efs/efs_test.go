package efs

import (
	"bytes"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func put24(p []byte, n uint32) { p[0] = byte(n >> 16); p[1] = byte(n >> 8); p[2] = byte(n) }
func extent(p []byte, start, length, logical uint32) {
	put24(p[1:4], start)
	p[4] = byte(length)
	put24(p[5:8], logical)
}
func fixture() []byte {
	b := make([]byte, 64*512)
	sb := b[512:]
	be.PutUint32(sb, 64)
	be.PutUint32(sb[4:], 2)
	be.PutUint32(sb[8:], 62)
	be.PutUint16(sb[12:], 2)
	be.PutUint16(sb[18:], 1)
	be.PutUint32(sb[28:], 0x072959)
	inode := func(id uint32, mode uint16, size uint32, count uint16) []byte {
		p := b[2*512+id*128:]
		be.PutUint16(p, mode)
		be.PutUint32(p[8:], size)
		be.PutUint16(p[28:], count)
		return p
	}
	p := inode(2, 0040755, 512, 1)
	extent(p[32:], 4, 1, 0)
	p = inode(3, 0100644, 600, 2)
	extent(p[32:], 6, 1, 0)
	extent(p[40:], 8, 1, 1)
	copy(b[6*512:], bytes.Repeat([]byte{'a'}, 512))
	copy(b[8*512:], bytes.Repeat([]byte{'b'}, 88))
	p = inode(4, 0100755, 13*512, 13)
	extent(p[32:], 5, 1, 1)
	for i := 0; i < 13; i++ {
		extent(b[5*512+i*8:], uint32(20+i), 1, uint32(i))
		copy(b[(20+i)*512:], bytes.Repeat([]byte{byte(i)}, 512))
	}
	p = inode(5, 0120777, 4, 0)
	copy(p[32:], "file")
	dir := b[4*512 : 5*512]
	be.PutUint16(dir, 0xbeef)
	dir[3] = 5
	pos := 512
	for i, item := range []struct {
		name string
		id   uint32
	}{{".", 2}, {"..", 2}, {"file", 3}, {"large", 4}, {"link", 5}} {
		pos -= (5 + len(item.name) + 1) &^ 1
		dir[4+i] = byte(pos / 2)
		be.PutUint32(dir[pos:], item.id)
		dir[pos+4] = byte(len(item.name))
		copy(dir[pos+5:], item.name)
	}
	dir[2] = byte(pos / 2)
	return b
}
func TestReadExtentsAndSymlink(t *testing.T) {
	v, err := Open(&starfile.Bytes{Data: fixture()}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Entries) != 4 {
		t.Fatal(len(v.Entries))
	}
	want := [][]byte{nil, append(bytes.Repeat([]byte{'a'}, 512), bytes.Repeat([]byte{'b'}, 88)...), nil, []byte("file")}
	for i := 0; i < 13; i++ {
		want[2] = append(want[2], bytes.Repeat([]byte{byte(i)}, 512)...)
	}
	for i := 1; i < len(v.Entries); i++ {
		got, err := starfile.ReadAll(v.Entries[i].Data)
		if err != nil || !bytes.Equal(got, want[i]) {
			t.Fatalf("%s: size %d %v", v.Entries[i].Path, len(got), err)
		}
	}
	if v.Entries[3].Kind != "symlink" {
		t.Fatal("lost symlink")
	}
}
func TestRejectMalformed(t *testing.T) {
	for name, change := range map[string]func([]byte){
		"magic":     func(b []byte) { b[512+28] = 1 },
		"geometry":  func(b []byte) { be.PutUint16(b[512+12:], 0) },
		"directory": func(b []byte) { b[4*512] = 0 },
		"slot":      func(b []byte) { b[4*512+6] = 1 },
		"extent":    func(b []byte) { extent(b[2*512+3*128+32:], 63, 2, 0) },
		"overlap":   func(b []byte) { extent(b[2*512+3*128+40:], 8, 1, 0) },
		"indirect":  func(b []byte) { put24(b[2*512+4*128+37:], 13) },
	} {
		t.Run(name, func(t *testing.T) {
			b := fixture()
			change(b)
			if _, err := Open(&starfile.Bytes{Data: b}, 100); err == nil {
				t.Fatal("accepted malformed volume")
			}
		})
	}
	if _, err := Open(&starfile.Bytes{Data: fixture()}, 2); err == nil {
		t.Fatal("ignored entry limit")
	}
}

func TestTrimmedFreeTail(t *testing.T) {
	b := fixture()[:40*512]
	// The fixture's inode table occupies sector 2; place its explicit bitmap
	// in sector 10. Blocks 40..63 are omitted and marked free.
	be.PutUint32(b[512+44:], 8)
	be.PutUint32(b[512+56:], 10)
	copy(b[10*512+5:], []byte{0xff, 0xff, 0xff})
	v, err := Open(&starfile.Bytes{Data: b}, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range v.Entries {
		if _, err := starfile.ReadAll(e.Data); err != nil {
			t.Fatal(err)
		}
	}
	b[10*512+6] = 0xfe
	if _, err := Open(&starfile.Bytes{Data: b}, 100); err == nil {
		t.Fatal("accepted omitted allocated blocks")
	}
	b[10*512+6] = 0xff
	extent(b[2*512+3*128+32:], 42, 1, 0)
	if _, err := Open(&starfile.Bytes{Data: b}, 100); err == nil {
		t.Fatal("accepted file extent outside input despite free bitmap claim")
	}
}

func TestTrimmedPartialBitmapBytes(t *testing.T) {
	b := fixture()[:37*512]
	be.PutUint32(b[512:], 61)
	be.PutUint32(b[512+44:], 8)
	be.PutUint32(b[512+56:], 10)
	// Omitted blocks 37..60 are free; present 32..36 and out-of-geometry
	// bits 61..63 are zero. Both boundary masks must be applied correctly.
	copy(b[10*512+4:], []byte{0xe0, 0xff, 0xff, 0x1f})
	if _, err := Open(&starfile.Bytes{Data: b}, 100); err != nil {
		t.Fatal(err)
	}
	b[10*512+4] = 0xc0
	if _, err := Open(&starfile.Bytes{Data: b}, 100); err == nil {
		t.Fatal("accepted missing allocated first boundary block")
	}
}
