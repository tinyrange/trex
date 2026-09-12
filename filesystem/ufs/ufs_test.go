package ufs

import (
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func fixture(order binary.ByteOrder) []byte {
	b := make([]byte, 256*512)
	sb := b[8192:]
	for offset, value := range map[int]uint32{16: 32, 36: 256, 44: 1, 48: 4096, 52: 512, 56: 8, 116: 1024, 120: 32, 184: 32, 188: 256, 1372: 0x11954} {
		order.PutUint32(sb[offset:], value)
	}
	root := b[32*512+2*128:]
	order.PutUint16(root, 0x41ed)
	order.PutUint16(root[2:], 2)
	order.PutUint64(root[8:], 512)
	order.PutUint32(root[40:], 48)
	file := b[32*512+3*128:]
	order.PutUint16(file, 0x81a4)
	order.PutUint16(file[2:], 1)
	order.PutUint16(file[4:], 42)
	order.PutUint16(file[6:], 17)
	order.PutUint64(file[8:], 3)
	order.PutUint32(file[40:], 56)
	dir := b[48*512:]
	for _, e := range []struct {
		off, size int
		ino       uint32
		name      string
	}{{0, 12, 2, "."}, {12, 12, 2, ".."}, {24, 488, 3, "file"}} {
		order.PutUint32(dir[e.off:], e.ino)
		order.PutUint16(dir[e.off+4:], uint16(e.size))
		order.PutUint16(dir[e.off+6:], uint16(len(e.name)))
		copy(dir[e.off+8:], e.name)
	}
	copy(b[56*512:], "abc")
	return b
}
func TestReadHistoricalUFS(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		b := fixture(order)
		v, err := Open(&starfile.Bytes{Data: b}, 10, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(v.Entries) != 2 || v.Entries[1].Path != "/file" || v.Entries[1].UID != 42 || v.Entries[1].GID != 17 {
			t.Fatal(v)
		}
		got, err := starfile.ReadAll(v.Entries[1].Data)
		if err != nil || string(got) != "abc" {
			t.Fatal(string(got), err)
		}
	}
}
func TestSparseAndIndirection(t *testing.T) {
	for depth := 1; depth <= 3; depth++ {
		b := fixture(binary.LittleEndian)
		raw := b[32*512+3*128:]
		clear(raw[40:100])
		blocks := uint64(12)
		capacity := uint64(1024)
		for i := 1; i < depth; i++ {
			blocks += capacity
			capacity *= 1024
		}
		binary.LittleEndian.PutUint64(raw[8:], blocks*4096+3)
		binary.LittleEndian.PutUint32(raw[88+(depth-1)*4:], 64)
		for level := 0; level < depth; level++ {
			binary.LittleEndian.PutUint32(b[(64+level*8)*512:], uint32(64+(level+1)*8))
		}
		copy(b[(64+depth*8)*512:], "xyz")
		v, err := Open(&starfile.Bytes{Data: b}, 10, 100)
		if err != nil {
			t.Fatal(depth, err)
		}
		var got [3]byte
		if _, err := starfile.ReadFullAt(v.Entries[1].Data, got[:], int64(blocks*4096)); err != nil || string(got[:]) != "xyz" {
			t.Fatal(depth, got, err)
		}
		if _, err := starfile.ReadFullAt(v.Entries[1].Data, got[:], 0); err != nil || got != [3]byte{} {
			t.Fatal("hole", depth, got, err)
		}
	}
}
func TestMalformed(t *testing.T) {
	for _, mutate := range []func([]byte){
		func(b []byte) { binary.LittleEndian.PutUint32(b[8192+48:], 123) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[32*512+3*128+40:], 999999) },
		func(b []byte) { binary.LittleEndian.PutUint16(b[48*512+4:], 0) },
		func(b []byte) { binary.LittleEndian.PutUint16(b[48*512+6:], 255) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[48*512+24:], 2) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[48*512+12:], 3) },
	} {
		b := fixture(binary.LittleEndian)
		mutate(b)
		if _, err := Open(&starfile.Bytes{Data: b}, 10, 100); err == nil {
			t.Fatal("accepted malformed fixture")
		}
	}
	b := fixture(binary.LittleEndian)
	if _, err := Open(&starfile.Bytes{Data: b}, 1, 100); err == nil {
		t.Fatal("entry limit")
	}
	if _, err := Open(&starfile.Bytes{Data: b}, 10, 1); err == nil {
		t.Fatal("mapping limit")
	}
}

func TestCylinderGroupOffset(t *testing.T) {
	b := append(fixture(binary.LittleEndian), make([]byte, 256*512)...)
	binary.LittleEndian.PutUint32(b[8192+36:], 512)
	binary.LittleEndian.PutUint32(b[8192+44:], 2)
	binary.LittleEndian.PutUint32(b[8192+24:], 8)
	binary.LittleEndian.PutUint32(b[8192+28:], 0xfffffffe)
	copy(b[(256+8+32)*512:], b[32*512+3*128:32*512+4*128])
	binary.LittleEndian.PutUint32(b[48*512+24:], 32)
	v, err := Open(&starfile.Bytes{Data: b}, 10, 100)
	if err != nil {
		t.Fatal(err)
	}
	got, err := starfile.ReadAll(v.Entries[1].Data)
	if err != nil || string(got) != "abc" || v.Entries[1].Inode != 32 {
		t.Fatal(v, err)
	}
}

func TestHardLinkIdentity(t *testing.T) {
	b := fixture(binary.LittleEndian)
	dir := b[48*512:]
	binary.LittleEndian.PutUint16(dir[28:], 16)
	binary.LittleEndian.PutUint32(dir[40:], 3)
	binary.LittleEndian.PutUint16(dir[44:], 472)
	binary.LittleEndian.PutUint16(dir[46:], 5)
	copy(dir[48:], "alias")
	binary.LittleEndian.PutUint16(b[32*512+3*128+2:], 2)
	v, err := Open(&starfile.Bytes{Data: b}, 10, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Entries) != 3 || v.Entries[1].Inode != v.Entries[2].Inode || v.Entries[1].Data != v.Entries[2].Data || v.Entries[2].Links != 2 {
		t.Fatal("hard link lost")
	}
}

func FuzzHistoricalUFS(f *testing.F) {
	f.Add(fixture(binary.LittleEndian))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 256*1024 {
			return
		}
		v, err := Open(&starfile.Bytes{Data: b}, 100, 1000)
		if err == nil && len(v.Entries) > 100 {
			t.Fatal("entry bound")
		}
	})
}
