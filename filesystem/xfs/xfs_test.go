package xfs

import (
	"bytes"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func fixture() []byte {
	b := make([]byte, 32*512)
	be.PutUint32(b, 0x58465342)
	be.PutUint32(b[4:], 512)
	be.PutUint64(b[8:], 32)
	be.PutUint64(b[56:], 8)
	be.PutUint32(b[84:], 32)
	be.PutUint32(b[88:], 1)
	be.PutUint16(b[100:], 0x2004)
	be.PutUint16(b[104:], 256)
	b[120], b[122], b[123], b[124] = 9, 8, 1, 5
	root := b[8*256 : 9*256]
	be.PutUint16(root, 0x494e)
	be.PutUint16(root[2:], 0040755)
	root[4], root[5] = 1, 1
	data := []byte{1, 0, 0, 0, 0, 8, 1, 0, 48, 'a', 0, 0, 0, 9}
	be.PutUint64(root[56:], uint64(len(data)))
	copy(root[100:], data)
	file := b[9*256 : 10*256]
	be.PutUint16(file, 0x494e)
	be.PutUint16(file[2:], 0100644)
	file[4], file[5] = 1, 2
	be.PutUint64(file[56:], 515)
	be.PutUint32(file[76:], 1)
	// A sparse first block followed by three bytes from physical block ten.
	be.PutUint64(file[100:], 1<<9)
	be.PutUint64(file[108:], 10<<21|1)
	copy(b[10*512:], "abc")
	return b
}
func TestExtentAndShortDirectory(t *testing.T) {
	v, err := Open(&starfile.Bytes{Data: fixture()}, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Entries) != 2 || v.Entries[1].Path != "/a" {
		t.Fatalf("entries: %+v", v.Entries)
	}
	data, err := starfile.ReadAll(v.Entries[1].Data)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 515 || !bytes.Equal(data[:512], make([]byte, 512)) || string(data[512:]) != "abc" {
		t.Fatal("incorrect sparse extent")
	}
}
func TestRejectMalformed(t *testing.T) {
	for name, mutate := range map[string]func([]byte){
		"generation": func(b []byte) { b[101] = 5 },
		"geometry":   func(b []byte) { b[120] = 63 },
		"name":       func(b []byte) { b[8*256+109] = '/' },
		"fork":       func(b []byte) { b[9*256+82] = 255 },
		"extent":     func(b []byte) { be.PutUint64(b[9*256+108:], 32<<21|1) },
		"local size": func(b []byte) { be.PutUint64(b[8*256+56:], 1000) },
	} {
		t.Run(name, func(t *testing.T) {
			b := fixture()
			mutate(b)
			if _, err := Open(&starfile.Bytes{Data: b}, 100); err == nil {
				t.Fatal("accepted malformed input")
			}
		})
	}
	if _, err := Open(&starfile.Bytes{Data: fixture()}, 1); err == nil {
		t.Fatal("entry limit ignored")
	}
}
func TestBlockDirectory(t *testing.T) {
	b := make([]byte, 512)
	be.PutUint32(b, 0x58443242)
	be.PutUint64(b[16:], 9)
	b[24] = 1
	b[25] = 'a'
	be.PutUint16(b[30:], 16)
	be.PutUint16(b[32:], 0xffff)
	be.PutUint16(b[34:], 464)
	be.PutUint16(b[494:], 32)
	be.PutUint32(b[500:], 2)
	be.PutUint32(b[504:], 1)
	entries, err := blockDirectory(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].name != "a" || entries[0].inode != 9 {
		t.Fatal(entries)
	}
	b[495] = 33
	if _, err := blockDirectory(b); err == nil {
		t.Fatal("invalid tag accepted")
	}
}
