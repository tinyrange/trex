package xfs

import (
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func v1Leaf() []byte {
	b := make([]byte, 512)
	be.PutUint16(b[8:], 0xfeeb)
	be.PutUint16(b[12:], 1)
	be.PutUint16(b[14:], 1)
	be.PutUint32(b[32:], 'a')
	be.PutUint16(b[36:], 503)
	b[38] = 1
	be.PutUint64(b[503:], 9)
	b[511] = 'a'
	return b
}
func TestV1DirectoryForms(t *testing.T) {
	sf := make([]byte, 19)
	be.PutUint64(sf, 8)
	sf[8] = 1
	be.PutUint64(sf[9:], 9)
	sf[17] = 1
	sf[18] = 'a'
	entries, err := shortDirectoryV1(sf)
	if err != nil || len(entries) != 1 || entries[0].inode != 9 {
		t.Fatalf("shortform: %v %v", entries, err)
	}
	if _, err := shortDirectoryV1(sf[:18]); err == nil {
		t.Fatal("truncated shortform accepted")
	}
	block := v1Leaf()
	entries, err = leafDirectoryV1(block)
	if err != nil || len(entries) != 1 || entries[0].name != "a" {
		t.Fatalf("leaf: %v %v", entries, err)
	}
	b := make([]byte, 1024)
	be.PutUint16(b[8:], 0xfebe)
	be.PutUint16(b[12:], 1)
	be.PutUint16(b[14:], 1)
	be.PutUint32(b[16:], 'a')
	be.PutUint32(b[20:], 1)
	copy(b[512:], block)
	r := reader{block: 512}
	dir := Entry{Data: &starfile.Bytes{Data: b}}
	entries, err = r.directoryV1(dir, 10)
	if err != nil || len(entries) != 1 {
		t.Fatalf("tree: %v %v", entries, err)
	}
	be.PutUint32(b[20:], 0)
	if _, err := r.directoryV1(dir, 10); err == nil {
		t.Fatal("directory cycle accepted")
	}
}
func TestV1LeafValidation(t *testing.T) {
	for name, change := range map[string]func([]byte){
		"count":      func(b []byte) { be.PutUint16(b[12:], 65535) },
		"name bytes": func(b []byte) { be.PutUint16(b[14:], 2) },
		"name index": func(b []byte) { be.PutUint16(b[36:], 504) },
		"empty name": func(b []byte) { b[38] = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			b := v1Leaf()
			change(b)
			if _, err := leafDirectoryV1(b); err == nil {
				t.Fatal("accepted malformed leaf")
			}
		})
	}
}
func TestV1Volume(t *testing.T) {
	b := fixture()
	be.PutUint16(b[100:], 4)
	root := b[8*256 : 9*256]
	root[5] = 2
	be.PutUint64(root[56:], 512)
	be.PutUint32(root[76:], 1)
	clear(root[100:])
	be.PutUint64(root[108:], 11<<21|1)
	copy(b[11*512:], v1Leaf())
	volume, err := Open(&starfile.Bytes{Data: b}, 100)
	if err != nil || len(volume.Entries) != 2 {
		t.Fatalf("%v %v", volume, err)
	}
}
