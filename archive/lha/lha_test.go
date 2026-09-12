package lha

import (
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func archiveFixture() []byte {
	name := []byte("folder\\file")
	h := make([]byte, 24+len(name))
	h[0] = byte(len(h) - 2)
	copy(h[2:], "-lh0-")
	binary.LittleEndian.PutUint32(h[7:], 3)
	binary.LittleEndian.PutUint32(h[11:], 3)
	h[21] = byte(len(name))
	copy(h[22:], name)
	binary.LittleEndian.PutUint16(h[22+len(name):], crc16([]byte("abc")))
	for _, v := range h[2:] {
		h[1] += v
	}
	return append(h, 'a', 'b', 'c', 0)
}
func TestArchive(t *testing.T) {
	b := archiveFixture()
	a, err := Open(&starfile.Bytes{Data: b}, 10, 100)
	if err != nil || len(a.Entries) != 1 {
		t.Fatal(a, err)
	}
	got, err := starfile.ReadAll(a.Entries[0].Data)
	if err != nil || string(got) != "abc" || a.Entries[0].Path != "/folder/file" {
		t.Fatal(a, err)
	}
	for _, off := range []int{1, len(b) - 2} {
		bad := append([]byte(nil), b...)
		bad[off] ^= 1
		if _, err := Open(&starfile.Bytes{Data: bad}, 10, 100); err == nil {
			t.Fatal("accepted corrupt header/payload", off)
		}
	}
	if _, err := Open(&starfile.Bytes{Data: b[:len(b)-1]}, 10, 100); err == nil {
		t.Fatal("missing end marker")
	}
	if _, err := Open(&starfile.Bytes{Data: b}, 10, 2); err == nil {
		t.Fatal("byte limit")
	}
}

func FuzzArchive(f *testing.F) {
	f.Add(archiveFixture())
	f.Fuzz(func(t *testing.T, data []byte) {
		a, err := Open(&starfile.Bytes{Data: data}, 100, 1<<20)
		if err != nil {
			return
		}
		for _, e := range a.Entries {
			if _, err := starfile.ReadAll(e.Data); err != nil {
				t.Fatal(err)
			}
		}
	})
}
