package ods2

import (
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func TestTree(t *testing.T) {
	disk := volumeFixture()
	root := disk[13*512 : 14*512]
	le.PutUint32(root[52:], 0x2000)
	seal(root)
	directory := disk[15*512 : 16*512]
	clear(directory)
	for i, name := range []string{"000000.DIR", "INDEXF.SYS"} {
		b := directory[i*24:]
		le.PutUint16(b, 22)
		le.PutUint16(b[2:], 1)
		b[5] = 10
		copy(b[6:], name)
		le.PutUint16(b[16:], 1)
		id := uint16(4)
		if i == 1 {
			id = 1
		}
		le.PutUint16(b[18:], id)
		le.PutUint16(b[20:], id)
	}
	le.PutUint16(directory[48:], 65535)
	v, err := Open(&starfile.Bytes{Data: disk})
	if err != nil {
		t.Fatal(err)
	}
	entries, err := v.Walk(10, 1)
	if err != nil || len(entries) != 3 {
		t.Fatal(entries, err)
	}
	if entries[1].Path != "/000000.DIR;1" || !entries[1].DirectoryLink || entries[1].Data != entries[0].Data || entries[2].Path != "/INDEXF.SYS;1" {
		t.Fatal(entries)
	}
	if _, err := v.Walk(2, 1); err == nil {
		t.Fatal("entry limit")
	}
	copy(directory[6:], "OTHER_.DIR")
	if _, err := v.Walk(10, 1); err == nil {
		t.Fatal("unrecognized root cycle")
	}
}
