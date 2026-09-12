package ods2

import (
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func volumeFixture() []byte {
	disk := make([]byte, 20*512)
	home := disk[512:1024]
	le.PutUint32(home, 1)
	le.PutUint32(home[4:], 2)
	le.PutUint32(home[8:], 3)
	le.PutUint16(home[12:], 0x0201)
	le.PutUint16(home[14:], 1)
	le.PutUint16(home[22:], 5)
	le.PutUint32(home[24:], 4)
	le.PutUint32(home[28:], 16)
	le.PutUint16(home[32:], 1)
	copy(home[496:], "DECFILE11B  ")
	le.PutUint16(home[58:], checksum(home[:58]))
	seal(home)
	index := headerFixture()
	le.PutUint16(index[8:], 1)
	le.PutUint16(index[26:], 9)
	le.PutUint16(index[30:], 10)
	index[58] = 6
	le.PutUint16(index[200:], 0x8004)
	le.PutUint32(index[202:], 0)
	le.PutUint16(index[206:], 0x8003)
	le.PutUint32(index[208:], 10)
	seal(index)
	copy(disk[3*512:], index)
	copy(disk[10*512:], index)
	root := headerFixture()
	le.PutUint16(root[8:], 4)
	le.PutUint16(root[10:], 4)
	le.PutUint16(root[26:], 1)
	le.PutUint16(root[30:], 2)
	root[58] = 3
	le.PutUint16(root[200:], 0x8000)
	le.PutUint32(root[202:], 15)
	seal(root)
	copy(disk[13*512:], root)
	copy(disk[15*512:], directoryFixture())
	return disk
}
func TestFragmentedIndex(t *testing.T) {
	disk := volumeFixture()
	v, err := Open(&starfile.Bytes{Data: disk})
	if err != nil {
		t.Fatal(err)
	}
	h, f, err := v.File(FileID{Number: 4, Sequence: 4})
	if err != nil || h.ID.Number != 4 || f.Size() != 512 {
		t.Fatal(h, f, err)
	}
	entries, err := ReadDirectory(f, 10)
	if err != nil || len(entries) != 2 {
		t.Fatal(entries, err)
	}
	if _, err := v.Header(FileID{Number: 4, Sequence: 3}); err == nil {
		t.Fatal("stale identity")
	}
	if _, err := v.Header(FileID{Number: 4, Sequence: 4, Volume: 1}); err == nil {
		t.Fatal("external volume")
	}
	primary := disk[10*512 : 11*512]
	le.PutUint32(primary[208:], 11)
	seal(primary)
	if _, err := Open(&starfile.Bytes{Data: disk}); err == nil {
		t.Fatal("inconsistent primary index")
	}
}
