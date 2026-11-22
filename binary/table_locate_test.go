package binary

import (
	"encoding/binary"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

func TestLocateTableFindsPlacement(t *testing.T) {
	data := make([]byte, 0x4000)
	const base = 0xffffffff80030000 - 0x1000
	var addrs []uint64
	for i := 0; i < 40; i++ {
		off := 0x1000 + 8*i*7
		binary.BigEndian.PutUint64(data[off:], 0xffffffffff100000+uint64(i))
		addrs = append(addrs, base+uint64(off))
	}
	// A distracting pointer elsewhere.
	binary.BigEndian.PutUint64(data[0x3800:], 0xffffffff00000000)
	got, err := LocateTable(&starfile.Bytes{Data: data}, addrs, 0xffffffff, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 || got[0].Base != base || got[0].Hits != 40 {
		t.Fatalf("%+v", got)
	}
	if _, err := LocateTable(&starfile.Bytes{Data: data}, addrs[:2], 0xffffffff, 3); err == nil {
		t.Fatal("accepted two addresses")
	}
}

func TestLocateWordsFindsBranchTable(t *testing.T) {
	data := make([]byte, 0x2000)
	const base = 0xffffffffcf180000
	var addrs []uint64
	for i := 0; i < 30; i++ {
		off := 0x100 + 16*i*3
		binary.BigEndian.PutUint32(data[off:], 0x48000100|uint32(i)<<4) // b +x
		addrs = append(addrs, base+uint64(off))
	}
	got, err := LocateWords(&starfile.Bytes{Data: data}, addrs, 0xfc000003, 0x48000000, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 || got[0].Base != base || got[0].Hits != 30 {
		t.Fatalf("%+v", got)
	}
}
