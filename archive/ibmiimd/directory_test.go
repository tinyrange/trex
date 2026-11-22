package ibmiimd

import (
	"encoding/binary"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

func TestResidentDirectoryPreservesVirtualLocations(t *testing.T) {
	b := fixture()[4096:4196]
	// Resident SLS sector numbers may overlap or exceed the directory file;
	// they are not physical extents. Keep declared addresses and raw flags.
	for _, offset := range []int{36, 68} {
		binary.BigEndian.PutUint32(b[offset:], 0xffff0000)
	}
	entries, size, err := ReadDirectory(&starfile.Bytes{Data: b}, 0, 2)
	if err != nil || size != 100 || len(entries) != 2 {
		t.Fatal(entries, size, err)
	}
	if entries[0].Offset != 0 || entries[0].Data != nil || entries[0].Sector != 0xffff0000 || entries[1].DeclaredAddress != 0xffffffff10000400 || entries[1].Flags != 0x80000000 {
		t.Fatal(entries)
	}
	for _, source := range [][]byte{b[:99], append([]byte(nil), b...)} {
		if len(source) == 100 {
			source[99] ^= 1
		}
		if _, _, err := ReadDirectory(&starfile.Bytes{Data: source}, 0, 2); err == nil {
			t.Fatal("bad end accepted")
		}
	}
	if _, _, err := ReadDirectory(&starfile.Bytes{Data: b}, 0, 1); err == nil {
		t.Fatal("entry budget ignored")
	}
}
