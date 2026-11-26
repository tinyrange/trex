package ibm9020

import (
	"slices"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

func TestReadRelocations(t *testing.T) {
	file := &starfile.Bytes{Data: []byte("\xd8\x06\xa5\x03\x09\x00\x10\x15\x08\x00\x1c\x01\x0e\x12\x34\x56")}
	id, entries, err := ReadRelocations(file)
	want := []Relocation{
		{Address: 0x1015, Width: 3},
		{Address: 0x1c01, Width: 3},
		{Address: 0x123456, Width: 4, Subtract: true},
	}
	if err != nil || id != 0xd806a503 || !slices.Equal(entries, want) {
		t.Fatalf("ReadRelocations = %08x, %+v, %v", id, entries, err)
	}
}

func TestReadRelocationsRejectsMalformedRecord(t *testing.T) {
	for _, data := range [][]byte{
		{0xd8, 0x06, 0xa5, 3, 9},
		{0xd8, 0x06, 0xa5, 0},
		{0xd8, 0x06, 0xa5, 3, 16, 0, 0x10, 0x15},
	} {
		if _, _, err := ReadRelocations(&starfile.Bytes{Data: data}); err == nil {
			t.Errorf("ReadRelocations accepted %x", data)
		}
	}
}
