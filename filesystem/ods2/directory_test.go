package ods2

import (
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func directoryFixture() []byte {
	b := make([]byte, 512)
	le.PutUint16(b, 24)
	le.PutUint16(b[2:], 5)
	b[5] = 3
	copy(b[6:], "A.B")
	le.PutUint16(b[10:], 3)
	le.PutUint16(b[12:], 10)
	le.PutUint16(b[14:], 1)
	le.PutUint16(b[18:], 2)
	le.PutUint16(b[20:], 11)
	le.PutUint16(b[22:], 2)
	le.PutUint16(b[26:], 65535)
	return b
}
func TestDirectory(t *testing.T) {
	b := directoryFixture()
	entries, err := ReadDirectory(&starfile.Bytes{Data: b}, 10)
	if err != nil || len(entries) != 2 {
		t.Fatal(entries, err)
	}
	if string(entries[0].Name) != "A.B" || entries[0].Version != 3 || entries[1].ID.Number != 11 || entries[0].VersionLimit != 5 {
		t.Fatal(entries)
	}
	if _, err := ReadDirectory(&starfile.Bytes{Data: b}, 1); err == nil {
		t.Fatal("limit")
	}
	for _, mutate := range []func([]byte){
		func(b []byte) { le.PutUint16(b, 512) },
		func(b []byte) { b[5] = 79 },
		func(b []byte) { b[4] = 1 },
		func(b []byte) { b[9] = 1 },
		func(b []byte) { le.PutUint16(b[18:], 3) },
	} {
		bad := directoryFixture()
		mutate(bad)
		if _, err := ReadDirectory(&starfile.Bytes{Data: bad}, 10); err == nil {
			t.Fatal("accepted malformed directory")
		}
	}
	second := directoryFixture()
	le.PutUint16(second, 16)
	le.PutUint16(second[10:], 1)
	le.PutUint16(second[18:], 65535)
	joined := append(b, second...)
	entries, err = ReadDirectory(&starfile.Bytes{Data: joined}, 10)
	if err != nil || len(entries) != 3 || entries[2].Offset != 512 {
		t.Fatal(entries, err)
	}
}
