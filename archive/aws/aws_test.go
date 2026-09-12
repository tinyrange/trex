package aws

import (
	"bytes"
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func block(length, previous uint16, flags byte, data string) []byte {
	h := make([]byte, 6)
	binary.LittleEndian.PutUint16(h, length)
	binary.LittleEndian.PutUint16(h[2:], previous)
	h[4] = flags
	return append(h, []byte(data)...)
}
func TestRecordsAndMarks(t *testing.T) {
	b := block(3, 0, 0x80, "abc")
	b = append(b, block(2, 3, 0x20, "de")...)
	b = append(b, block(0, 2, 0x40, "")...)
	b = append(b, block(1, 0, 0xa0, "f")...)
	records, err := Open(&starfile.Bytes{Data: b}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 || !records[1].TapeMark || records[1].Data != nil || records[0].Blocks != 2 {
		t.Fatalf("%+v", records)
	}
	data, err := starfile.ReadAll(records[0].Data)
	if err != nil || string(data) != "abcde" {
		t.Fatalf("%q %v", data, err)
	}
	if _, err := Open(&starfile.Bytes{Data: b}, 2); err == nil {
		t.Fatal("ignored limit")
	}
	for _, bad := range [][]byte{b[:2], b[:8], block(1, 1, 0xa0, "x"), block(1, 0, 0x20, "x"), block(1, 0, 0x80, "x"), block(1, 0, 0x40, "x"), block(0, 0, 0x01, "")} {
		if _, err := Open(&starfile.Bytes{Data: bad}, 10); err == nil {
			t.Fatalf("accepted %x", bad)
		}
	}
	mutated := bytes.Clone(b)
	mutated[5] = 1
	if _, err := Open(&starfile.Bytes{Data: mutated}, 10); err == nil {
		t.Fatal("accepted second flags")
	}
}
