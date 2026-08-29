package windows

import (
	"encoding/binary"
	"testing"
)

func TestParseCodeViewRecord(t *testing.T) {
	record := make([]byte, 24)
	copy(record, "RSDS")
	binary.LittleEndian.PutUint32(record[4:8], 0x12345678)
	binary.LittleEndian.PutUint16(record[8:10], 0x9abc)
	binary.LittleEndian.PutUint16(record[10:12], 0xdef0)
	copy(record[12:20], []byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0})
	binary.LittleEndian.PutUint32(record[20:24], 2)
	record = append(record, []byte("ntoskrnl.pdb\x00ignored")...)

	info, err := parseCodeViewRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if info == nil {
		t.Fatal("expected CodeView info")
	}
	if got, want := info.guid, "12345678-9ABC-DEF0-1234-56789ABCDEF0"; got != want {
		t.Fatalf("guid = %q, want %q", got, want)
	}
	if got, want := info.key, "123456789ABCDEF0123456789ABCDEF02"; got != want {
		t.Fatalf("key = %q, want %q", got, want)
	}
	if got, want := info.path, "ntoskrnl.pdb"; got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
}
