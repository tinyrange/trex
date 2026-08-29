package windows

import (
	"encoding/binary"
	"testing"
)

func TestParseEventLogRecord(t *testing.T) {
	record := make([]byte, 0x120)
	binary.LittleEndian.PutUint32(record[0:4], uint32(len(record)))
	copy(record[4:8], "LfLe")
	binary.LittleEndian.PutUint32(record[8:12], 7)
	binary.LittleEndian.PutUint32(record[12:16], 1234)
	binary.LittleEndian.PutUint32(record[20:24], 64004)
	binary.LittleEndian.PutUint16(record[24:26], 1)
	binary.LittleEndian.PutUint16(record[26:28], 1)
	copy(record[0x38:], utf16Nul("Windows starfile.File Protection"))
	computerOffset := 0x38 + len(utf16Nul("Windows starfile.File Protection"))
	copy(record[computerOffset:], utf16Nul("TREX-XP"))
	stringOffset := computerOffset + len(utf16Nul("TREX-XP"))
	binary.LittleEndian.PutUint32(record[0x24:0x28], uint32(stringOffset))
	copy(record[stringOffset:], utf16Nul("c:\\windows\\system32\\example.dll"))

	got, err := parseEventLogRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if got.number != 7 || got.eventID != 64004 || got.source != "Windows starfile.File Protection" || got.computer != "TREX-XP" {
		t.Fatalf("record = %#v", got)
	}
	if len(got.strings) != 1 || got.strings[0] != `c:\windows\system32\example.dll` {
		t.Fatalf("strings = %q", got.strings)
	}
}
