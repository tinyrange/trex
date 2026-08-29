package windows

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func TestOpenTypeFullNames(t *testing.T) {
	font := testOpenTypeFont("Tahoma")
	names, err := openTypeFullNames(font)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != "Tahoma" {
		t.Fatalf("full names = %q, want [Tahoma]", names)
	}
}

func TestOpenTypeFullNamesRejectsTruncatedFont(t *testing.T) {
	if _, err := openTypeFullNames([]byte("bad")); err == nil {
		t.Fatal("openTypeFullNames accepted a truncated font")
	}
}

func testOpenTypeFont(name string) []byte {
	chars := utf16.Encode([]rune(name))
	nameBytes := make([]byte, len(chars)*2)
	for i, char := range chars {
		binary.BigEndian.PutUint16(nameBytes[i*2:], char)
	}
	nameTable := make([]byte, 18+len(nameBytes))
	binary.BigEndian.PutUint16(nameTable[2:4], 1)
	binary.BigEndian.PutUint16(nameTable[4:6], 18)
	binary.BigEndian.PutUint16(nameTable[6:8], 3)
	binary.BigEndian.PutUint16(nameTable[8:10], 1)
	binary.BigEndian.PutUint16(nameTable[10:12], 0x0409)
	binary.BigEndian.PutUint16(nameTable[12:14], 4)
	binary.BigEndian.PutUint16(nameTable[14:16], uint16(len(nameBytes)))
	copy(nameTable[18:], nameBytes)

	font := make([]byte, 28+len(nameTable))
	copy(font[:4], []byte{0x00, 0x01, 0x00, 0x00})
	binary.BigEndian.PutUint16(font[4:6], 1)
	copy(font[12:16], "name")
	binary.BigEndian.PutUint32(font[20:24], 28)
	binary.BigEndian.PutUint32(font[24:28], uint32(len(nameTable)))
	copy(font[28:], nameTable)
	return font
}
