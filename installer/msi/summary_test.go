package msi

import (
	"encoding/binary"
	"testing"
)

func summaryFixture() []byte {
	b := make([]byte, 128)
	binary.LittleEndian.PutUint16(b, 0xfffe)
	binary.LittleEndian.PutUint32(b[24:], 1)
	binary.LittleEndian.PutUint32(b[44:], 48)
	binary.LittleEndian.PutUint32(b[48:], 80)
	binary.LittleEndian.PutUint32(b[52:], 2)
	binary.LittleEndian.PutUint32(b[56:], 9)
	binary.LittleEndian.PutUint32(b[60:], 24)
	binary.LittleEndian.PutUint32(b[64:], 15)
	binary.LittleEndian.PutUint32(b[68:], 72)
	binary.LittleEndian.PutUint32(b[72:], 30)
	binary.LittleEndian.PutUint32(b[76:], 39)
	copy(b[80:], "{ea4a8e4a-f5bf-454f-b107-666be3f30608}\x00")
	binary.LittleEndian.PutUint32(b[120:], 3)
	binary.LittleEndian.PutUint32(b[124:], 2)
	return b
}

func TestSummaryPackageCodeBounds(t *testing.T) {
	b := summaryFixture()
	v, err := summaryProperty(b, 9)
	if err != nil {
		t.Fatal(err)
	}
	got, err := summaryPackageCode(v)
	if err != nil || got != "{EA4A8E4A-F5BF-454F-B107-666BE3F30608}" {
		t.Fatalf("%q %v", got, err)
	}
	// No truncation of a complete property set is acceptable.
	for i := 0; i < len(b); i++ {
		if _, err := summaryProperty(b[:i], 9); err == nil {
			t.Fatalf("accepted truncation at %d", i)
		}
	}
	for _, tc := range []struct {
		name   string
		offset int
		value  uint32
	}{
		{"section overlap", 44, 28}, {"huge section", 48, 0xffffffff},
		{"huge count", 52, 0xffffffff}, {"duplicate id", 64, 9},
		{"offset alias", 68, 24}, {"property in index", 60, 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := summaryFixture()
			binary.LittleEndian.PutUint32(bad[tc.offset:], tc.value)
			if _, err := summaryProperty(bad, 9); err == nil {
				t.Fatal("accepted malformed summary")
			}
		})
	}
	// Declared string length must not consume the next property's bytes.
	binary.LittleEndian.PutUint32(b[68:], 40)
	v, err = summaryProperty(b, 9)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = summaryPackageCode(v); err == nil {
		t.Fatal("read into sibling property")
	}
	b = summaryFixture()
	b[81] = 'z'
	v, _ = summaryProperty(b, 9)
	if _, err = summaryPackageCode(v); err == nil {
		t.Fatal("accepted non-GUID package code")
	}
}
