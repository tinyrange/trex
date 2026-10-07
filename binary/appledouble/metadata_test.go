package appledouble

import (
	"encoding/binary"
	"testing"
)

func attrFixture() source {
	b := make(source, 174)
	be := binary.BigEndian
	be.PutUint32(b, 0x51607)
	be.PutUint32(b[4:], 0x20000)
	be.PutUint16(b[24:], 2)
	be.PutUint32(b[26:], 9)
	be.PutUint32(b[30:], 50)
	be.PutUint32(b[34:], 120)
	be.PutUint32(b[38:], 2)
	be.PutUint32(b[42:], 170)
	be.PutUint32(b[46:], 4)
	b[58] = 0x80 // preserve Finder flags
	copy(b[84:], "ATTR")
	be.PutUint32(b[92:], 170)
	be.PutUint32(b[96:], 156)
	be.PutUint32(b[100:], 14)
	be.PutUint16(b[118:], 1)
	be.PutUint32(b[120:], 156)
	be.PutUint32(b[124:], 14)
	b[130] = 20
	copy(b[131:], "com.apple.test-attr\x00")
	copy(b[156:], "attribute-data")
	copy(b[170:], "fork")
	return b
}
func TestATTRBorrowedMetadataAndZeroAttributeSlack(t *testing.T) {
	b := attrFixture()
	m, err := OpenMetadata(b)
	if err != nil {
		t.Fatal(err)
	}
	if m.FinderInfo.Size() != 32 || m.Resource.Size() != 4 || len(m.Attributes) != 1 {
		t.Fatal("metadata separation")
	}
	b[156] = 'A'
	var got [14]byte
	if _, err := m.Attributes["com.apple.test-attr"].ReadAt(got[:], 0); err != nil || string(got[:]) != "Attribute-data" {
		t.Fatal("copied or misbased ATTR", err)
	}
	// The real installer has an allocated empty ATTR table followed by slack.
	binary.BigEndian.PutUint16(b[118:], 0)
	binary.BigEndian.PutUint32(b[96:], 120)
	binary.BigEndian.PutUint32(b[100:], 0)
	m, err = OpenMetadata(b)
	if err != nil || len(m.Attributes) != 0 {
		t.Fatal("empty padded ATTR rejected", err)
	}
}
func TestATTRRejectsMalformedBoundsAndNames(t *testing.T) {
	for _, mutate := range []func(source){
		func(b source) { binary.BigEndian.PutUint32(b[92:], 175) },
		func(b source) { binary.BigEndian.PutUint32(b[96:], 119) },
		func(b source) { binary.BigEndian.PutUint32(b[120:], 155) },
		func(b source) { binary.BigEndian.PutUint32(b[124:], 15) },
		func(b source) { b[130] = 128 },
		func(b source) { b[135] = 0 },
		func(b source) { b[150] = 'x' },
		func(b source) { b[131] = 0xff },
		func(b source) { binary.BigEndian.PutUint16(b[118:], 2) },
	} {
		b := attrFixture()
		mutate(b)
		if m, err := OpenMetadata(b); m != nil || err == nil {
			t.Fatal("malformed ATTR accepted", err)
		}
	}
}
