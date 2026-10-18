package wim

import (
	"encoding/binary"
	"testing"
)

func TestWIMEADecodeAndProjection(t *testing.T) {
	// Two unaligned packed records, one NEED_EA, with a binary value.
	raw := []byte{3, 0, 1, 0x80, 'A', 0, 0, 1, 255, 0, 0, 1, 0, 'B', 0}
	eas, err := parseWIMEAs(raw)
	if err != nil || len(eas) != 2 {
		t.Fatalf("%v %v", eas, err)
	}
	if eas[0].Name != "A" || eas[0].Flags != 0x80 || string(eas[0].Value) != string([]byte{0, 1, 255}) || eas[1].Name != "B" || len(eas[1].Value) != 0 {
		t.Fatalf("%v", eas)
	}
	data := make([]byte, 128)
	binary.LittleEndian.PutUint64(data, 128)
	binary.LittleEndian.PutUint32(data[104:], 2)
	binary.LittleEndian.PutUint32(data[108:], uint32(len(raw)))
	copy(data[112:], raw)
	e, err := parseWIMEntry(data, 0, "/")
	if err != nil {
		t.Fatal(err)
	}
	m := (&image{}).virtualMetadata(e, true)
	if len(m.ExtendedAttributes) != 2 || m.ExtendedAttributes[0].Name != "A" {
		t.Fatalf("%v", m)
	}
	for _, bad := range [][]byte{raw[:3], raw[:8], {0, 0, 0, 0, 0}, {0, 0, 1, 1, 'A', 0}, {0, 0, 1, 0, 'A', 1}, {0, 0, 2, 0, 'A', 0, 0}} {
		if _, err := parseWIMEAs(bad); err == nil {
			t.Errorf("accepted invalid EA %x", bad)
		}
	}
}
