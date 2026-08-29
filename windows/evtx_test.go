package windows

import (
	"encoding/binary"
	"testing"
)

func TestDecodeEVTXTemplateValues(t *testing.T) {
	data := make([]byte, 128)
	copy(data, []byte{0x0f, 1, 1, 0, 0x0c, 1})
	binary.LittleEndian.PutUint32(data[14:18], 4)
	spec := 18
	for _, item := range []struct {
		length uint16
		typ    byte
	}{{1, 0x04}, {1, 0x04}, {2, 0x06}, {2, 0x06}} {
		binary.LittleEndian.PutUint16(data[spec:spec+2], item.length)
		data[spec+2] = item.typ
		spec += 4
	}
	copy(data[34:], []byte{4, 0, 0, 0, 0x80, 0x1b})
	values, _, err := decodeEVTXTemplateInstance(data, 0, 40, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 4 {
		t.Fatalf("value count = %d, want 4", len(values))
	}
	if got, ok := evtxUnsigned(values[3].value); !ok || got != 7040 {
		t.Fatalf("event ID value = %#v, want 7040", values[3].value)
	}
}

func TestEVTXSID(t *testing.T) {
	raw := []byte{1, 2, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0, 32, 2, 0, 0}
	got, err := evtxSID(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got != "S-1-5-18-544" {
		t.Fatalf("SID = %q", got)
	}
}
