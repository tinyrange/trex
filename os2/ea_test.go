package os2

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestExtendedAttributes(t *testing.T) {
	data := []byte{0, 0, 0, 0, 0x80, 5, 3, 0, '.', 'T', 'Y', 'P', 'E', 0, 0, 1, 0xff}
	binary.LittleEndian.PutUint32(data, uint32(len(data)))
	eas, err := ExtendedAttributes(data)
	if err != nil || len(eas) != 1 || eas[0].Name != ".TYPE" || eas[0].Flags != 0x80 || !bytes.Equal(eas[0].Value, []byte{0, 1, 0xff}) {
		t.Fatal(eas, err)
	}
	data[14] = 99
	if eas[0].Value[0] != 0 {
		t.Fatal("EA aliases input")
	}
	for n := 0; n < len(data); n++ {
		if _, err := ExtendedAttributes(data[:n]); err == nil {
			t.Fatalf("accepted prefix %d", n)
		}
	}
	bad := append([]byte(nil), data...)
	bad[13] = 1
	if _, err := ExtendedAttributes(bad); err == nil {
		t.Fatal("accepted missing name terminator")
	}
	duplicate := append(append([]byte(nil), data...), data[4:]...)
	binary.LittleEndian.PutUint32(duplicate, uint32(len(duplicate)))
	if _, err := ExtendedAttributes(duplicate); err == nil {
		t.Fatal("accepted duplicate EA")
	}
}

func FuzzExtendedAttributes(f *testing.F) {
	f.Add([]byte{4, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		eas, err := ExtendedAttributes(data)
		if err == nil {
			for _, ea := range eas {
				if len(ea.Name) == 0 || len(ea.Name) > 255 || len(ea.Value) > 65535 {
					t.Fatal("invalid accepted EA")
				}
			}
		}
	})
}
