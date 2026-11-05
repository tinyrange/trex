package nsis

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func unicodeTable(units ...uint16) []byte {
	b := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(b[2*i:], u)
	}
	return b
}

func TestUnicodeStrings(t *testing.T) {
	tests := []struct {
		name  string
		units []uint16
		want  string
	}{
		{"name", []uint16{'文', '件', '.', 'e', 'x', 'e', 0}, "文件.exe"},
		{"surrogate", []uint16{0xd83d, 0xde00, 0}, "😀"},
		{"variable", []uint16{3, 0x8095, '\\', 'x', 0}, "$INSTDIR\\x"},
		{"language", []uint16{1, 0x8181, 0}, "${LANG:129}"},
		{"shell", []uint16{2, 0x8e9a, 0}, "${SHELL:9a,8e}"},
		{"literal", []uint16{4, 3, '$', 0}, "\x03$$"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := unicodeTable(append([]uint16{0}, tc.units...)...)
			got, raw, err := decodeString(data, 1)
			if err != nil || got != tc.want || len(raw) != (len(tc.units)-1)*2 {
				t.Fatalf("%q raw=%x err=%v", got, raw, err)
			}
		})
	}
	if got, _, err := decodeString(unicodeTable(0), -3); err != nil || got != "${LANG:2}" {
		t.Fatalf("language %q %v", got, err)
	}
}

func TestUnicodeStringsRejectMalformed(t *testing.T) {
	for _, units := range [][]uint16{{0, 'x'}, {0, 3}, {0, 3, 0}, {0, 4, 0}, {0, 0xd800, 0}, {0, 0xdc00, 0}, {0, 0xd800}} {
		if _, _, err := decodeString(unicodeTable(units...), 1); err == nil {
			t.Fatalf("accepted %x", units)
		}
	}
	if _, _, err := decodeString(unicodeTable(0, 'x', 0), 1<<30); err == nil {
		t.Fatal("accepted overflowing offset")
	}
	long := unicodeTable(append([]uint16{0}, make([]uint16, 65538)...)...)
	for i := 2; i < len(long); i += 2 {
		long[i] = 'x'
	}
	if _, _, err := decodeString(long, 1); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("limit: %v", err)
	}
}

// A full Unicode header has two 2072-byte section records. The second name
// must be read from the second record, not the first record's runtime buffer.
func TestUnicodeContainerSectionsAndPayload(t *testing.T) {
	const stride = 24 + 2048
	code := 68 + 2*stride
	data := make([]byte, code+28)
	put := binary.LittleEndian.PutUint32
	put(data[4:], 68)
	put(data[12:], 68)
	put(data[16:], 2)
	put(data[20:], uint32(code))
	put(data[24:], 1)
	for i, name := range []uint32{1, 5} {
		row := data[68+i*stride:]
		put(row, name)
		put(row[8:], 1)
		put(row[16:], 1)
	}
	put(data[code:], 20)
	put(data[code+8:], 9)
	put(data[28:], uint32(len(data)))
	data = append(data, unicodeTable(0, 'o', 'n', 'e', 0, 't', 'w', 'o', 0, '文', 0)...)
	for i := 4; i < 7; i++ {
		put(data[4+i*8:], uint32(len(data)))
	}
	input := bytes.NewReader(fixture(t, data, false, 512))
	listing, err := List(input, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(listing.Sections) != 2 || listing.Sections[1].Name != "two" || len(listing.Entries) != 1 || listing.Entries[0].Name != "文" {
		t.Fatalf("sections=%+v entries=%+v", listing.Sections, listing.Entries)
	}
	archive, err := Open(input, Options{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := archive.Plan(map[string]string{"<TARGETDIR>": `C:\App`}, nil, []CodeRange{{0, 1}})
	if err != nil || planList(t, plan, "unresolved").Len() != 0 || planList(t, plan, "files").Len() != 1 {
		t.Fatalf("plan %v %v", plan, err)
	}
	put(data[16:], 3)
	if _, err := List(bytes.NewReader(fixture(t, data, false, 512)), Options{}); err == nil {
		t.Fatal("accepted inconsistent section count")
	}
}
