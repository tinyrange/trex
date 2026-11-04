package windows

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func stringBlock(values map[int]string) []byte {
	var b []byte
	for i := 0; i < 16; i++ {
		units := utf16.Encode([]rune(values[i]))
		b = binary.LittleEndian.AppendUint16(b, uint16(len(units)))
		for _, u := range units {
			b = binary.LittleEndian.AppendUint16(b, u)
		}
	}
	return b
}

func TestPEStringTablesLanguagesAndCountedText(t *testing.T) {
	b := stringBlock(map[int]string{0: "Pacific Standard Time", 15: "A\x00🌍"})
	rows, err := peStringTableResources([]peResource{
		{typ: "#6", name: "#14", lang: "#1033", data: b},
		{typ: "#6", name: "#14", lang: "#1036", data: stringBlock(map[int]string{0: "Pacifique"})},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || rows[0].id != 208 || rows[0].text != "Pacific Standard Time" || rows[1].lang != "#1036" || rows[2].id != 223 || rows[2].text != "A\x00🌍" {
		t.Fatalf("%+v", rows)
	}
	// Exact maximum ID does not wrap to zero.
	rows, err = peStringTableResources([]peResource{{typ: "#6", name: "#268435456", data: stringBlock(map[int]string{15: "last"})}})
	if err != nil || len(rows) != 1 || rows[0].id != 0xffffffff {
		t.Fatalf("max id: %+v %v", rows, err)
	}
}

func TestPEStringTablesRejectMalformed(t *testing.T) {
	valid := stringBlock(map[int]string{0: "x"})
	for n := 0; n < len(valid); n++ {
		_, err := peStringTableResources([]peResource{{typ: "#6", name: "#1", data: valid[:n]}})
		if err == nil {
			t.Fatalf("accepted truncated prefix %d", n)
		}
	}
	badSurrogate := append([]byte(nil), valid...)
	binary.LittleEndian.PutUint16(badSurrogate[2:], 0xd800)
	for _, b := range [][]byte{append(append([]byte(nil), valid...), 1), append(append([]byte(nil), valid...), 0, 0, 0, 0), badSurrogate} {
		if _, err := peStringTableResources([]peResource{{typ: "#6", name: "#1", data: b}}); err == nil {
			t.Fatal("accepted malformed block")
		}
	}
	for _, name := range []string{"#0", "#268435457", "#01", "named", "1", "#-1"} {
		if _, err := peStringTableResources([]peResource{{typ: "#6", name: name, data: valid}}); err == nil {
			t.Fatalf("accepted %s", name)
		}
	}
	r := peResource{typ: "#6", name: "#1", lang: "#1033", data: valid}
	if _, err := peStringTableResources([]peResource{r, r}); err == nil {
		t.Fatal("accepted ambiguous block")
	}
}
