package windows

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestNEExtensionPreservesOriginalStorageAndMovableEntries(t *testing.T) {
	source := neExportFixture()
	// Windows 3.x may preload only this original range. Appended segments
	// require ordinary segment loading instead of the stale range.
	ne := int(binary.LittleEndian.Uint32(source[0x3c:]))
	source[ne+0x37] |= 0x08
	binary.LittleEndian.PutUint32(source[ne+0x38:], 0x12345678)
	original := append([]byte(nil), source...)
	code := []byte{0xb8, 0xff, 0xff, 0x8e, 0xd8, 0x9a, 0xff, 0xff, 0, 0, 0xcb}
	data := []byte{1, 2, 3, 4}
	result, err := extendWindowsNE(source, code, data, []neInternalRelocation{{2, 1, -1, 0}, {3, 6, 1, 7}}, map[int]int{1: 0, 101: 10}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(source, original) {
		t.Fatal("mutated source")
	}
	if !bytes.Equal(result[64:len(source)], source[64:]) {
		t.Fatal("changed original resource/code bytes")
	}
	exports, err := parseWindowsNEExports(result)
	if err != nil {
		t.Fatal(err)
	}
	if len(exports) != 4 {
		t.Fatalf("exports=%+v", exports)
	}
	if e := exports[0]; e.Ordinal != 1 || e.Segment != 3 || e.Offset != 0 || e.Names[0] != "FIXED" || !bytes.Equal(result[e.FileOffset:e.FileOffset+len(code)], code) {
		t.Fatalf("redirect=%+v", e)
	}
	if e := exports[1]; e.Ordinal != 3 || e.FileOffset != 521 || !e.Movable || e.Names[0] != "MOVE" {
		t.Fatalf("original movable entry=%+v", e)
	}
	if e := exports[2]; !e.Constant || e.Offset != 0x1234 {
		t.Fatalf("constant=%+v", e)
	}
	if e := exports[3]; e.Ordinal != 101 || e.Segment != 3 || e.Offset != 10 {
		t.Fatalf("new export=%+v", e)
	}
	m, err := parseWindowsNEModule(result)
	if err != nil {
		t.Fatal(err)
	}
	if result[m.ne+0x37]&0x08 != 0 || binary.LittleEndian.Uint32(result[m.ne+0x38:]) != 0 {
		t.Fatal("retained stale fast-load range")
	}
	if m.segmentCount != 4 {
		t.Fatal(m.segmentCount)
	}
	dataOffset := int(binary.LittleEndian.Uint16(result[m.segments+24:])) << m.alignShift
	if !bytes.Equal(result[dataOffset:dataOffset+4], data) {
		t.Fatal("new data missing")
	}
	fixup := exports[0].FileOffset + len(code)
	want := []byte{2, 0, 2, 0, 1, 0, 4, 0, 0, 0, 3, 0, 6, 0, 1, 0, 7, 0}
	if !bytes.Equal(result[fixup:fixup+len(want)], want) {
		t.Fatalf("relocations=%x", result[fixup:fixup+len(want)])
	}
}

func TestNEExtensionRejectsInvalidReferences(t *testing.T) {
	for _, r := range []neInternalRelocation{
		{2, -1, -1, 0}, {3, 1, -1, 0}, {1, 0, -1, 0}, {2, 0, 5, 0}, {2, 0, -2, 0}, {2, 0, 1, 65536},
	} {
		if _, err := extendWindowsNE(neExportFixture(), []byte{0xff, 0xff}, []byte{0}, []neInternalRelocation{r}, nil, nil); err == nil {
			t.Fatalf("accepted %+v", r)
		}
	}
	for _, exports := range []map[int]int{{0: 0}, {1: 1}, {65536: 0}} {
		if _, err := extendWindowsNE(neExportFixture(), []byte{0xcb}, []byte{0}, nil, exports, nil); err == nil {
			t.Fatalf("accepted exports=%v", exports)
		}
	}
}

func TestNEExtensionRejectsOverlappingFixups(t *testing.T) {
	_, err := extendWindowsNE(neExportFixture(), []byte{0xff, 0xff, 0xff, 0xff}, []byte{0},
		[]neInternalRelocation{{3, 0, 1, 0}, {2, 2, 1, 0}}, nil, nil)
	if err == nil {
		t.Fatal("accepted overlapping fixups")
	}
}

func TestNEExtensionPreservesAliasedEntryPrologues(t *testing.T) {
	source := neExportFixture()
	result, err := extendWindowsNE(source, []byte{0xcb}, []byte{0}, nil, map[int]int{1: 0, 3: 0}, map[int]int{100: 1, 101: 3})
	if err != nil {
		t.Fatal(err)
	}
	entries, err := parseWindowsNEExports(result)
	if err != nil {
		t.Fatal(err)
	}
	original, _ := parseWindowsNEExports(source)
	for i, entry := range entries[3:] {
		want := original[i]
		if entry.Ordinal != 100+i || entry.Segment != want.Segment || entry.Offset != want.Offset || entry.Flags != want.Flags || entry.Movable != want.Movable {
			t.Fatalf("alias=%+v original=%+v", entry, want)
		}
	}
	ne := int(binary.LittleEndian.Uint32(result[0x3c:]))
	if binary.LittleEndian.Uint16(result[ne+0x30:]) != 1 {
		t.Fatal("incorrect movable entry count")
	}
	for _, aliases := range []map[int]int{{1: 1}, {100: 2}, {0: 1}, {65536: 1}} {
		if _, err := extendWindowsNE(source, []byte{0xcb}, []byte{0}, nil, nil, aliases); err == nil {
			t.Fatalf("accepted aliases %v", aliases)
		}
	}
}

func TestNEExtensionMovableCallUsesEntryThunk(t *testing.T) {
	source := neExportFixture()
	code := []byte{0x9a, 0xff, 0xff, 0, 0, 0xcb}
	result, err := extendWindowsNE(source, code, []byte{0}, []neInternalRelocation{{3, 1, -2, 3}}, map[int]int{600: 0}, nil)
	if err != nil {
		t.Fatal(err)
	}
	exports, err := parseWindowsNEExports(result)
	if err != nil {
		t.Fatal(err)
	}
	entry := exports[len(exports)-1]
	fixup := result[entry.FileOffset+len(code) : entry.FileOffset+len(code)+10]
	if !bytes.Equal(fixup, []byte{1, 0, 3, 0, 1, 0, 255, 0, 3, 0}) {
		t.Fatalf("movable fixup=%x", fixup)
	}
	for _, ordinal := range []int{0, 1, 2, 4, 600} {
		if _, err := extendWindowsNE(source, code, []byte{0}, []neInternalRelocation{{3, 1, -2, ordinal}}, map[int]int{600: 0}, nil); err == nil {
			t.Fatalf("accepted nonmovable ordinal %d", ordinal)
		}
	}
}
