package windows

import (
	"encoding/binary"
	"math"
	"testing"
)

func TestWMIRepositoryMappingDeletedSlots(t *testing.T) {
	section := wmiMappingSection{generation: 9, physicalPages: 3, base: []uint32{0, math.MaxUint32, 2, math.MaxUint32}, free: []uint32{1}}
	mapping := wmiRepositoryMapping{objects: section, index: section}
	got, err := parseWMIRepositoryMapping(serializeWMIRepositoryMapping(mapping))
	if err != nil || !equalUint32s(got.objects.base, section.base) {
		t.Fatalf("deleted slots: %#v, %v", got, err)
	}
	for _, bad := range []wmiMappingSection{
		{physicalPages: 3, base: []uint32{0, math.MaxUint32, 2}, free: []uint32{math.MaxUint32}},
		{physicalPages: 3, base: []uint32{0, math.MaxUint32, 2}, free: []uint32{2}},
		{physicalPages: math.MaxUint32, base: []uint32{0}},
	} {
		if _, err := parseWMIRepositoryMapping(serializeWMIRepositoryMapping(wmiRepositoryMapping{objects: bad, index: section})); err == nil {
			t.Fatalf("accepted invalid mapping %#v", bad)
		}
	}
}

func TestWMIRepositoryObjectDeletedSlotsFailClosed(t *testing.T) {
	data, _, err := buildWMIRepositoryObjects([][]byte{[]byte("a real record")})
	if err != nil {
		t.Fatal(err)
	}
	base := make([]uint32, len(data)/wmiRepositoryPageSize)
	for i := range base {
		base[i] = uint32(i)
	}
	base = append(base, math.MaxUint32)
	section := wmiMappingSection{physicalPages: uint32(len(data) / wmiRepositoryPageSize), base: base}
	if records, err := parseWMIRepositoryRecords(section, data); err != nil || len(records) != 1 {
		t.Fatalf("unused hole: %d, %v", len(records), err)
	}
	// A cache entry may not refer to the deleted slot.
	bad := append([]byte(nil), data...)
	binary.LittleEndian.PutUint32(bad[12:16], uint32(len(base)-1))
	if _, err := parseWMIRepositoryRecords(section, bad); err == nil {
		t.Fatal("accepted cache reference to hole")
	}
	// A record spanning into a deleted slot must return an error, not panic.
	bad = append([]byte(nil), data...)
	binary.LittleEndian.PutUint32(bad[8:12], 0)
	binary.LittleEndian.PutUint32(bad[wmiRepositoryPageSize+8:wmiRepositoryPageSize+12], wmiRepositoryPageSize)
	if _, err := parseWMIRepositoryRecords(section, bad); err == nil {
		t.Fatal("accepted record continuation into hole")
	}
}

func TestWMIRepositoryIndexDeletedSlots(t *testing.T) {
	page, err := buildWMIRepositoryIndexPage(1, []string{"test"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 2*wmiRepositoryPageSize)
	binary.LittleEndian.PutUint32(data[:4], wmiIndexMetaSignature)
	copy(data[wmiRepositoryPageSize:], page)
	section := wmiMappingSection{physicalPages: 2, base: []uint32{0, 1, math.MaxUint32}}
	if pages, err := parseWMIRepositoryIndex(section, data); err != nil || len(pages) != 1 {
		t.Fatalf("unused index hole: %d, %v", len(pages), err)
	}
}
