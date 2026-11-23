package elfmeta

import (
	"debug/dwarf"
	"encoding/binary"
	"maps"
	"testing"
)

func TestNamedDWARFStructOffsets(t *testing.T) {
	abbrev := []byte{
		1, byte(dwarf.TagCompileUnit), 1, 0, 0,
		2, byte(dwarf.TagStructType), 1, byte(dwarf.AttrName), 8, byte(dwarf.AttrByteSize), 0x0b, 0, 0,
		3, byte(dwarf.TagMember), 0, byte(dwarf.AttrName), 8, byte(dwarf.AttrDataMemberLoc), 0x0b, 0, 0,
		0,
	}
	info := []byte{0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 8, 1}
	info = append(info, 2, 't', 'a', 's', 'k', 0, 24)
	info = append(info, 3, 'p', 'i', 'd', 0, 0)
	info = append(info, 3, 's', 't', 'a', 'c', 'k', 0, 16, 0, 0)
	binary.LittleEndian.PutUint32(info, uint32(len(info)-4))
	data, err := dwarf.New(abbrev, nil, nil, info, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := readStructLayouts(data, []string{"task"})
	if err != nil || got["task"].Size != 24 || !maps.Equal(got["task"].Fields, map[string]uint64{"pid": 0, "stack": 16}) {
		t.Fatalf("layouts: %+v, %v", got, err)
	}
	if _, err := readStructLayouts(data, []string{"missing"}); err == nil {
		t.Fatal("missing structure was accepted")
	}
}
