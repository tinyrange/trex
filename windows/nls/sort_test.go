package nls

import (
	"encoding/binary"
	"testing"
)

func TestSortKeyMatchesWindows81AppRepositoryKey(t *testing.T) {
	table := testSortTable(map[uint16]uint32{
		'C': 0x12020e0a, 'c': 0x02020e0a,
		'h': 0x02020e2c, 'e': 0x02020e21, 'k': 0x02020e36,
		'P': 0x12020e7e, 'o': 0x02020e7c, 'i': 0x02020e32,
		'n': 0x02020e70, 't': 0x02020e99,
	})
	key, err := table.SortKey("CheckPoint", 0x30401, table.guids[0].id[:])
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x0e, 0x0a, 0x0e, 0x2c, 0x0e, 0x21, 0x0e, 0x0a, 0x0e, 0x36, 0x0e, 0x7e, 0x0e, 0x7c, 0x0e, 0x32, 0x0e, 0x70, 0x0e, 0x99, 1, 1, 1, 1, 0}
	if string(key) != string(want) {
		t.Fatalf("key = %x, want %x", key, want)
	}
}

func TestParseSortDefaultRejectsBadOffsets(t *testing.T) {
	data := make([]byte, 32)
	binary.LittleEndian.PutUint32(data[0:4], 16)
	binary.LittleEndian.PutUint32(data[4:8], 12)
	if _, err := parseSortDefault(data); err == nil {
		t.Fatal("parseSortDefault accepted decreasing offsets")
	}
}

func testSortTable(weights map[uint16]uint32) *SortTable {
	data := make([]byte, baseKeyCount*4)
	for character, weight := range weights {
		binary.LittleEndian.PutUint32(data[int(character)*4:], weight)
	}
	var identifier [16]byte
	copy(identifier[:], []byte("test-sort-guid!!"))
	return &SortTable{data: data, guids: []sortGUID{{id: identifier}}}
}
