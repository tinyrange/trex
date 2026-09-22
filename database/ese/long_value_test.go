package ese

import (
	"bytes"
	"encoding/binary"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

func TestLegacyLongValueChunks(t *testing.T) {
	root := make([]byte, 8)
	binary.LittleEndian.PutUint32(root, 2)
	binary.LittleEndian.PutUint32(root[4:], 6)
	rootEntry, _ := recordLeafEntry([]byte{0, 0, 0, 7}, root)
	first, _ := recordLeafEntry([]byte{0, 0, 0, 7, 0, 0, 0, 0}, []byte("abc"))
	last, _ := recordLeafEntry([]byte{0, 0, 0, 7, 0, 0, 0, 3}, []byte("def"))
	for _, tc := range []struct {
		name    string
		entries [][]byte
		ok      bool
	}{
		{"complete", [][]byte{rootEntry, first, last}, true},
		{"missing tail", [][]byte{rootEntry, first}, false},
		{"missing root", [][]byte{first, last}, false},
		{"gap", [][]byte{rootEntry, last}, false},
		{"duplicate chunk", [][]byte{rootEntry, first, first, last}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := append([][]byte{make([]byte, 16)}, tc.entries...)
			page, err := (encodedPage{number: 1, flags: pageFlagRoot | pageFlagLeaf | pageFlagLongValue, values: values}).encode(8192)
			if err != nil {
				t.Fatal(err)
			}
			data := append(make([]byte, 2*8192), page...)
			db := &Database{source: &starfile.Bytes{Data: data}, info: Info{PageSize: 8192, Revision: 2, Version: 0x620}}
			cache := make(map[uint32][]byte)
			got, err := db.legacyLongValue(&Table{Name: "objects", longValuePage: 1}, []byte{7, 0, 0, 0}, cache)
			if (err == nil) != tc.ok {
				t.Fatalf("value=%q error=%v", got, err)
			}
			if tc.ok && (!bytes.Equal(got, []byte("abcdef")) || !bytes.Equal(cache[7], got)) {
				t.Fatalf("value=%q cache=%v", got, cache)
			}
		})
	}
}

func TestLongValueCommonKey(t *testing.T) {
	value := pageValue{flags: tagFlagCommon, data: []byte{3, 0, 5, 0, 7, 0, 0, 0, 3, 'a', 'b', 'c'}}
	key, data, err := keyedEntry(value, []byte{0, 0, 0, 1, 0, 0, 0, 0})
	if err != nil || !bytes.Equal(key, []byte{0, 0, 0, 7, 0, 0, 0, 3}) || string(data) != "abc" {
		t.Fatalf("key=%x data=%q err=%v", key, data, err)
	}
	value.data[0] = 9
	if _, _, err := keyedEntry(value, []byte{0}); err == nil {
		t.Fatal("accepted oversized common prefix")
	}
}
