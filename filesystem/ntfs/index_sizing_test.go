package ntfs

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// Validate layout planning against emitted records across alignment, UTF-16,
// and metadata changes. In particular a cached name must not cache file data.
func TestIndexSizingAndDirectEncoding(t *testing.T) {
	parent := &ntfsNode{id: 42, dir: true}
	node := &ntfsNode{id: 43, parent: parent, size: 12345}
	for _, value := range []string{"a", "ab", "abc", "abcd", "Ä中😀", strings.Repeat("x", 255)} {
		for _, encoded := range []bool{false, true} {
			name := newNTFSName(value, 1, parent)
			if !encoded {
				name.encoded = nil
			}
			key := &ntfsIndexKey{node: node, name: name}
			for _, sub := range []bool{false, true} {
				for _, size := range []int64{1, 8193} {
					node.size = size
					entry := ntfsIndexEntry(key, sub, 7)
					attr := ntfsFileNameAttribute(node, name)
					if len(entry) != ntfsIndexEntrySize(key, sub) || int(binary.LittleEndian.Uint16(entry[8:10])) != len(entry) {
						t.Fatal("entry layout mismatch")
					}
					if !bytes.Equal(entry[16:16+len(attr)], attr) || int64(binary.LittleEndian.Uint64(entry[64:72])) != size {
						t.Fatal("filename metadata stale or direct encoding differs")
					}
					if len(ntfsResidentAttr(ntfsAttrFileName, "", attr)) != ntfsResidentAttrSize("", ntfsFileNameSize(name)) {
						t.Fatal("resident filename planning mismatch")
					}
				}
			}
		}
	}
	name := newNTFSName("allocation-free", 1, parent)
	key := &ntfsIndexKey{node: node, name: name}
	if count := testing.AllocsPerRun(100, func() { _ = ntfsIndexEntriesSize([]*ntfsIndexKey{key}, true) }); count != 0 {
		t.Fatalf("size-only planning allocates: %v", count)
	}
}
