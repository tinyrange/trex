package ntfs

import (
	"encoding/binary"
	"strings"
	"testing"
)

// Planning precedes cluster allocation. Any record accepted by the planner
// must still serialize when its data runs land beyond a one-byte LCN.
func TestNTFSRecordCapacityAfterAllocation(t *testing.T) {
	b := &ntfsBuild{versionMajor: 3, versionMinor: 1}
	parent := &ntfsNode{id: 16, dir: true}
	checked := 0
	for _, lcn := range []int64{1, 1 << 16, 1 << 32, 1 << 56} {
		for length := 1; length <= 255; length++ {
			node := &ntfsNode{id: 17, size: 1 << 24, lcn: lcn, eaInfo: make([]byte, 8), eaData: make([]byte, 104)}
			node.names = []ntfsName{newNTFSName("LONGNA~1.DLL", 2, parent), newNTFSName(strings.Repeat("x", length), 1, parent), newNTFSName(strings.Repeat("y", length), 0, parent)}
			planned := ntfsNodeRecordSize(node, node.names, false)
			if planned > int(ntfsRecordSize) {
				continue
			}
			record, err := b.mftRecord(node)
			if err != nil {
				t.Fatalf("LCN %x name length %d, planned %d: %v", lcn, length, planned, err)
			}
			if actual := int(binary.LittleEndian.Uint32(record[24:28])); actual > planned {
				t.Fatalf("LCN %x: actual %d exceeds planned %d", lcn, actual, planned)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no fitting records checked")
	}
}
