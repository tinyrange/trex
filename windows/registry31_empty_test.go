package windows

import (
	"encoding/binary"
	"testing"
)

// Original Regedit can create a valid empty SHCC database before any import.
func TestRegistry31ReadEmptyReachableTree(t *testing.T) {
	data := registry31ReadFixture()
	binary.LittleEndian.PutUint16(data[50:], 0)
	got, err := readRegistry31(data)
	if err != nil || len(got) != 0 {
		t.Fatalf("empty database=%v err=%v", got, err)
	}
}
