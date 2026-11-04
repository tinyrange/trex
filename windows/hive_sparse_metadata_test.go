package windows

import (
	"encoding/binary"
	"testing"
)

func TestSparseDeletionRecomputesChildMaxima(t *testing.T) {
	tree := newRegistryTree("ROOT")
	ensureRegistryKeyParts(tree, []string{"a"}).class = utf16Bytes("x")
	ensureRegistryKeyParts(tree, []string{"long child name"}).class = utf16Bytes("long class")
	data, err := buildRegistryHive(tree)
	if err != nil {
		t.Fatal(err)
	}
	h := &mutableHive{data: data, childBatches: map[uint32]*hiveChildBatch{}}
	if err := h.deleteKeyParts([]string{"long child name"}); err != nil {
		t.Fatal(err)
	}
	if err := h.finishChildBatches(); err != nil {
		t.Fatal(err)
	}
	root, err := h.cellBody(binary.LittleEndian.Uint32(h.data[0x24:]))
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(root[0x34:]); got != 2 {
		t.Fatalf("name maximum = %d", got)
	}
	if got := binary.LittleEndian.Uint32(root[0x38:]); got != 2 {
		t.Fatalf("class maximum = %d", got)
	}
}
