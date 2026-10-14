package apfs

import (
	"bytes"
	"testing"
)

func TestCanonicalSealedTreeRoundTripAndFreedSeparators(t *testing.T) {
	var records []Record
	for i := uint64(0); i < 17000; i++ {
		key := le.AppendUint64(fsKey(1000+i/128, 13), 1<<56|(i%128)*4096)
		value := make([]byte, 35)
		le.PutUint16(value, 1)
		value[2] = 32
		le.PutUint64(value[3:], i)
		records = append(records, Record{key, value})
	}
	tree, err := EncodeSealedTree(records, 4096, 1)
	if err != nil {
		t.Fatal(err)
	}
	c := &Container{Source: tree.File, BlockSize: 4096, Blocks: tree.Nodes}
	count := 0
	err = c.walkTreeHash(0, nil, 1, tree.RootHash, func(k, v []byte) error {
		if count >= len(records) || !bytes.Equal(k, records[count].Key) || !bytes.Equal(v, records[count].Value) {
			t.Fatalf("record %d changed", count)
		}
		count++
		return nil
	})
	if err != nil || count != len(records) {
		t.Fatalf("count=%d err=%v", count, err)
	}
	freed := false
	for i := uint64(1); i < tree.Nodes; i++ {
		b, e := c.raw(i)
		if e != nil {
			t.Fatal(e)
		}
		if le.Uint16(b[34:]) != 1 || le.Uint16(b[50:]) == 0 {
			continue
		}
		freed = true
		if le.Uint16(b[50:]) != 16 || le.Uint16(b[54:]) != 40 {
			t.Fatal("freed separator sizes")
		}
		key := 56 + int(le.Uint16(b[42:])) + int(le.Uint16(b[48:]))
		value := 4096 - int(le.Uint16(b[52:]))
		if le.Uint16(b[key:]) != 65535 || le.Uint16(b[key+2:]) != 16 || le.Uint16(b[value:]) != 65535 || le.Uint16(b[value+2:]) != 40 || !bytes.Equal(b[value+8:value+40], make([]byte, 32)) {
			t.Fatal("freed insertion placeholder changed")
		}
	}
	if !freed {
		t.Fatal("missing closed interior node control")
	}
}

func TestCanonicalSealedTreeGeometryAndInputBounds(t *testing.T) {
	for _, r := range [][]Record{nil, {{[]byte{1}, []byte{1}}}, {{make([]byte, 8), nil}}, {{make([]byte, 8), make([]byte, 4096)}}} {
		if _, err := EncodeSealedTree(r, 4096, 1); err == nil {
			t.Fatal("accepted invalid record")
		}
	}
	for _, size := range []uint32{0, 4097, 131072} {
		if _, err := EncodeSealedTree([]Record{{make([]byte, 8), []byte{1}}}, size, 1); err == nil {
			t.Fatal("accepted invalid node size")
		}
	}
}

func TestSealedTreeFirstRecordReservesRootFooter(t *testing.T) {
	// A root has 40 fewer available bytes than an ordinary leaf. A first
	// record fitting only the latter cannot be split into two nonempty nodes.
	for _, size := range []int{3928, 3929, 3968} {
		_, err := EncodeSealedTree([]Record{{make([]byte, 8), make([]byte, size)}}, 4096, 1)
		if (err == nil) != (size == 3928) {
			t.Fatalf("value size %d: %v", size, err)
		}
	}
}

func TestSealedTreeDefersParentSplitUntilChildNeedsSeparator(t *testing.T) {
	// Each leaf holds 67 records. Creating leaf 61 leaves the root with
	// 72 bytes free. Its two-separator reservation fails, but the child can
	// still accept records. Grow only when that child needs another leaf.
	var records []Record
	for i := uint64(0); i < 4088; i++ {
		key := le.AppendUint64(fsKey(1000, 13), 1<<56|i*4096)
		value := make([]byte, 35)
		le.PutUint16(value, 1)
		value[2] = 32
		records = append(records, Record{key, value})
	}
	before, err := EncodeSealedTree(records[:4022], 4096, 1)
	if err != nil {
		t.Fatal(err)
	}
	beforeRoot := make([]byte, 4096)
	if _, err := before.File.ReadAt(beforeRoot, 0); err != nil {
		t.Fatal(err)
	}
	if before.Nodes != 62 || le.Uint16(beforeRoot[34:]) != 1 || le.Uint32(beforeRoot[36:]) != 61 {
		t.Fatal("parent split despite space in its child")
	}
	tree, err := EncodeSealedTree(records, 4096, 1)
	if err != nil {
		t.Fatal(err)
	}
	c := &Container{Source: tree.File, BlockSize: 4096, Blocks: tree.Nodes}
	root, err := c.raw(0)
	if err != nil {
		t.Fatal(err)
	}
	if tree.Nodes != 65 || le.Uint16(root[34:]) != 2 || le.Uint32(root[36:]) != 2 {
		t.Fatalf("nodes=%d root level=%d keys=%d", tree.Nodes, le.Uint16(root[34:]), le.Uint32(root[36:]))
	}
	leftID := le.Uint64(root[4096-40-int(le.Uint16(root[60:])):])
	rightID := le.Uint64(root[4096-40-int(le.Uint16(root[68:])):])
	left, _ := c.raw(leftID)
	right, _ := c.raw(rightID)
	if leftID != 63 || rightID != 62 || le.Uint32(left[36:]) != 60 || le.Uint32(right[36:]) != 2 {
		t.Fatalf("left=%d/%d right=%d/%d", leftID, le.Uint32(left[36:]), rightID, le.Uint32(right[36:]))
	}
}
