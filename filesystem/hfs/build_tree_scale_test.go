package hfs

import (
	"testing"
)

func TestBuildTreeInstalledVolumeScale(t *testing.T) {
	// A complete original desktop volume exceeds the former 64 MiB cap once
	// thread records and free growth nodes are included. Check the on-disk
	// accounting independently, not just the leaf-enumerating format reader.
	rows := make([]treeRecord, 100000)
	data := make([]byte, 400)
	for i := range rows {
		rows[i] = treeRecord{catalogKey(uint32(i+2), nil), data}
	}
	tree, err := buildTree(rows, 516, 0xbc)
	if err != nil {
		t.Fatal(err)
	}
	if len(tree) <= 64<<20 || len(tree) > 256<<20 {
		t.Fatal("unexpected tree bound", len(tree))
	}
	h := tree[14:120]
	total, free := be.Uint32(h[22:]), be.Uint32(h[26:])
	mapOffset := int(be.Uint16(tree[treeNodeSize-6:]))
	bitmap := tree[mapOffset : treeNodeSize-8]
	var used uint32
	for id := uint32(0); id < total; id++ {
		if bitmap[id/8]&(0x80>>uint(id%8)) != 0 {
			used++
		}
	}
	if used+free != total || int(total)*treeNodeSize != len(tree) {
		t.Fatal("node map accounting", used, free, total)
	}
	var records uint32
	id := be.Uint32(h[10:])
	previous := uint32(0)
	for id != 0 {
		if id >= total || id <= previous {
			t.Fatal("leaf chain cycle or invalid node", id)
		}
		n := tree[int(id)*treeNodeSize:]
		if n[8] != 255 || n[9] != 1 || be.Uint32(n[4:]) != previous {
			t.Fatal("leaf descriptor")
		}
		records += uint32(be.Uint16(n[10:]))
		previous, id = id, be.Uint32(n)
	}
	if records != uint32(len(rows)) || previous != be.Uint32(h[14:]) {
		t.Fatal("incomplete leaf chain", records)
	}
}
