package hfs

import (
	"bytes"
	"testing"
)

func TestBuildTreeLargeCatalogGrowthReserve(t *testing.T) {
	// More than half of the bounded metadata space is populated, as in the
	// complete Yosemite catalog. A doubled optional reserve must not fail it.
	data := make([]byte, 4096)
	records := make([]treeRecord, 16400)
	for i := range records {
		key := make([]byte, 8)
		be.PutUint16(key, 6)
		be.PutUint32(key[2:], uint32(i+1))
		records[i] = treeRecord{key, data}
	}
	tree, err := buildTree(records, 6, 0xbc)
	if err != nil {
		t.Fatal(err)
	}
	header := tree[14:120]
	total, free := be.Uint32(header[22:]), be.Uint32(header[26:])
	if len(tree) != 256<<20 || uint64(total)*treeNodeSize != uint64(len(tree)) || free < 8 {
		t.Fatal("metadata bound or guest growth reserve lost")
	}
	bitmap := tree[14+106+128 : treeNodeSize-8]
	var occupied uint32
	for i := uint32(0); i < total; i++ {
		if bitmap[i/8]&(0x80>>(i%8)) != 0 {
			occupied++
		}
	}
	if occupied+free != total {
		t.Fatal("header free count disagrees with node bitmap")
	}
	first, last := be.Uint32(header[10:]), be.Uint32(header[14:])
	for _, id := range []uint32{first, last} {
		node := tree[int(id)*treeNodeSize : int(id+1)*treeNodeSize]
		if node[8] != 255 || node[9] != 1 || be.Uint16(node[10:]) != 1 {
			t.Fatal("large catalog leaf geometry invalid")
		}
	}
	lastLeaf := tree[int(last)*treeNodeSize : int(last+1)*treeNodeSize]
	if !bytes.Equal(lastLeaf[14:22], records[len(records)-1].key) || be.Uint32(lastLeaf) != 0 {
		t.Fatal("large catalog final record or leaf link lost")
	}
	// The populated metadata itself still cannot exceed the same bound.
	records = append(records, make([]treeRecord, 16400)...)
	for i := 16400; i < len(records); i++ {
		records[i] = records[i-16400]
	}
	if _, err := buildTree(records, 6, 0xbc); err == nil {
		t.Fatal("accepted populated tree exceeding metadata ceiling")
	}
}
