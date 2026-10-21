package bom

import (
	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func fixture(branch bool) []byte { return variantFixture(branch, false, false) }
func variantFixture(branch, variants, tail bool) []byte {
	b := make([]byte, 32)
	pointers := []pointer{{}}
	add := func(data []byte) uint32 {
		id := uint32(len(pointers))
		pointers = append(pointers, pointer{uint32(len(b)), uint32(len(data))})
		b = append(b, data...)
		return id
	}
	var pairs [][2]uint32
	names := []string{".", "hello", "link"}
	if variants {
		names = append(names, "hello")
	}
	for i, name := range names {
		meta := make([]byte, 27)
		meta[0] = 1
		if i == 0 {
			meta = meta[:23]
			meta[0] = 2
		}
		if i == 2 {
			meta = make([]byte, 37)
			meta[0] = 3
			be.PutUint32(meta[27:], 6)
			copy(meta[31:], "hello")
		}
		be.PutUint16(meta[2:], uint16(i))
		be.PutUint16(meta[4:], 0644)
		be.PutUint32(meta[6:], 501)
		be.PutUint32(meta[18:], 17)
		mid := add(meta)
		info := make([]byte, 8)
		be.PutUint32(info, uint32(i+1))
		be.PutUint32(info[4:], mid)
		iid := add(info)
		key := make([]byte, 4)
		if i > 0 {
			be.PutUint32(key, 1)
		}
		key = append(key, []byte(name)...)
		key = append(key, 0)
		kid := add(key)
		pairs = append(pairs, [2]uint32{iid, kid})
	}
	allPairs := pairs
	if tail {
		pairs = pairs[:len(pairs)-1]
	}
	leaf := make([]byte, 12+8*len(pairs))
	be.PutUint16(leaf, 1)
	be.PutUint16(leaf[2:], uint16(len(pairs)))
	for i, p := range pairs {
		be.PutUint32(leaf[12+i*8:], p[0])
		be.PutUint32(leaf[16+i*8:], p[1])
	}
	child := add(leaf)
	count := uint32(len(allPairs))
	if tail {
		last := allPairs[len(allPairs)-1]
		node := make([]byte, 20)
		be.PutUint16(node, 1)
		be.PutUint16(node[2:], 1)
		be.PutUint32(node[8:], child)
		be.PutUint32(node[12:], last[0])
		be.PutUint32(node[16:], last[1])
		next := add(node)
		be.PutUint32(b[pointers[child].off+4:], next)
	}
	if branch {
		node := make([]byte, 20)
		be.PutUint16(node[2:], 1)
		be.PutUint32(node[12:], child)
		child = add(node)
		count++
	}
	tree := make([]byte, 21)
	copy(tree, "tree")
	be.PutUint32(tree[4:], 1)
	be.PutUint32(tree[8:], child)
	be.PutUint32(tree[12:], 4096)
	be.PutUint32(tree[16:], count)
	tid := add(tree)
	vars := make([]byte, 9)
	be.PutUint32(vars, 1)
	be.PutUint32(vars[4:], tid)
	vars[8] = 5
	vars = append(vars, []byte("Paths")...)
	voff := len(b)
	b = append(b, vars...)
	ioff := len(b)
	index := make([]byte, 4+8*len(pointers))
	be.PutUint32(index, uint32(len(pointers)))
	for i, p := range pointers {
		be.PutUint32(index[4+i*8:], p.off)
		be.PutUint32(index[8+i*8:], p.length)
	}
	b = append(b, index...)
	copy(b, "BOMStore")
	be.PutUint32(b[8:], 1)
	be.PutUint32(b[12:], uint32(len(pointers)-1))
	be.PutUint32(b[16:], uint32(ioff))
	be.PutUint32(b[20:], uint32(len(index)))
	be.PutUint32(b[24:], uint32(voff))
	be.PutUint32(b[28:], uint32(len(vars)))
	return b
}
func TestInventoryIsMetadataOnly(t *testing.T) {
	for _, branch := range []bool{false, true} {
		b := fixture(branch)
		root := auto.Open(&starfile.Bytes{Data: b}, "Archive.bom", auto.Options{})
		n, err := root.Resolve("hello")
		if err != nil {
			t.Fatal(err)
		}
		m := n.Summary()
		if m.Readable || m.Attributes["size"] != uint32(17) || m.Attributes["uid"] != uint32(501) || m.Attributes["missing_contents"] != true {
			t.Fatalf("%+v", m)
		}
		n, err = root.Resolve("link")
		if err != nil {
			t.Fatal(err)
		}
		if n.Reader() != nil || n.Summary().Attributes["target"] != "hello" {
			t.Fatal(n.Summary())
		}
	}
}
func TestMalformedBOM(t *testing.T) {
	for _, mutate := range []func([]byte){
		func(b []byte) { be.PutUint32(b[16:], uint32(len(b))) },
		func(b []byte) { off := be.Uint32(b[16:]); be.PutUint32(b[off+4+8:], uint32(len(b))) },
		func(b []byte) { off := be.Uint32(b[16:]); key := be.Uint32(b[off+4+6*8:]); be.PutUint32(b[key:], 2) }, // self-parent of file
		func(b []byte) {
			off := be.Uint32(b[16:])
			node := be.Uint32(b[off+4+11*8:])
			be.PutUint32(b[node+12:], 11)
		}, // branch cycle
	} {
		b := fixture(true)
		mutate(b)
		if _, err := Open(b, &starfile.Bytes{Data: b}, auto.Options{}); err == nil {
			t.Fatal("accepted malformed BOM")
		}
	}
}

func TestTrailingLeafAndArchitectureVariants(t *testing.T) {
	for _, tail := range []bool{false, true} {
		b := variantFixture(true, true, tail)
		records, err := Read(&starfile.Bytes{Data: b}, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(records) != 4 {
			t.Fatalf("dropped records: %d", len(records))
		}
		var variants int
		for _, e := range records {
			if e.Name == "hello" {
				variants++
			}
		}
		if variants != 2 {
			t.Fatal("architecture variants lost")
		}
		root := auto.Open(&starfile.Bytes{Data: b}, "Bom", auto.Options{})
		n, err := root.Resolve("%00bom-variants/4")
		if err != nil || n.Summary().Attributes["bom_path"] != "hello" {
			t.Fatalf("variant tree %v %v", n, err)
		}
		if tail {
			// The partial final leaf must point back to its predecessor.
			index := be.Uint32(b[16:])
			last := be.Uint32(b[index+4+14*8:]) // leaf after four sets of metadata blocks
			be.PutUint32(b[last+8:], 0)
			if _, err := Read(&starfile.Bytes{Data: b}, 100); err == nil {
				t.Fatal("accepted disconnected leaf chain")
			}
		}
	}
}
