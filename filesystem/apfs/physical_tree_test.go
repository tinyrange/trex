package apfs

import (
	"bytes"
	"fmt"
	"testing"
)

func TestPhysicalTreeNoncontiguousPlacementAndLevels(t *testing.T) {
	for _, size := range []uint32{4096, 8192, 16384, 65536} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			rows := make([]Record, 18000)
			for i := range rows {
				rows[i] = Record{le.AppendUint64(le.AppendUint64(nil, uint64(i/3)), uint64(i%3)), le.AppendUint64(le.AppendUint64(nil, uint64(i)), uint64(i*2))}
			}
			disk := make([]byte, 4<<20)
			next := uint64(0)
			allocate := func() (uint64, error) { next += 2; return next, nil }
			write := func(pa uint64, b []byte) error { copy(disk[pa*uint64(size):], b); return nil }
			root, nodes, err := encodePhysicalTree(rows, size, 11, 18, allocate, write)
			if err != nil || nodes < 2 || root != next {
				t.Fatalf("root=%d nodes=%d err=%v", root, nodes, err)
			}
			c := &Container{Source: bytes.NewReader(disk), BlockSize: size, Blocks: uint64(len(disk)) / uint64(size)}
			seen := 0
			err = c.walkTree(root, nil, func(k, v []byte) error {
				if seen >= len(rows) || !bytes.Equal(k, rows[seen].Key) || !bytes.Equal(v, rows[seen].Value) {
					return fmt.Errorf("record %d differs", seen)
				}
				seen++
				return nil
			})
			if err != nil || seen != len(rows) {
				t.Fatalf("records=%d err=%v", seen, err)
			}
			for pa := uint64(2); pa <= next; pa += 2 {
				b, _ := c.raw(pa)
				if le.Uint64(b[8:]) != pa || le.Uint64(b[16:]) != 18 || le.Uint32(b[28:]) != 11 {
					t.Fatal("object identity or subtype")
				}
				if pa == root && le.Uint32(b[len(b)-40:]) != 0x10 {
					t.Fatal("physical tree footer must not advertise uint64-only keys")
				}
				if size == 4096 {
					want := uint16(448)
					if le.Uint16(b[34:]) != 0 {
						want = 576
					}
					if le.Uint16(b[42:]) != want {
						t.Fatal("fixed ToC must retain all slots, including unused entries")
					}
				}
			}
		})
	}
}

func TestPhysicalTreeEmptyAndInvalidInputs(t *testing.T) {
	var output []byte
	alloc := func() (uint64, error) { return 0, nil }
	write := func(_ uint64, b []byte) error { output = b; return nil }
	root, nodes, err := encodePhysicalTree(nil, 4096, 31, 18, alloc, write)
	if err != nil || root != 0 || nodes != 1 || le.Uint32(output[36:]) != 0 || verify(output) != nil {
		t.Fatalf("empty tree: root=%d nodes=%d err=%v", root, nodes, err)
	}
	if le.Uint16(output[42:]) != 448 {
		t.Fatal("empty fixed tree must retain its full ToC")
	}
	r := Record{make([]byte, 16), make([]byte, 16)}
	for _, rows := range [][]Record{{r, r}, {{make([]byte, 8), r.Value}}, {{r.Key, make([]byte, 8)}}} {
		if _, _, err := encodePhysicalTree(rows, 4096, 11, 18, alloc, write); err == nil {
			t.Fatal("accepted invalid physical records")
		}
	}
	rows := make([]Record, 120)
	for i := range rows {
		rows[i] = Record{le.AppendUint64(le.AppendUint64(nil, uint64(i)), 0), r.Value}
	}
	if _, _, err := encodePhysicalTree(rows, 4096, 11, 18, alloc, write); err == nil {
		t.Fatal("accepted repeated allocated block")
	}
}
