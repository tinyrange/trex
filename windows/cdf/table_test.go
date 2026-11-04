package cdf

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestNativeTables(t *testing.T) {
	d, e := Parse(nativeRoot(t))
	if e != nil {
		t.Fatal(e)
	}
	for _, id := range []int{1, 3} {
		b := d.Blobs[id]
		table, e := ParseTable(b.Kind, b.Data)
		if e != nil {
			t.Fatal(e)
		}
		if id == 1 && (len(table.Keys) != 1 || table.Hashes[0] != 0xffff7d02 || table.Keys[0] != 0 || table.Values[0] != 0) {
			t.Fatalf("native dot table %+v", table)
		}
		if id == 3 && (len(table.Keys) != 2 || table.Keys[0] != 0 || table.Keys[1] != 1 || table.Values[0] != 1 || table.Values[1] != 2) {
			t.Fatalf("native TOC %+v", table)
		}
		out, e := table.Marshal()
		if e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(out, b.Data) {
			t.Fatal("native table bytes changed")
		}
		for n := 0; n < len(out); n++ {
			if _, e := ParseTable(b.Kind, out[:n]); e == nil {
				t.Fatalf("accepted truncation %d", n)
			}
		}
	}
}

func TestTableCollisionsAndBounds(t *testing.T) {
	table := &Table{Kind: 6, Hashes: []uint32{7, 7}, Keys: []uint32{12, 9}, Values: []uint32{3, 4}}
	data, e := table.Marshal()
	if e != nil {
		t.Fatal(e)
	}
	got, e := ParseTable(6, data)
	if e != nil {
		t.Fatal(e)
	}
	if got.Keys[0] != 12 || got.Keys[1] != 9 {
		t.Fatal("collision order changed")
	}
	bad := append([]byte{}, data...)
	binary.LittleEndian.PutUint32(bad, 0xffffff01)
	if _, e := ParseTable(6, bad); e == nil {
		t.Fatal("accepted oversized count")
	}
	bad = append([]byte{}, data...)
	bad[0] = 0x11
	if _, e := ParseTable(6, bad); e == nil {
		t.Fatal("guessed compact key layout")
	}
	table.Hashes[1] = 6
	if _, e := table.Marshal(); e == nil {
		t.Fatal("accepted unordered hashes")
	}
	table.Hashes[1] = 7
	table.Keys[1] = 12
	if _, e := table.Marshal(); e == nil {
		t.Fatal("accepted duplicate key IDs")
	}
}
