package rpa

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func putList(b []byte, at int, next uint64, entries ...Extent) {
	binary.BigEndian.PutUint32(b[at:], 0x01010000)
	binary.BigEndian.PutUint32(b[at+4:], uint32(16+len(entries)*16))
	binary.BigEndian.PutUint64(b[at+8:], next)
	for i, e := range entries {
		binary.BigEndian.PutUint64(b[at+16+i*16:], e.Address)
		binary.BigEndian.PutUint64(b[at+24+i*16:], e.Size)
	}
}

func TestChainedAbsoluteBlockLists(t *testing.T) {
	b := make([]byte, 4096)
	putList(b, 32, 0x8000000000000080, Extent{Address: 0x8000000000000200, Size: 3})
	putList(b, 128, 0, Extent{Address: 0x8000000000000300, Size: 5})
	before := bytes.Clone(b)
	list, err := ReadBlockList(bytes.NewReader(b), 0x8000000000000020, 8)
	if err != nil || list.Capacity != 8 || len(list.Entries) != 2 || list.Entries[0].Real != 512 || list.Entries[1].Size != 5 {
		t.Fatal(list, err)
	}
	if !bytes.Equal(before, b) {
		t.Fatal("inspection changed memory")
	}
}

func TestInvalidBlockListsReturnNoTargets(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func([]byte)
		budget uint64
	}{
		{"version", func(b []byte) { b[32] = 0 }, 8},
		{"format", func(b []byte) { b[35] = 1 }, 8},
		{"short", func(b []byte) { binary.BigEndian.PutUint32(b[36:], 15) }, 8},
		{"unaligned size", func(b []byte) { binary.BigEndian.PutUint32(b[36:], 31) }, 8},
		{"oversized", func(b []byte) { binary.BigEndian.PutUint32(b[36:], 4112) }, 8},
		{"cycle", func(b []byte) { binary.BigEndian.PutUint64(b[40:], 0x8000000000000020) }, 8},
		{"bad target", func(b []byte) { binary.BigEndian.PutUint64(b[48:], 0x8000000000000fff) }, 8},
		{"virtual target", func(b []byte) { binary.BigEndian.PutUint64(b[48:], 0xb000000000000200) }, 8},
		{"header overlap", func(b []byte) { binary.BigEndian.PutUint64(b[48:], 0x8000000000000020) }, 8},
		{"zero target length", func(b []byte) { binary.BigEndian.PutUint64(b[56:], 0) }, 8},
		{"budget", func([]byte) {}, 2},
		{"bad later block", func(b []byte) { binary.BigEndian.PutUint64(b[40:], 0x8000000000000fff) }, 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := make([]byte, 4096)
			putList(b, 32, 0, Extent{Address: 0x8000000000000200, Size: 3})
			tc.change(b)
			before := bytes.Clone(b)
			list, err := ReadBlockList(bytes.NewReader(b), 0x8000000000000020, tc.budget)
			if err == nil || list != nil || !bytes.Equal(before, b) {
				t.Fatal(list, err)
			}
		})
	}
}
