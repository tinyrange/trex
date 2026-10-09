package macho

import (
	"encoding/binary"
	"testing"
)

func TestUniversalCPUSubtypeSelection(t *testing.T) {
	for _, wide := range []bool{false, true} {
		for _, order := range [][2]uint32{{3, 8}, {8, 3}} {
			b := make(source, 8192+160)
			be := binary.BigEndian.PutUint32
			width := 20
			magic := uint32(0xcafebabe)
			if wide {
				width = 32
				magic = 0xcafebabf
			}
			be(b, magic)
			be(b[4:], 2)
			for i, subtype := range order {
				a := b[8+i*width:]
				off := uint32(4096 * (i + 1))
				be(a, AMD64)
				be(a[4:], subtype)
				if wide {
					binary.BigEndian.PutUint64(a[8:], uint64(off))
					binary.BigEndian.PutUint64(a[16:], 160)
					be(a[24:], 12)
				} else {
					be(a[8:], off)
					be(a[12:], 160)
					be(a[16:], 12)
				}
				thin := fixture()
				binary.LittleEndian.PutUint32(thin[8:], subtype)
				// Distinct symbols prove we did not silently select the first CPU match.
				thin[146] = byte('0' + subtype)
				copy(b[off:], thin)
			}
			if _, err := Open(b, AMD64); err == nil {
				t.Fatal("accepted ambiguous CPU-only selection")
			}
			for _, subtype := range []uint32{3, 8} {
				img, err := OpenSubtype(b, AMD64, subtype)
				if err != nil {
					t.Fatal(err)
				}
				if img.Subtype != subtype || img.Symbols[0].Name[1] != byte('0'+subtype) {
					t.Fatalf("wrong slice: %+v", img)
				}
			}
			if _, err := OpenSubtype(b, AMD64, 4); err == nil {
				t.Fatal("accepted absent subtype")
			}
			// A directory/header mismatch must not masquerade as the requested CPU.
			binary.LittleEndian.PutUint32(b[4096+8:], 99)
			if _, err := OpenSubtype(b, AMD64, order[0]); err == nil {
				t.Fatal("accepted mismatched thin subtype")
			}
			// Two entries of the same subtype remain ambiguous.
			be(b[8+width+4:], order[0])
			if _, err := OpenSubtype(b, AMD64, order[0]); err == nil {
				t.Fatal("accepted duplicate subtype")
			}
		}
	}
	thin := fixture()
	binary.LittleEndian.PutUint32(thin[8:], 3)
	if _, err := OpenSubtype(thin, AMD64, 8); err == nil {
		t.Fatal("accepted wrong thin subtype")
	}
}
