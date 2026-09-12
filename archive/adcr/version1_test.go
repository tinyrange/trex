package adcr

import (
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func version1Fixture(payload []byte, target int, stored bool) []byte {
	b := make([]byte, 16)
	copy(b, "ADCR")
	binary.BigEndian.PutUint32(b[4:], 1<<24|uint32(target))
	if stored {
		b[8] = 1
	}
	binary.BigEndian.PutUint32(b[12:], uint32(len(payload)))
	return append(b, payload...)
}

func TestVersion1Phrases(t *testing.T) {
	// Literal AAA inserts bucket1/slot0. The following match copies it,
	// including overlap, and updates the two pending literal positions.
	b := version1Fixture([]byte{8, 0, 'A', 'A', 'A', 0x13, 0}, 9, false)
	f, err := Open(&starfile.Bytes{Data: b}, nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	got, err := starfile.ReadAll(f)
	if err != nil || string(got) != "AAAAAAAAA" {
		t.Fatal(string(got), err)
	}
	for _, n := range []int{0, 8, 15, len(b) - 1} {
		if _, err := Open(&starfile.Bytes{Data: b[:n]}, nil, 100); err == nil {
			t.Fatal("accepted truncation", n)
		}
	}
	if _, err := Open(&starfile.Bytes{Data: b}, nil, 8); err == nil {
		t.Fatal("accepted limit")
	}
}

func TestVersion1SeedAndFraming(t *testing.T) {
	b := version1Fixture([]byte{1, 0, 0, 0}, 3, false)
	if _, err := Open(&starfile.Bytes{Data: b}, nil, 100); err == nil {
		t.Fatal("invented seed")
	}
	f, err := Open(&starfile.Bytes{Data: b}, &starfile.Bytes{Data: []byte("abcEXTRA")}, 100)
	if err != nil {
		t.Fatal(err)
	}
	got, err := starfile.ReadAll(f)
	if err != nil || string(got) != "abc" {
		t.Fatal(string(got), err)
	}
	b = version1Fixture([]byte("raw"), 3, true)
	if _, err = Open(&starfile.Bytes{Data: b}, nil, 100); err == nil {
		t.Fatal("accepted unobserved framing flag")
	}
	b[8] = 0
	b[15]++
	if _, err = Open(&starfile.Bytes{Data: b}, nil, 100); err == nil {
		t.Fatal("accepted stored length mismatch")
	}
}

func FuzzVersion1Bounded(f *testing.F) {
	f.Add([]byte{8, 0, 'A', 'A', 'A', 0x13, 0}, uint16(9))
	f.Fuzz(func(t *testing.T, b []byte, n uint16) {
		if len(b) > 4096 {
			return
		}
		out, err := decodeVersion1Stream(b, []byte("abcdefghijklmnopqr"), int(n%4096))
		if err == nil && len(out) != int(n%4096) {
			t.Fatal("wrong size")
		}
	})
}
