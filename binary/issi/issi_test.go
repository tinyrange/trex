package issi

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestPointerTagsDistinguishAddressFromBitmap(t *testing.T) {
	var h [HeaderBytes]byte
	// An unmarked (untagged) sector carries part of the page address where
	// a tagged sector stores its bitmap.
	binary.BigEndian.PutUint64(h[32:40], 0x73f5020567003d10)
	binary.BigEndian.PutUint64(h[56:64], 0x5ff5008000000118)
	var want [32]byte
	want[28], want[31] = 0x80, 1
	if tags := PointerTags(&h); tags != want {
		t.Fatalf("pointer tags %x, want %x", tags, want)
	}
}

func TestSectorFramingRoundTripAndReceivedControls(t *testing.T) {
	page := make([]byte, 4096)
	for i := range page {
		page[i] = byte(i*17 + i/512)
	}
	headers := make([]byte, 64)
	for i := range headers {
		headers[i] = byte(i + 1)
	}
	original, originalHeaders := bytes.Clone(page), bytes.Clone(headers)
	sidecar := bytes.Repeat([]byte{0xa5}, 512)
	if err := Save(sidecar, headers, page); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(page, original) || !bytes.Equal(headers, originalHeaders) || !bytes.Equal(sidecar[8:72], headers) {
		t.Fatal("save mutated source or lost headers")
	}
	for i := 0; i < 8; i++ {
		if !bytes.Equal(sidecar[72+i*8:80+i*8], original[i*512+504:(i+1)*512]) {
			t.Fatal("lost tail", i)
		}
	}
	stamp := uint64(0x123456789abcdef0)
	if err := Stamp(sidecar, page, stamp); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if binary.BigEndian.Uint64(page[i*512+504:]) != stamp || !bytes.Equal(page[i*512:i*512+504], original[i*512:i*512+504]) {
			t.Fatal("stamp", i)
		}
	}
	if binary.BigEndian.Uint64(sidecar) != stamp || binary.BigEndian.Uint64(sidecar[504:]) != stamp || sidecar[200] != 0xa5 {
		t.Fatal("sidecar control or reserved bytes")
	}
	// A mismatching received control is preserved for the consumer's validation.
	binary.BigEndian.PutUint64(page[3*512+504:], stamp^1)
	clear(headers)
	if err := Restore(sidecar, headers, page, true); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(page, original) || !bytes.Equal(headers, originalHeaders) {
		t.Fatal("round trip")
	}
	for i := 0; i < 8; i++ {
		want := stamp
		if i == 3 {
			want ^= 1
		}
		if binary.BigEndian.Uint64(sidecar[136+i*8:]) != want {
			t.Fatal("received control", i)
		}
	}
}

func TestInvalidBuffersAreAtomic(t *testing.T) {
	for _, sizes := range [][3]int{{511, 64, 4096}, {512, 63, 4096}, {512, 64, 4095}} {
		a, b, c := make([]byte, sizes[0]), make([]byte, sizes[1]), make([]byte, sizes[2])
		if Save(a, b, c) == nil || Restore(a, b, c, true) == nil {
			t.Fatal("accepted lengths", sizes)
		}
	}
	a, b := bytes.Repeat([]byte{0xaa}, 512), bytes.Repeat([]byte{0xbb}, 4096)
	if Stamp(a, b, 0) == nil || a[0] != 0xaa || b[504] != 0xbb {
		t.Fatal("zero stamp mutated buffers")
	}
}
