package dmr

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestIndexReference(t *testing.T) {
	for _, tc := range []struct {
		index uint32
		wire  string
	}{
		{0, "00040c000000040000000000"},
		{0x12345678, "00040c000000040078563412"},
		{0x7fffffff, "00040c0000000400ffffff7f"},
	} {
		want, err := hex.DecodeString(tc.wire)
		if err != nil {
			t.Fatal(err)
		}
		got, err := EncodeIndexResourceReference(tc.index)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("encode: %x %v", got, err)
		}
		index, err := ParseIndexResourceReference(want)
		if err != nil || index != tc.index {
			t.Fatalf("parse: %x %v", index, err)
		}
	}
	for _, index := range []uint32{0x80000000, 0xffffffff} {
		if _, err := EncodeIndexResourceReference(index); err == nil {
			t.Fatal("accepted invalid index")
		}
	}
}

func TestIndexReferenceMalformed(t *testing.T) {
	b, _ := EncodeIndexResourceReference(0)
	for i := 0; i < 12; i++ {
		if _, err := ParseIndexResourceReference(b[:i]); err == nil {
			t.Fatalf("accepted truncation %d", i)
		}
	}
	for _, offset := range []int{0, 1, 2, 3, 4, 5, 6, 7} {
		bad := bytes.Clone(b)
		bad[offset] ^= 1
		if _, err := ParseIndexResourceReference(bad); err == nil {
			t.Fatalf("accepted header mutation %d", offset)
		}
	}
	b[11] = 0x80
	if _, err := ParseIndexResourceReference(b); err == nil {
		t.Fatal("accepted negative index")
	}
	b[11] = 0
	if _, err := ParseIndexResourceReference(append(b, 0)); err == nil {
		t.Fatal("accepted trailing byte")
	}
}
