package dmr

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestFixedSectionsGolden(t *testing.T) {
	want, err := hex.DecodeString("54504c5400000000000000000300000088776655443322110400030002000100")
	if err != nil {
		t.Fatal(err)
	}
	p := TargetPlatform{Platform: 3, Value16: 0x1122334455667788, Value24: 0x0001000200030004}
	if got := EncodeTargetPlatform(p); !bytes.Equal(got, want) {
		t.Fatalf("TPLT: %x", got)
	}
	got, err := ParseTargetPlatform(want)
	if err != nil || got != p {
		t.Fatalf("TPLT: %#v, %v", got, err)
	}
	trailer := []byte{'J', 'H', 'N', '8', 0, 0, 0, 0}
	if !bytes.Equal(EncodeTrailer(), trailer) {
		t.Fatal("trailer mismatch")
	}
	if err := ParseTrailer(trailer); err != nil {
		t.Fatal(err)
	}
	container, err := EncodeContainer([]Section{{TargetPlatformTag, want}, {TrailerTag, trailer}})
	if err != nil {
		t.Fatal(err)
	}
	sections, err := ParseContainer(container)
	if err != nil || len(sections) != 2 {
		t.Fatalf("container: %v", err)
	}
	if !bytes.Equal(sections[0].Data, want) || !bytes.Equal(sections[1].Data, trailer) {
		t.Fatal("container extent mismatch")
	}
}

func TestFixedSectionsMalformed(t *testing.T) {
	for _, size := range []int{0, 1, 7, 8, 16, 31, 33} {
		if _, err := ParseTargetPlatform(make([]byte, size)); err == nil {
			t.Fatalf("accepted TPLT size %d", size)
		}
	}
	for _, offset := range []int{0, 4, 7, 8, 11} {
		b := EncodeTargetPlatform(TargetPlatform{})
		b[offset] ^= 1
		if _, err := ParseTargetPlatform(b); err == nil {
			t.Fatalf("accepted TPLT mutation %d", offset)
		}
	}
	for i := 0; i < 8; i++ {
		b := EncodeTrailer()
		b[i] ^= 1
		if err := ParseTrailer(b); err == nil {
			t.Fatalf("accepted trailer mutation %d", i)
		}
		if err := ParseTrailer(EncodeTrailer()[:i]); err == nil {
			t.Fatalf("accepted trailer truncation %d", i)
		}
	}
	if err := ParseTrailer(append(EncodeTrailer(), 0)); err == nil {
		t.Fatal("accepted trailing byte")
	}
}
