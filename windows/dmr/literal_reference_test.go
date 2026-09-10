package dmr

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestLiteralReferenceGolden(t *testing.T) {
	for _, tc := range []struct{ value, wire string }{
		{"", "00010c000000020000000000"},
		{"AB", "00011000000006004100420000000000"},
	} {
		want, err := hex.DecodeString(tc.wire)
		if err != nil {
			t.Fatal(err)
		}
		got, err := EncodeLiteralResourceReference(tc.value)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("encoded %x: %v", got, err)
		}
		parsed, err := ParseLiteralResourceReference(want)
		if err != nil || parsed != tc.value {
			t.Fatalf("parsed %q: %v", parsed, err)
		}
	}
}

func TestLiteralReferenceMalformed(t *testing.T) {
	for _, tc := range []struct {
		offset int
		value  uint16
	}{
		{0, 0}, {0, 0x400}, {0, 0x101}, {2, 12}, {4, 1}, {6, 0},
		{6, 5}, {6, 65534}, {8, 0xd800}, {12, 1}, {14, 1},
	} {
		b, err := EncodeLiteralResourceReference("AB")
		if err != nil {
			t.Fatal(err)
		}
		le.PutUint16(b[tc.offset:], tc.value)
		if _, err := ParseLiteralResourceReference(b); err == nil {
			t.Fatalf("accepted mutation %d/%x", tc.offset, tc.value)
		}
	}
	b, _ := EncodeLiteralResourceReference("AB")
	for i := range b {
		if _, err := ParseLiteralResourceReference(b[:i]); err == nil {
			t.Fatalf("accepted truncation %d", i)
		}
	}
}

func TestLiteralReferenceLimits(t *testing.T) {
	for _, value := range []string{"名前😀", strings.Repeat("a", 4091)} {
		b, err := EncodeLiteralResourceReference(value)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseLiteralResourceReference(b)
		if err != nil || got != value {
			t.Fatalf("round trip: %v", err)
		}
	}
	for _, value := range []string{strings.Repeat("a", 4092), "a\x00b", "\xff"} {
		if _, err := EncodeLiteralResourceReference(value); err == nil {
			t.Fatal("accepted invalid literal")
		}
	}
}

func FuzzLiteralReference(f *testing.F) {
	for _, value := range []string{"", "AB"} {
		b, err := EncodeLiteralResourceReference(value)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		value, err := ParseLiteralResourceReference(data)
		if err != nil {
			return
		}
		b, err := EncodeLiteralResourceReference(value)
		if err != nil || !bytes.Equal(b, data) {
			t.Fatalf("round trip: %v", err)
		}
	})
}
