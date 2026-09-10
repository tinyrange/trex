package dmr

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestAlternatePathGolden(t *testing.T) {
	for _, tc := range []struct {
		family bool
		wire   string
	}{
		{false, "414c54500e0000004100420000000000"},
		{true, "414c54461600000000000000060000004100420000000000"},
	} {
		want, err := hex.DecodeString(tc.wire)
		if err != nil {
			t.Fatal(err)
		}
		got, err := EncodeAlternatePath("AB", tc.family)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("encoded %x: %v", got, err)
		}
		value, family, err := ParseAlternatePath(want)
		if err != nil || value != "AB" || family != tc.family {
			t.Fatalf("decoded %q/%v: %v", value, family, err)
		}
		for _, offset := range []int{0, 4, len(want) - 1} {
			bad := bytes.Clone(want)
			bad[offset] ^= 1
			if _, _, err := ParseAlternatePath(bad); err == nil {
				t.Fatalf("accepted mutation %d", offset)
			}
		}
		for i := range want {
			if _, _, err := ParseAlternatePath(want[:i]); err == nil {
				t.Fatalf("accepted truncation %d", i)
			}
		}
		if tc.family {
			for _, offset := range []int{8, 12} {
				bad := bytes.Clone(want)
				bad[offset] ^= 1
				if _, _, err := ParseAlternatePath(bad); err == nil {
					t.Fatal("accepted invalid ALTF header")
				}
			}
		}
	}
}

func TestAlternatePathLimits(t *testing.T) {
	for _, family := range []bool{false, true} {
		for _, value := range []string{"", `C:\A;C:\B`, "名前😀", strings.Repeat("a", 65535)} {
			b, err := EncodeAlternatePath(value, family)
			if err != nil {
				t.Fatal(err)
			}
			got, f, err := ParseAlternatePath(b)
			if err != nil || got != value || f != family {
				t.Fatalf("round trip: %v", err)
			}
		}
		for _, value := range []string{"a\x00b", "\xff", strings.Repeat("a", 65536)} {
			if _, err := EncodeAlternatePath(value, family); err == nil {
				t.Fatal("accepted invalid path")
			}
		}
	}
}

func FuzzAlternatePath(f *testing.F) {
	for _, family := range []bool{false, true} {
		b, err := EncodeAlternatePath(`C:\A;C:\B`, family)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		value, family, err := ParseAlternatePath(data)
		if err != nil {
			return
		}
		b, err := EncodeAlternatePath(value, family)
		if err != nil || !bytes.Equal(b, data) {
			t.Fatalf("round trip: %v", err)
		}
	})
}
