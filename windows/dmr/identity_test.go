package dmr

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// Independent wire-layout vector; short strings intentionally test the format,
// not valid Windows package-name/publisher-ID policy. Resource ID is absent.
const identityGolden = "3000000020000000040003000200010009000000" +
	"040004000400000000000400" + "41000000420000004300000044000000"

func identityFixture(t testing.TB) []byte {
	t.Helper()
	b, err := hex.DecodeString(identityGolden)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestIdentityGolden(t *testing.T) {
	want := identityFixture(t)
	id := Identity{Flags: 0x20, Version: 0x0001000200030004, Architecture: 9, Name: "A", PublisherID: "B", Publisher: "C", FullName: "D"}
	got, err := EncodeIdentity(id)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("encoded %x: %v", got, err)
	}
	parsed, err := ParseIdentity(want)
	if err != nil || parsed != id {
		t.Fatalf("parsed %#v: %v", parsed, err)
	}
}

func TestIdentityUnicodeAndBounds(t *testing.T) {
	for _, name := range []string{"A", "名前😀", strings.Repeat("a", 32766)} {
		id := Identity{Name: name}
		b, err := EncodeIdentity(id)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseIdentity(b)
		if err != nil || parsed != id {
			t.Fatalf("round trip: %v", err)
		}
	}
	for _, name := range []string{"", "a\x00b", "\xff", strings.Repeat("a", 32767), strings.Repeat("😀", 16384)} {
		if _, err := EncodeIdentity(Identity{Name: name}); err == nil {
			t.Fatal("accepted invalid identity string")
		}
	}
}

func TestIdentityMalformed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		offset int
		value  uint32
	}{
		{"size", 0, 44}, {"name_length", 20, 0x00040000},
		{"publisher_overflow", 24, 0xffffffff}, {"publisher_limit", 24, 65536},
		{"odd_name", 20, 0x00040003}, {"missing_terminator", 32, 0x00410041},
		{"high_surrogate", 32, 0x0000d800}, {"low_surrogate", 32, 0x0000dc00},
		{"embedded_nul", 32, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := identityFixture(t)
			le.PutUint32(b[tc.offset:], tc.value)
			if _, err := ParseIdentity(b); err == nil {
				t.Fatal("accepted malformed identity")
			}
		})
	}
	b := identityFixture(t)
	for i := range b {
		if _, err := ParseIdentity(b[:i]); err == nil {
			t.Fatalf("accepted truncation %d", i)
		}
	}
}

func FuzzIdentity(f *testing.F) {
	f.Add(identityFixture(f))
	f.Fuzz(func(t *testing.T, data []byte) {
		identity, err := ParseIdentity(data)
		if err != nil {
			return
		}
		encoded, err := EncodeIdentity(identity)
		if err != nil || !bytes.Equal(encoded, data) {
			t.Fatalf("round trip: %v", err)
		}
	})
}
