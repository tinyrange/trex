package dmr

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
)

// Empty positional entry, then AB (six UTF-16 bytes plus two alignment bytes).
const mutablePathsGolden = "504b4d50200000000000000002000000" + "04000000" + "0a0000004100420000000000"

func mutableFixture(t testing.TB) []byte {
	t.Helper()
	b, err := hex.DecodeString(mutablePathsGolden)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestMutablePathsGolden(t *testing.T) {
	want := mutableFixture(t)
	paths := []string{"", "AB"}
	got, err := EncodeMutablePaths(paths)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("encoded %x: %v", got, err)
	}
	parsed, err := ParseMutablePaths(want)
	if err != nil || !reflect.DeepEqual(parsed, paths) {
		t.Fatalf("parsed %q: %v", parsed, err)
	}
	paths = []string{`C:\A`, "", "名前😀", `C:\A`, ""}
	got, err = EncodeMutablePaths(paths)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err = ParseMutablePaths(got)
	if err != nil || !reflect.DeepEqual(parsed, paths) {
		t.Fatalf("ordered paths: %v", err)
	}
}

func TestMutablePathsMalformed(t *testing.T) {
	for _, tc := range []struct {
		offset int
		value  uint32
	}{
		{0, 0}, {4, 28}, {8, 1}, {12, 0}, {12, 3}, {12, 0xffffffff},
		{16, 0}, {16, 0xffffffff}, {20, 9}, {20, 8}, {24, 0x0000d800}, {28, 0x00010000},
	} {
		b := mutableFixture(t)
		le.PutUint32(b[tc.offset:], tc.value)
		if _, err := ParseMutablePaths(b); err == nil {
			t.Fatalf("accepted mutation %d/%x", tc.offset, tc.value)
		}
	}
	b := mutableFixture(t)
	for i := range b {
		if _, err := ParseMutablePaths(b[:i]); err == nil {
			t.Fatalf("accepted truncation %d", i)
		}
	}
}

func TestMutablePathsLimits(t *testing.T) {
	paths := make([]string, maxNodes)
	b, err := EncodeMutablePaths(paths)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseMutablePaths(b)
	if err != nil || len(got) != maxNodes {
		t.Fatalf("maximum count: %v", err)
	}
	for _, invalid := range [][]string{nil, append(paths, ""), {"a\x00b"}, {"\xff"}} {
		if _, err := EncodeMutablePaths(invalid); err == nil {
			t.Fatal("accepted invalid paths")
		}
	}
}

func FuzzMutablePaths(f *testing.F) {
	f.Add(mutableFixture(f))
	f.Fuzz(func(t *testing.T, data []byte) {
		paths, err := ParseMutablePaths(data)
		if err != nil {
			return
		}
		b, err := EncodeMutablePaths(paths)
		if err != nil || !bytes.Equal(b, data) {
			t.Fatalf("round trip: %v", err)
		}
	})
}
