package dmr

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
)

// Hand-composed envelope, independently of EncodeContainer: two equal tags,
// file-relative offsets 44 and 48, total extent 56. Payloads are opaque here;
// this is an envelope test, not a valid Windows dependency graph fixture.
const envelopeGolden = "41524938000000003800000000000000" +
	"544f43381c00000002000000" +
	"524553502c0000005245535030000000" +
	"0102030405060708090a0b0c"

func golden(t testing.TB) []byte {
	t.Helper()
	b, err := hex.DecodeString(envelopeGolden)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestContainerGolden(t *testing.T) {
	want := golden(t)
	sections := []Section{{0x50534552, []byte{1, 2, 3, 4}}, {0x50534552, []byte{5, 6, 7, 8, 9, 10, 11, 12}}}
	got, err := EncodeContainer(sections)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("encoded %x, want %x", got, want)
	}
	parsed, err := ParseContainer(want)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(parsed, sections) {
		t.Fatalf("parsed %#v", parsed)
	}
	for _, section := range parsed {
		if cap(section.Data) != len(section.Data) {
			t.Fatal("section exposes following payload through capacity")
		}
	}
}

func TestContainerRejectsMalformed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		offset int
		value  uint32
	}{
		{"magic", 0, 0}, {"reserved4", 4, 1}, {"short_extent", 8, 52},
		{"long_extent", 8, 60}, {"reserved12", 12, 1}, {"toc_magic", 16, 0},
		{"toc_size", 20, 20}, {"zero_count", 24, 0}, {"count_overflow", 24, 0xffffffff},
		{"offset_in_toc", 32, 40}, {"unaligned_offset", 32, 45},
		{"overlapping_sections", 40, 44}, {"reversed_sections", 40, 40},
		{"offset_beyond_file", 40, 60}, {"offset_overflow", 40, 0xfffffffc},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := golden(t)
			le.PutUint32(data[tc.offset:], tc.value)
			if _, err := ParseContainer(data); err == nil {
				t.Fatal("accepted malformed envelope")
			}
		})
	}
	data := golden(t)
	for i := 0; i < len(data); i++ {
		if _, err := ParseContainer(data[:i]); err == nil {
			t.Fatalf("accepted truncation at %d", i)
		}
	}
	if _, err := ParseContainer(append(data, 0, 0, 0, 0)); err == nil {
		t.Fatal("accepted bytes beyond declared extent")
	}
}

func TestContainerEncodingLimits(t *testing.T) {
	for _, sections := range [][]Section{nil, {{Tag: 1}}, {{1, []byte{1}}}, make([]Section, maxSections+1)} {
		if _, err := EncodeContainer(sections); err == nil {
			t.Fatal("accepted invalid sections")
		}
	}
	sections := make([]Section, maxSections)
	for i := range sections {
		sections[i] = Section{uint32(i), []byte{0, 0, 0, 0}}
	}
	b, err := EncodeContainer(sections)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseContainer(b)
	if err != nil || len(parsed) != maxSections {
		t.Fatalf("maximum sections: %d, %v", len(parsed), err)
	}
}

func FuzzContainer(f *testing.F) {
	f.Add(golden(f))
	f.Add([]byte("ARI8"))
	f.Fuzz(func(t *testing.T, data []byte) {
		sections, err := ParseContainer(data)
		if err != nil {
			return
		}
		encoded, err := EncodeContainer(sections)
		if err != nil {
			t.Fatalf("accepted unencodable container: %v", err)
		}
		again, err := ParseContainer(encoded)
		if err != nil || !reflect.DeepEqual(sections, again) {
			t.Fatalf("round trip mismatch: %v", err)
		}
	})
}
