package windows

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func TestReplaceRegistryPathComponents(t *testing.T) {
	encode := func(s string) []byte {
		u := utf16.Encode([]rune(s))
		b := make([]byte, len(u)*2)
		for i, v := range u {
			binary.LittleEndian.PutUint16(b[i*2:], v)
		}
		return b
	}
	mapping := map[string][]byte{"old": encode("new-name")}
	for _, tc := range []struct {
		before, after string
		changed       bool
	}{
		{"old", "new-name", true},
		{"OLD\x00", "new-name\x00", true},
		{"C:\\old\\file\x00", "C:\\new-name\\file\x00", true},
		{"keep\x00Old\x00old_suffix\x00\x00", "keep\x00new-name\x00old_suffix\x00\x00", true},
		{"old_suffix", "old_suffix", false},
		{"prefixold", "prefixold", false},
		{"", "", false},
		{"old\\old", "new-name\\new-name", true},
	} {
		got, changed := replaceRegistryPathComponents(encode(tc.before), mapping)
		if changed != tc.changed || !bytes.Equal(got, encode(tc.after)) {
			t.Fatalf("%q: %x %v", tc.before, got, changed)
		}
	}
	raw := append(encode("old\\"), 0, 0xd8, 0xff)
	want := append(encode("new-name\\"), 0, 0xd8, 0xff)
	got, changed := replaceRegistryPathComponents(raw, mapping)
	if !changed || !bytes.Equal(got, want) {
		t.Fatalf("raw preservation: %x", got)
	}
}
