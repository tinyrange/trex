package msi

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/tinyrange/trex/archive/cfb"
	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
)

// A real compound directory and FAT, independent of database table semantics.
// Three streams share a deterministic 4096-byte payload for read comparisons.
func namedCompound(names []string, msi bool) []byte {
	b := make([]byte, 11*512)
	put16 := func(at int, v uint16) { binary.LittleEndian.PutUint16(b[at:], v) }
	put32 := func(at int, v uint32) { binary.LittleEndian.PutUint32(b[at:], v) }
	copy(b, []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1})
	put16(26, 3)
	put16(28, 0xfffe)
	put16(30, 9)
	put16(32, 6)
	put32(44, 1)
	put32(48, 1)
	put32(56, 4096)
	put32(60, 0xfffffffe)
	put32(68, 0xfffffffe)
	for at := 76; at < 1024; at += 4 {
		put32(at, 0xffffffff)
	}
	put32(76, 0)
	put32(512, 0xfffffffd)
	put32(516, 0xfffffffe)
	for id := 2; id < 9; id++ {
		put32(512+id*4, uint32(id+1))
	}
	put32(512+9*4, 0xfffffffe)
	entry := func(id int, name string, kind byte) {
		at := 1024 + id*128
		chars := utf16.Encode([]rune(name))
		for i, c := range chars {
			put16(at+i*2, c)
		}
		put16(at+64, uint16((len(chars)+1)*2))
		b[at+66] = kind
		b[at+67] = 1
		put32(at+68, 0xffffffff)
		put32(at+72, 0xffffffff)
		put32(at+76, 0xffffffff)
		put32(at+116, 0xfffffffe)
	}
	entry(0, "Root Entry", 5)
	put32(1024+76, 1)
	if msi {
		copy(b[1024+80:], packageClassID[:])
	}
	for i, name := range names {
		entry(i+1, name, 2)
		at := 1024 + (i+1)*128
		if i+1 < len(names) {
			put32(at+72, uint32(i+2))
		}
		put32(at+116, 2)
		put32(at+120, 4096)
	}
	for i := 1536; i < len(b); i++ {
		b[i] = byte(i % 251)
	}
	return b
}

func TestMSIAutoReadableNamesAndRawIdentity(t *testing.T) {
	// These codepoints encode "File" and "cab"; U+4840 is a table marker.
	names := []string{"\u4840\u430f\u422f", "\u4126\u4825", "\x05SummaryInformation"}
	b := namedCompound(names, true)
	source := &starfile.Bytes{Data: b}
	result, err := auto.Identify(source, auto.Options{})
	if err != nil || result.Format != "msi" {
		t.Fatalf("%+v %v", result, err)
	}
	es, err := result.View.Entries()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]auto.Entry{}
	for _, e := range es {
		got[e.Name] = e
	}
	raw, err := cfb.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{"!File", "cab", "[U+0005]SummaryInformation"} {
		e, ok := got[name]
		if !ok {
			t.Fatalf("missing %q: %+v", name, es)
		}
		if e.Attributes["cfb_path"] != "/"+names[i] || e.Attributes["msi_table"] != (i == 0) {
			t.Fatalf("%+v", e.Attributes)
		}
		payload, err := io.ReadAll(io.NewSectionReader(e.Reader, 0, e.Reader.Size()))
		if err != nil || !bytes.Equal(payload, b[1536:]) {
			t.Fatalf("changed payload: %v", err)
		}
		if raw.Lookup(names[i]) == nil {
			t.Fatal("raw CFB lookup changed")
		}
	}
	// Actual Unicode names in non-MSI compound documents must remain untouched.
	ordinary := namedCompound(names, false)
	result, err = auto.Identify(&starfile.Bytes{Data: ordinary}, auto.Options{})
	if err != nil || result.Format != "cfb" {
		t.Fatalf("ordinary CFB: %+v %v", result, err)
	}
	es, err = result.View.Entries()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range es {
		if e.Name == names[0] {
			found = true
		}
	}
	if !found {
		t.Fatal("renamed ordinary CFB Unicode stream")
	}
}

func TestMSINameCollisionsAreNotDiscarded(t *testing.T) {
	b := namedCompound([]string{"\u4840File", "!File", "[U+0005]"}, true)
	v, err := openView(b, &starfile.Bytes{Data: b}, auto.Options{})
	if err != nil {
		t.Fatal(err)
	}
	es, err := v.Entries()
	if err != nil || len(es) != 3 {
		t.Fatalf("%+v %v", es, err)
	}
	seen := map[string]bool{}
	for _, e := range es {
		if seen[e.Name] {
			t.Fatal("lost collision")
		}
		seen[e.Name] = true
	}
	// Two genuinely different encoded names can decode to the same spelling.
	b = namedCompound([]string{"File", "\u430f\u422f"}, true)
	if _, err := openView(b, &starfile.Bytes{Data: b}, auto.Options{}); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("duplicate: %v", err)
	}
}
