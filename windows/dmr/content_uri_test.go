package dmr

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

func TestContentURIGolden(t *testing.T) {
	// Independent vector: +x NUL, sa-y NUL, w+z NUL. No extra terminator.
	want, err := hex.DecodeString("2b0078000000730061002d007900000077002b007a000000")
	if err != nil {
		t.Fatal(err)
	}
	rules := []ContentURIRule{{Include: true, URI: "x"}, {Flag1: true, RuntimeAccess: 1, URI: "y"}, {RuntimeAccess: 2, Include: true, URI: "z"}}
	got, err := EncodeContentURIRules(rules)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("encoded %x: %v", got, err)
	}
	parsed, err := ParseContentURIRules(want, 3)
	if err != nil || !reflect.DeepEqual(parsed, rules) {
		t.Fatalf("parsed %#v: %v", parsed, err)
	}
	for i := range want {
		if _, err := ParseContentURIRules(want[:i], 3); err == nil {
			t.Fatalf("accepted truncation %d", i)
		}
	}
	for _, count := range []uint16{0, 1, 2, 4, 65535} {
		if _, err := ParseContentURIRules(want, count); err == nil {
			t.Fatalf("accepted count %d", count)
		}
	}
}

func TestContentURIValidation(t *testing.T) {
	for _, text := range []string{"", "n+x", "ss+x", "x", "s", "wa+x"} {
		b, err := terminatedString(text, 65534)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseContentURIRules(b, 1); err == nil {
			t.Fatalf("accepted %q", text)
		}
	}
	for _, rules := range [][]ContentURIRule{{{RuntimeAccess: 3}}, {{URI: "a\x00b"}}, {{URI: "\xff"}}, {{URI: strings.Repeat("x", 32766)}}} {
		if _, err := EncodeContentURIRules(rules); err == nil {
			t.Fatal("accepted invalid rule")
		}
	}
	for _, uri := range []string{"", "https://example.test/名前😀", strings.Repeat("x", 32765)} {
		rules := []ContentURIRule{{Include: true, URI: uri}}
		b, err := EncodeContentURIRules(rules)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseContentURIRules(b, 1)
		if err != nil || !reflect.DeepEqual(got, rules) {
			t.Fatalf("round trip: %v", err)
		}
	}
	if _, err := ParseContentURIRules(nil, 0); err != nil {
		t.Fatal(err)
	}
}

func FuzzContentURIRules(f *testing.F) {
	b, err := EncodeContentURIRules([]ContentURIRule{{URI: "https://example.test", Include: true}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b, uint16(1))
	f.Fuzz(func(t *testing.T, data []byte, count uint16) {
		rules, err := ParseContentURIRules(data, count)
		if err != nil {
			return
		}
		b, err := EncodeContentURIRules(rules)
		if err != nil || !bytes.Equal(b, data) {
			t.Fatalf("round trip: %v", err)
		}
	})
}
