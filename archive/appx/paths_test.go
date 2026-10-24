package appx

import (
	"bytes"
	"testing"
)

func TestDecodedOPCNames(t *testing.T) {
	cases := map[string]string{
		"ProfileIcons/%7Babc%7D.png": "ProfileIcons/{abc}.png",
		"a%20b/%E6%97%A5.txt":        "a b/日.txt",
		"percent%2520.txt":           "percent%20.txt",
		"a+b.txt":                    "a+b.txt",
	}
	for encoded, decoded := range cases {
		a, err := Open(bytes.NewReader(makeZIP(t, fixtureEntry{"AppxManifest.xml", []byte(manifest)}, fixtureEntry{encoded, []byte("x")})))
		if err != nil {
			t.Fatal(err)
		}
		e := a.Entries[1]
		if e.Name != decoded || e.ArchiveName != encoded {
			t.Fatalf("name: %q archive: %q", e.Name, e.ArchiveName)
		}
		value, err := e.Attr("path")
		if err != nil || value.String() != `"`+decoded+`"` {
			t.Fatalf("path: %v %v", value, err)
		}
	}
}

func TestRejectEncodedTraversalAndAliases(t *testing.T) {
	for _, name := range []string{"%2e%2e/evil", "a/%2E%2E/evil", "%2froot", "C%3Aevil", "a%5cevil", "a%00b", "bad%zz", "bad%ff", "a%2e/file", "a%20/file", "dir%2f"} {
		if _, err := Open(bytes.NewReader(makeZIP(t, fixtureEntry{"AppxManifest.xml", []byte(manifest)}, fixtureEntry{name, nil}))); err == nil {
			t.Fatalf("accepted %q", name)
		}
	}
	for _, pair := range [][2]string{{"a%20b", "a b"}, {"a%62", "ab"}, {"DIR", "dir%2ffile"}} {
		if _, err := Open(bytes.NewReader(makeZIP(t, fixtureEntry{"AppxManifest.xml", []byte(manifest)}, fixtureEntry{pair[0], nil}, fixtureEntry{pair[1], nil}))); err == nil {
			t.Fatalf("accepted alias %q", pair)
		}
	}
}
