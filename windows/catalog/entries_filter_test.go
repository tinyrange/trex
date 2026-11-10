package catalog

import (
	"bytes"
	"encoding/asn1"
	"reflect"
	"strings"
	"testing"
)

func TestFilteredEntriesMatchFullProjectionAndOwnBytes(t *testing.T) {
	name := []byte{30, 8, 0, 'H', 0, 'i', 0, 'n', 0, 't'}
	nv := catalogTestDER(t, 16, true, name, []byte{2, 3, 1, 0, 1}, []byte{4, 4, 'x', 0, 0, 0})
	attr := catalogTestDER(t, 16, true, catalogTestOID(t, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 12, 2, 1}), catalogTestDER(t, 17, true, nv, nv))
	unknown := catalogTestDER(t, 16, true, catalogTestOID(t, asn1.ObjectIdentifier{1, 2, 3, 4}), catalogTestDER(t, 17, true, []byte{4, 1, 9}))
	encoded := entryAttributesFile(t, unknown, attr, unknown, attr)
	fullVersion, full, err := ParseEntries(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Hint", "hINT", "absent"} {
		var want []Entry
		for _, e := range full {
			var attrs []Attribute
			for _, a := range e.Attributes {
				if a.NameValue && strings.ToLower(a.Name) == strings.ToLower(name) {
					attrs = append(attrs, a)
				}
			}
			if len(attrs) != 0 {
				want = append(want, Entry{Subject: e.Subject, Digest: e.Digest, Attributes: attrs})
			}
		}
		version, got, err := ParseEntriesWithNameValue(encoded, name)
		if err != nil || version != fullVersion || !reflect.DeepEqual(got, want) {
			t.Fatalf("%s projection: %#v, %v", name, got, err)
		}
		if len(got) != 0 {
			saved := bytes.Clone(encoded)
			got[0].Subject[0] ^= 255
			got[0].Digest[0] ^= 255
			got[0].Attributes[0].Value[0] ^= 255
			if !bytes.Equal(encoded, saved) || !bytes.Equal(got[0].Attributes[1].Value, want[0].Attributes[1].Value) {
				t.Fatal("projection aliases input or duplicate attribute values")
			}
		}
	}
	for end := 0; end < len(encoded); end++ {
		if _, _, err := ParseEntriesWithNameValue(encoded[:end], "absent"); err == nil {
			t.Fatalf("accepted truncation %d", end)
		}
	}
	if _, _, err := ParseEntriesWithNameValue(encoded, ""); err == nil {
		t.Fatal("accepted empty selector")
	}
}

func TestFilteredEntriesValidateUnselectedMembers(t *testing.T) {
	// No selected attributes must not turn invalid digests into an empty success.
	for _, version := range []int{2, 3} {
		if _, _, err := ParseEntriesWithNameValue(catalogTestFile(t, version, true, make([]byte, 19)), "Hint"); err == nil {
			t.Fatal("accepted invalid member digest")
		}
	}
	oid := catalogTestOID(t, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 12, 2, 1})
	for _, bad := range [][]byte{{4, 1, 1}, {30, 0}, catalogTestDER(t, 16, true, []byte{30, 2, 0, 'X'}, []byte{2, 1, 255}, []byte{4, 0})} {
		attr := catalogTestDER(t, 16, true, oid, catalogTestDER(t, 17, true, bad))
		if _, _, err := ParseEntriesWithNameValue(entryAttributesFile(t, attr), "Hint"); err == nil {
			t.Fatal("accepted malformed unselected name/value")
		}
	}
}
