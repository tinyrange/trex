package catalog

import (
	"bytes"
	"encoding/asn1"
	"testing"
)

func entryAttributesFile(t *testing.T, attrs ...[]byte) []byte {
	t.Helper()
	seq := func(parts ...[]byte) []byte { return catalogTestDER(t, 16, true, parts...) }
	ctx := func(data []byte) []byte {
		v, err := asn1.Marshal(asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: data})
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	member := seq(catalogTestDER(t, 4, false, bytes.Repeat([]byte{7}, 32)), catalogTestDER(t, 17, true, attrs...))
	// Global name/value extensions must not be attached to any member.
	global := attributeTestExtension(t, []byte{30, 2, 0, 'G'}, []byte{2, 1, 0}, []byte{4, 1, 99})
	ctl := seq(seq(), catalogTestDER(t, 23, false, []byte("261010111300Z")), seq(catalogTestOID(t, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 12, 1, 3})), seq(member), ctx(seq(global)))
	return seq(catalogTestOID(t, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}), ctx(seq([]byte{2, 1, 1}, catalogTestDER(t, 17, true), seq(catalogTestOID(t, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 1}), ctx(ctl)), catalogTestDER(t, 17, true))))
}

func TestMemberAttributesPreserveAssociationAndMultiplicity(t *testing.T) {
	name := []byte{30, 8, 0, 'H', 0, 'i', 0, 'n', 0, 't'}
	rawValue := []byte{'x', 0, '/', 0, 'y', 0, 0, 0}
	nv := catalogTestDER(t, 16, true, name, []byte{2, 3, 1, 0, 1}, catalogTestDER(t, 4, false, rawValue))
	attr := catalogTestDER(t, 16, true, catalogTestOID(t, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 12, 2, 1}), catalogTestDER(t, 17, true, nv, nv))
	unknown := catalogTestDER(t, 16, true, catalogTestOID(t, asn1.ObjectIdentifier{1, 2, 3, 4}), catalogTestDER(t, 17, true, []byte{4, 1, 9}))
	encoded := entryAttributesFile(t, attr, unknown, attr)
	version, entries, err := ParseEntries(encoded)
	if err != nil || version != 2 || len(entries) != 1 {
		t.Fatalf("version=%d entries=%v err=%v", version, entries, err)
	}
	entry := entries[0]
	if len(entry.Attributes) != 5 || !bytes.Equal(entry.Subject, entry.Digest) {
		t.Fatalf("lost association/multiplicity: %#v", entry)
	}
	for _, i := range []int{0, 1, 3, 4} {
		a := entry.Attributes[i]
		if !a.NameValue || a.Name != "Hint" || a.Flags != 0x10001 || !bytes.Equal(a.Value, rawValue) {
			t.Fatalf("attribute %d: %#v", i, a)
		}
	}
	if entry.Attributes[2].NameValue || !bytes.Equal(entry.Attributes[2].Value, []byte{4, 1, 9}) {
		t.Fatal("opaque attribute altered")
	}
	saved := append([]byte(nil), encoded...)
	entry.Subject[0] ^= 255
	entry.Digest[0] ^= 255
	entry.Attributes[0].Value[0] ^= 255
	if !bytes.Equal(saved, encoded) || !bytes.Equal(entry.Attributes[1].Value, rawValue) {
		t.Fatal("returned values alias input/each other")
	}
	for end := 0; end < len(encoded); end++ {
		if _, _, err := ParseEntries(encoded[:end]); err == nil {
			t.Fatalf("accepted truncation %d", end)
		}
	}
	if _, _, err := ParseEntries(append(encoded, 0)); err == nil {
		t.Fatal("accepted trailing data")
	}
}

func TestMemberAttributesVersionsAndMalformedValues(t *testing.T) {
	for _, v := range []int{2, 3} {
		digest := bytes.Repeat([]byte{1}, 32)
		version, entries, err := ParseEntries(catalogTestFile(t, v, true, digest))
		if err != nil || version != v-1 || len(entries) != 1 || !bytes.Equal(entries[0].Digest, digest) {
			t.Fatalf("v%d: %#v %v", v, entries, err)
		}
		if bytes.Equal(entries[0].Subject, digest) != (v == 3) {
			t.Fatal("v1 subject mistaken for digest")
		}
	}
	oid := catalogTestOID(t, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 12, 2, 1})
	for _, value := range [][]byte{{4, 1, 1}, {30, 0}, catalogTestDER(t, 16, true, []byte{30, 2, 0, 0}, []byte{2, 1, 0}, []byte{4, 0}), catalogTestDER(t, 16, true, []byte{30, 2, 0, 'H'}, []byte{2, 1, 255}, []byte{4, 0})} {
		attr := catalogTestDER(t, 16, true, oid, catalogTestDER(t, 17, true, value))
		if _, _, err := ParseEntries(entryAttributesFile(t, attr)); err == nil {
			t.Fatalf("accepted malformed name/value %x", value)
		}
	}
	attr := catalogTestDER(t, 16, true, oid, catalogTestDER(t, 17, true))
	if _, _, err := ParseEntries(entryAttributesFile(t, attr)); err == nil {
		t.Fatal("accepted empty attribute set")
	}
}
