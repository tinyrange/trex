package windows

import (
	"bytes"
	"encoding/asn1"
	"reflect"
	"testing"
)

func catalogTestDER(t *testing.T, tag int, compound bool, children ...[]byte) []byte {
	t.Helper()
	value, err := asn1.Marshal(asn1.RawValue{Tag: tag, IsCompound: compound, Bytes: bytes.Join(children, nil)})
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func catalogTestOID(t *testing.T, oid asn1.ObjectIdentifier) []byte {
	t.Helper()
	value, err := asn1.Marshal(oid)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func catalogTestFile(t *testing.T, version int, wrapped bool, digests ...[]byte) []byte {
	t.Helper()
	seq := func(parts ...[]byte) []byte { return catalogTestDER(t, 16, true, parts...) }
	oct := func(data []byte) []byte { return catalogTestDER(t, 4, false, data) }
	context := func(data []byte) []byte {
		v, err := asn1.Marshal(asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: data})
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	var entries [][]byte
	for _, digest := range digests {
		subject := digest
		attrs := catalogTestDER(t, 17, true)
		if version == 2 {
			subject = bytes.Repeat([]byte{0xee}, 20) // not the v1 member digest
			decoy := seq(catalogTestOID(t, asn1.ObjectIdentifier{1, 2, 3, 4}), catalogTestDER(t, 17, true, oct(bytes.Repeat([]byte{0xdd}, 32))))
			indirect := seq(seq(catalogTestOID(t, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 15})), seq(seq(catalogTestOID(t, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1})), oct(digest)))
			attrs = catalogTestDER(t, 17, true, decoy, seq(catalogTestOID(t, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 4}), catalogTestDER(t, 17, true, indirect)))
		}
		entries = append(entries, seq(oct(subject), attrs))
	}
	ctl := seq(seq(), catalogTestDER(t, 23, false, []byte("261022000000Z")), seq(catalogTestOID(t, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 12, 1, version})), seq(entries...))
	if wrapped {
		ctl = oct(ctl)
	}
	content := seq(catalogTestOID(t, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 1}), context(ctl))
	signed := seq([]byte{2, 1, 1}, catalogTestDER(t, 17, true), content, context(oct(bytes.Repeat([]byte{0xcc}, 32))), catalogTestDER(t, 17, true))
	return seq(catalogTestOID(t, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}), context(signed))
}

func TestCatalogIndexSelectsOnlyMemberDigests(t *testing.T) {
	want := [][]byte{bytes.Repeat([]byte{1}, 20), bytes.Repeat([]byte{2}, 32)}
	for _, version := range []int{2, 3} {
		for _, wrapped := range []bool{false, true} {
			data := catalogTestFile(t, version, wrapped, want...)
			got, err := parseCatalogIndex(data)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("version %d wrapped %v: %x, %v", version, wrapped, got, err)
			}
			// Every truncation must reject, not silently return an incomplete index.
			for end := 0; end < len(data); end++ {
				if _, err := parseCatalogIndex(data[:end]); err == nil {
					t.Fatalf("accepted truncation %d", end)
				}
			}
			if _, err := parseCatalogIndex(append(data, 0)); err == nil {
				t.Fatal("accepted trailing data")
			}
		}
	}
}
func TestCatalogIndexRejectsUnsupportedEntries(t *testing.T) {
	for _, version := range []int{2, 3} {
		got, err := parseCatalogIndex(catalogTestFile(t, version, false))
		if err != nil || len(got) != 0 {
			t.Fatalf("empty CTL: %x %v", got, err)
		}
		for _, length := range []int{0, 19, 21, 31, 33} {
			if _, err := parseCatalogIndex(catalogTestFile(t, version, false, make([]byte, length))); err == nil {
				t.Fatalf("accepted digest length %d", length)
			}
		}
	}
	if _, err := parseCatalogIndex(catalogTestFile(t, 4, false, make([]byte, 20))); err == nil {
		t.Fatal("accepted unknown subject algorithm")
	}
}
