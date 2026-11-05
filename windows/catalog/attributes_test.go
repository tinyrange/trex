package catalog

import (
	"bytes"
	"encoding/asn1"
	"reflect"
	"testing"
)

func attributeTestFile(t *testing.T, wrapped bool, extensions ...[]byte) []byte {
	t.Helper()
	seq := func(parts ...[]byte) []byte { return catalogTestDER(t, 16, true, parts...) }
	context := func(data []byte) []byte {
		out, err := asn1.Marshal(asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: data})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	// The member's same-looking name/value must never be enumerated as a
	// catalog-level attribute. Certificate/signature bytes are also outside CTL.
	member := seq(catalogTestDER(t, 4, false, bytes.Repeat([]byte{7}, 20)), catalogTestDER(t, 17, true,
		seq(catalogTestOID(t, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 12, 2, 1}), catalogTestDER(t, 17, true, []byte{4, 1, 99}))))
	ctl := seq(seq(), catalogTestDER(t, 23, false, []byte("261010111300Z")), seq(catalogTestOID(t, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 12, 1, 3})), seq(member), context(seq(extensions...)))
	if wrapped {
		ctl = catalogTestDER(t, 4, false, ctl)
	}
	return seq(catalogTestOID(t, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}), context(seq([]byte{2, 1, 1}, catalogTestDER(t, 17, true), seq(catalogTestOID(t, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 1}), context(ctl)), catalogTestDER(t, 17, true))))
}

func attributeTestExtension(t *testing.T, name, flags, value []byte) []byte {
	t.Helper()
	seq := func(parts ...[]byte) []byte { return catalogTestDER(t, 16, true, parts...) }
	return seq(catalogTestOID(t, asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 12, 2, 1}), catalogTestDER(t, 4, false, seq(name, flags, value)))
}

func TestCatalogGlobalAttributesPreserveEncodingAndOrder(t *testing.T) {
	// Captured ntprint.cat OSAttr extension: BMPString big endian name,
	// INTEGER 0x10001, with little endian UTF-16 value including its NUL.
	name := []byte{0x1e, 12, 0, 'O', 0, 'S', 0, 'A', 0, 't', 0, 't', 0, 'r'}
	flags := []byte{2, 3, 1, 0, 1}
	data := []byte{'2', 0, ':', 0, '1', 0, '0', 0, '.', 0, '0', 0, 0, 0}
	ext := attributeTestExtension(t, name, flags, catalogTestDER(t, 4, false, data))
	opaque := catalogTestDER(t, 16, true, catalogTestOID(t, asn1.ObjectIdentifier{1, 2, 3, 4}), []byte{1, 1, 255}, catalogTestDER(t, 4, false, []byte{0, 128, 255}))
	want := []Attribute{
		{OID: "1.3.6.1.4.1.311.12.2.1", NameValue: true, Name: "OSAttr", Flags: 0x10001, Value: data},
		{OID: "1.2.3.4", Critical: true, Value: []byte{0, 128, 255}},
		{OID: "1.3.6.1.4.1.311.12.2.1", NameValue: true, Name: "OSAttr", Flags: 0x10001, Value: data},
	}
	for _, wrapped := range []bool{false, true} {
		encoded := attributeTestFile(t, wrapped, ext, opaque, ext)
		got, err := ParseAttributes(encoded)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("wrapped=%v got=%#v err=%v", wrapped, got, err)
		}
		before := append([]byte(nil), encoded...)
		got[0].Value[0] ^= 255
		if !bytes.Equal(encoded, before) {
			t.Fatal("returned bytes alias source")
		}
		for end := 0; end < len(encoded); end++ {
			if _, err := ParseAttributes(encoded[:end]); err == nil {
				t.Fatalf("accepted truncation %d", end)
			}
		}
		if _, err := ParseAttributes(append(encoded, 0)); err == nil {
			t.Fatal("accepted trailing bytes")
		}
	}
	for _, encoded := range [][]byte{catalogTestFile(t, 3, false), attributeTestFile(t, false)} {
		got, err := ParseAttributes(encoded)
		if err != nil || len(got) != 0 {
			t.Fatalf("empty extensions: %#v %v", got, err)
		}
	}
}

func TestCatalogAttributeRejectsMalformedNameValue(t *testing.T) {
	validName := []byte{30, 2, 0, 'X'}
	validFlags := []byte{2, 1, 0}
	validValue := []byte{4, 1, 255}
	for _, name := range [][]byte{{30, 0}, {30, 1, 0}, {30, 2, 0, 0}, {30, 2, 0xd8, 0}, {30, 2, 0xdc, 0}, {4, 2, 0, 'X'}} {
		if _, err := ParseAttributes(attributeTestFile(t, false, attributeTestExtension(t, name, validFlags, validValue))); err == nil {
			t.Fatalf("accepted name %x", name)
		}
	}
	for _, flags := range [][]byte{{2, 1, 255}, {2, 5, 1, 0, 0, 0, 0}, {4, 1, 1}} {
		if _, err := ParseAttributes(attributeTestFile(t, false, attributeTestExtension(t, validName, flags, validValue))); err == nil {
			t.Fatalf("accepted flags %x", flags)
		}
	}
	if _, err := ParseAttributes(attributeTestFile(t, false, attributeTestExtension(t, validName, validFlags, []byte{2, 1, 1}))); err == nil {
		t.Fatal("accepted non-octet payload")
	}
}
