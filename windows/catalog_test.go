package windows

import (
	"bytes"
	"encoding/asn1"
	"testing"
)

func TestParseCatalogMembers(t *testing.T) {
	want := bytes.Repeat([]byte{0x5a}, 20)
	catalog, err := asn1.Marshal(struct {
		Member []byte
	}{Member: want})
	if err != nil {
		t.Fatal(err)
	}
	encapsulated, err := asn1.Marshal(struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue
	}{
		Type:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 1},
		Content: asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: mustMarshalASN1(t, asn1.RawValue{Class: 0, Tag: 4, Bytes: catalog})},
	})
	if err != nil {
		t.Fatal(err)
	}
	signedData, err := asn1.Marshal(struct {
		Version int
		Digests asn1.RawValue
		Content asn1.RawValue
	}{
		Version: 1,
		Digests: asn1.RawValue{FullBytes: []byte{0x31, 0x00}},
		Content: asn1.RawValue{FullBytes: encapsulated},
	})
	if err != nil {
		t.Fatal(err)
	}
	input, err := asn1.Marshal(struct {
		Type    asn1.ObjectIdentifier
		Content asn1.RawValue
	}{
		Type:    pkcs7SignedDataOID,
		Content: asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: signedData},
	})
	if err != nil {
		t.Fatal(err)
	}
	members, err := parseCatalogMembers(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 1 || !bytes.Equal(members[0], want) {
		t.Fatalf("members = %x, want %x", members, want)
	}
}

func mustMarshalASN1(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestParseCatalogMembersRejectsNonSignedData(t *testing.T) {
	input, err := asn1.Marshal(struct {
		Type asn1.ObjectIdentifier
	}{Type: asn1.ObjectIdentifier{1, 2, 3}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseCatalogMembers(input); err == nil {
		t.Fatal("non-SignedData input was accepted")
	}
}
