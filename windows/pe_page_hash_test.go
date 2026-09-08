package windows

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"testing"
)

func TestPEPageHashes(t *testing.T) {
	data := signingTestPE(0xaa64)
	hashes, err := pePageHashes(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(hashes) != 4*36 {
		t.Fatalf("table size %d", len(hashes))
	}
	header := append([]byte(nil), data[:0xd8]...)
	header = append(header, data[0xdc:0x128]...)
	header = append(header, data[0x130:0x200]...)
	header = append(header, make([]byte, 4096-512)...)
	for i, c := range []struct {
		offset  int
		content []byte
	}{
		{0, header}, {0x200, append(bytes.Clone(data[0x200:0x300]), make([]byte, 4096-256)...)},
		{0x300, append(bytes.Clone(data[0x300:0x400]), make([]byte, 4096-256)...)},
	} {
		expected := sha256.Sum256(c.content)
		if binary.LittleEndian.Uint32(hashes[i*36:]) != uint32(c.offset) || !bytes.Equal(hashes[i*36+4:(i+1)*36], expected[:]) {
			t.Fatalf("wrong page %d", i)
		}
	}
	if binary.LittleEndian.Uint32(hashes[108:]) != 0x400 || !bytes.Equal(hashes[112:], make([]byte, 32)) {
		t.Fatal("wrong sentinel")
	}
	identity := signingTestIdentity(t)
	signed, err := signPEWithPageHashes(data, identity, false, true)
	if err != nil {
		t.Fatal(err)
	}
	after, err := pePageHashes(signed)
	if err != nil || !bytes.Equal(after, hashes) {
		t.Fatal("signing changed mapped page hashes", err)
	}
	cert := int(binary.LittleEndian.Uint32(signed[0x128:]))
	var outer testContentInfo
	_, err = asn1.Unmarshal(signed[cert+8:], &outer)
	if err != nil {
		t.Fatal(err)
	}
	var sd testSignedData
	unmarshalSigningTest(t, outer.Content.Bytes, &sd)
	attrs := bytes.Clone(sd.Signers[0].Attrs.FullBytes)
	attrs[0] = 0x31
	if err := identity.certificate.CheckSignature(x509.SHA256WithRSA, attrs, sd.Signers[0].Signature); err != nil {
		t.Fatal(err)
	}
	var indirect testIndirect
	unmarshalSigningTest(t, sd.Content.Content.Bytes, &indirect)
	var image struct {
		Flags asn1.BitString
		File  struct {
			Moniker struct{ ClassID, Data []byte } `asn1:"tag:1"`
		} `asn1:"tag:0"`
	}
	unmarshalSigningTest(t, indirect.Data.Value.FullBytes, &image)
	var attributes []testAttribute
	rest, err := asn1.UnmarshalWithParams(image.File.Moniker.Data, &attributes, "set")
	if err != nil || len(rest) != 0 || len(attributes) != 1 || !attributes[0].Type.Equal(spcPageHashV2OID) || len(attributes[0].Values) != 1 {
		t.Fatal("invalid page-hash attribute", err)
	}
	var embedded []byte
	unmarshalSigningTest(t, attributes[0].Values[0].FullBytes, &embedded)
	if !bytes.Equal(embedded, hashes) {
		t.Fatal("page hashes changed in DER")
	}
	data[0x443-1] ^= 1
	overlay, err := pePageHashes(data)
	if err != nil || !bytes.Equal(overlay, hashes) {
		t.Fatal("overlay entered page hashes")
	}
	data[0x210] ^= 1
	mutated, err := pePageHashes(data)
	if err != nil || bytes.Equal(mutated[36:72], hashes[36:72]) {
		t.Fatal("mapped page mutation was missed")
	}
}
