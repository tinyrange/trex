package windows

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"debug/pe"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"go.starlark.net/starlark"
)

func signingTestIdentity(t *testing.T) *peSigningIdentity {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Trex signing test"}, NotBefore: time.Unix(1700000000, 0), NotAfter: time.Unix(2000000000, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &peSigningIdentity{certificate: cert, key: key}
}

func signingTestPE(machine uint16) []byte {
	// Two sections appear in reverse file order. Unaligned overlay content
	// must be preserved and covered, including padding added by the signer.
	data := make([]byte, 0x443)
	copy(data, "MZ")
	binary.LittleEndian.PutUint32(data[0x3c:], 0x80)
	copy(data[0x80:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(data[0x84:], machine)
	binary.LittleEndian.PutUint16(data[0x86:], 2)
	size, magic, count := uint16(0xe0), uint16(0x10b), 0x98+92
	if machine != 0x14c {
		size, magic, count = 0xf0, 0x20b, 0x98+108
	}
	binary.LittleEndian.PutUint16(data[0x94:], size)
	binary.LittleEndian.PutUint16(data[0x96:], 0x22)
	binary.LittleEndian.PutUint16(data[0x98:], magic)
	binary.LittleEndian.PutUint32(data[0x98+60:], 0x200)
	binary.LittleEndian.PutUint32(data[count:], 16)
	for i, off := range []uint32{0x300, 0x200} {
		at := 0x98 + int(size) + 40*i
		copy(data[at:], []string{".data", ".text"}[i])
		binary.LittleEndian.PutUint32(data[at+8:], 0x100)
		binary.LittleEndian.PutUint32(data[at+12:], uint32(0x1000*(2-i)))
		binary.LittleEndian.PutUint32(data[at+16:], 0x100)
		binary.LittleEndian.PutUint32(data[at+20:], off)
	}
	for i := 0x200; i < len(data); i++ {
		data[i] = byte(i*13 + 5)
	}
	return data
}

// Parse the output with encoding/asn1's typed decoder, independently of the
// signer's DER constructors and the repository's tolerant catalog scanner.
type testContentInfo struct {
	Type    asn1.ObjectIdentifier
	Content asn1.RawValue `asn1:"explicit,tag:0"`
}
type testSignedData struct {
	Version      int
	Algorithms   []pkix.AlgorithmIdentifier `asn1:"set"`
	Content      testContentInfo
	Certificates asn1.RawValue    `asn1:"tag:0"`
	Signers      []testSignerInfo `asn1:"set"`
}
type testSignerInfo struct {
	Version      int
	IssuerSerial struct {
		Issuer asn1.RawValue
		Serial *big.Int
	}
	Algorithm  pkix.AlgorithmIdentifier
	Attrs      asn1.RawValue `asn1:"tag:0"`
	Encryption pkix.AlgorithmIdentifier
	Signature  []byte
}
type testAttribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}
type testIndirect struct {
	Data struct {
		Type  asn1.ObjectIdentifier
		Value asn1.RawValue
	}
	Digest struct {
		Algorithm pkix.AlgorithmIdentifier
		Value     []byte
	}
}

func unmarshalSigningTest(t *testing.T, data []byte, value any) {
	t.Helper()
	rest, err := asn1.Unmarshal(data, value)
	if err != nil || len(rest) != 0 {
		t.Fatalf("DER decode: %v, trailing %d", err, len(rest))
	}
}

func verifySigningTest(t *testing.T, signed []byte, identity *peSigningIdentity) []byte {
	t.Helper()
	image, err := pe.NewFile(bytes.NewReader(signed))
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	var dir pe.DataDirectory
	switch h := image.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dir = h.DataDirectory[4]
	case *pe.OptionalHeader64:
		dir = h.DataDirectory[4]
	default:
		t.Fatal("missing PE optional header")
	}
	if int(dir.VirtualAddress+dir.Size) != len(signed) || dir.VirtualAddress%8 != 0 || dir.Size%8 != 0 {
		t.Fatal("invalid certificate table alignment/size")
	}
	entry := signed[dir.VirtualAddress:]
	if binary.LittleEndian.Uint32(entry) != dir.Size || binary.LittleEndian.Uint16(entry[4:]) != 0x200 || binary.LittleEndian.Uint16(entry[6:]) != 2 {
		t.Fatal("invalid WIN_CERTIFICATE")
	}
	var outer testContentInfo
	rest, err := asn1.Unmarshal(entry[8:], &outer)
	if err != nil || !outer.Type.Equal(pkcs7SignedDataOID) {
		t.Fatalf("ContentInfo: %v", err)
	}
	if len(rest) > 7 || !bytes.Equal(rest, make([]byte, len(rest))) {
		t.Fatal("nonzero certificate padding")
	}
	var sd testSignedData
	unmarshalSigningTest(t, outer.Content.Bytes, &sd)
	if sd.Version != 1 || len(sd.Signers) != 1 || len(sd.Algorithms) != 1 || !sd.Algorithms[0].Algorithm.Equal(sha256OID) || !sd.Content.Type.Equal(spcIndirectOID) {
		t.Fatal("invalid SignedData")
	}
	certificates, err := x509.ParseCertificates(sd.Certificates.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range certificates {
		found = found || bytes.Equal(c.Raw, identity.certificate.Raw)
	}
	if !found {
		t.Fatal("missing signing certificate")
	}
	si := sd.Signers[0]
	if si.Version != 1 || !bytes.Equal(si.IssuerSerial.Issuer.FullBytes, identity.certificate.RawIssuer) || si.IssuerSerial.Serial.Cmp(identity.certificate.SerialNumber) != 0 || !si.Algorithm.Algorithm.Equal(sha256OID) || !si.Encryption.Algorithm.Equal(rsaEncryptionOID) {
		t.Fatal("invalid signer identity or algorithms")
	}
	attrsDER := append([]byte(nil), si.Attrs.FullBytes...)
	attrsDER[0] = 0x31
	if err := identity.certificate.CheckSignature(x509.SHA256WithRSA, attrsDER, si.Signature); err != nil {
		t.Fatalf("RSA signature verification: %v", err)
	}
	badSignature := bytes.Clone(si.Signature)
	badSignature[len(badSignature)-1] ^= 1
	if err := identity.certificate.CheckSignature(x509.SHA256WithRSA, attrsDER, badSignature); err == nil {
		t.Fatal("accepted modified RSA signature")
	}
	badAttributes := bytes.Clone(attrsDER)
	badAttributes[len(badAttributes)-1] ^= 1
	if err := identity.certificate.CheckSignature(x509.SHA256WithRSA, badAttributes, si.Signature); err == nil {
		t.Fatal("accepted modified signed attributes")
	}
	var attrs []testAttribute
	rest, err = asn1.UnmarshalWithParams(attrsDER, &attrs, "set")
	if err != nil || len(rest) != 0 || len(attrs) != 4 {
		t.Fatal("invalid signed attributes")
	}
	var indirectRaw asn1.RawValue
	unmarshalSigningTest(t, sd.Content.Content.Bytes, &indirectRaw)
	contentHash := sha256.Sum256(indirectRaw.Bytes)
	seen := map[string]bool{}
	for _, attr := range attrs {
		if seen[attr.Type.String()] || len(attr.Values) != 1 {
			t.Fatal("duplicate or multivalued attribute")
		}
		seen[attr.Type.String()] = true
		if attr.Type.Equal(pkcsMessageDigestOID) {
			var hash []byte
			unmarshalSigningTest(t, attr.Values[0].FullBytes, &hash)
			if !bytes.Equal(hash, contentHash[:]) {
				t.Fatal("wrong content hash")
			}
		}
		if attr.Type.Equal(pkcsContentTypeOID) {
			var oid asn1.ObjectIdentifier
			unmarshalSigningTest(t, attr.Values[0].FullBytes, &oid)
			if !oid.Equal(spcIndirectOID) {
				t.Fatal("wrong signed content type")
			}
		}
	}
	for _, oid := range []asn1.ObjectIdentifier{pkcsContentTypeOID, pkcsMessageDigestOID, spcStatementOID, spcOpusOID} {
		if !seen[oid.String()] {
			t.Fatal("missing required attribute")
		}
	}
	var indirect testIndirect
	unmarshalSigningTest(t, indirectRaw.FullBytes, &indirect)
	if !indirect.Data.Type.Equal(spcPEImageOID) || !indirect.Digest.Algorithm.Algorithm.Equal(sha256OID) {
		t.Fatal("invalid indirect data")
	}
	if !bytes.Equal(indirect.Data.Value.FullBytes, []byte{0x30, 9, 3, 1, 0, 0xa0, 4, 0xa2, 2, 0x80, 0}) {
		t.Fatal("unexpected SpcPeImageData encoding")
	}
	return indirect.Digest.Value
}

func TestPESignAuthenticode(t *testing.T) {
	id := signingTestIdentity(t)
	for _, machine := range []uint16{0x14c, 0x8664, 0xaa64} {
		t.Run(map[uint16]string{0x14c: "PE32", 0x8664: "AMD64", 0xaa64: "ARM64"}[machine], func(t *testing.T) {
			input := signingTestPE(machine)
			original := bytes.Clone(input)
			signed, err := signPE(input, id, false)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(input, original) {
				t.Fatal("signing changed source bytes")
			}
			digest := verifySigningTest(t, signed, id)
			// Independently assemble the specified digest stream for this fixture.
			security := 0x98 + 96 + 32
			if machine != 0x14c {
				security += 16
			}
			h := sha256.New()
			h.Write(original[:0x98+64])
			h.Write(original[0x98+68 : security])
			h.Write(original[security+8 : 0x200])
			h.Write(original[0x200:0x300])
			h.Write(original[0x300:0x400])
			h.Write(original[0x400:])
			h.Write(make([]byte, 5))
			if !bytes.Equal(digest, h.Sum(nil)) {
				t.Fatal("wrong image digest (including overlay and padding)")
			}
			layout, err := signingPELayout(signed)
			if err != nil {
				t.Fatal(err)
			}
			for _, at := range []int{0x40, 0x210, 0x310, 0x410, len(original) + 1} {
				modified := bytes.Clone(signed)
				modified[at] ^= 1
				got, err := peSigningDigest(modified, layout)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Equal(got, digest) {
					t.Fatalf("mutation at %#x not covered", at)
				}
			}
			modified := bytes.Clone(signed)
			modified[0x98+64] ^= 1
			got, err := peSigningDigest(modified, layout)
			if err != nil || !bytes.Equal(got, digest) {
				t.Fatal("checksum must be excluded")
			}
			if _, err := signPE(signed, id, false); err == nil {
				t.Fatal("overwrote signature without replace")
			}
			replaced, err := signPE(signed, id, true)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(replaced, signed) {
				t.Fatal("replacing same untimestamped signature should preserve all bytes")
			}
			checksum := bytes.Clone(signed)
			if err := updatePEChecksum(checksum); err != nil || !bytes.Equal(checksum, signed) {
				t.Fatal("incorrect final PE checksum")
			}
		})
	}
}

func TestPESignRejectsMalformedInput(t *testing.T) {
	id := signingTestIdentity(t)
	valid := signingTestPE(0xaa64)
	for n := 0; n < 0x200; n++ {
		if _, err := signPE(valid[:n], id, false); err == nil {
			t.Fatalf("accepted truncation %d", n)
		}
	}
	signed, err := signPE(valid, id, false)
	if err != nil {
		t.Fatal(err)
	}
	layout, err := signingPELayout(signed)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func([]byte){
		func(b []byte) { binary.LittleEndian.PutUint32(b[layout.security:], 0x200) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[layout.security+4:], 0xffffffff) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[layout.certificate:], 0) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[layout.certificate:], 0xffffffff) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[0x98+108:], 4) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[0x98+0xf0+20:], 0x210) },
	} {
		b := bytes.Clone(signed)
		mutate(b)
		if _, err := signPE(b, id, true); err == nil {
			t.Fatal("accepted malformed signing layout")
		}
	}
	if _, err := signPE(append(signed, 0), id, true); err == nil {
		t.Fatal("accepted data after certificate table")
	}
	other := signingTestIdentity(t)
	other.certificate = id.certificate
	if _, err := signPE(valid, other, false); err == nil {
		t.Fatal("accepted mismatched certificate/key")
	}
}

func TestPESigningStarlark(t *testing.T) {
	id := signingTestIdentity(t)
	key := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(id.key)})
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: id.certificate.Raw})
	thread := &starlark.Thread{Name: "signing-test"}
	api := Builtins()
	identity, err := starlark.Call(thread, api["signing_identity"], starlark.Tuple{starlark.Bytes(cert), starlark.Bytes(key)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if identity.String() != "<windows.signing_identity>" {
		t.Fatal("identity must hide private key")
	}
	out, err := starlark.Call(thread, api["pe_sign"], starlark.Tuple{starlark.Bytes(signingTestPE(0xaa64)), identity}, nil)
	if err != nil {
		t.Fatal(err)
	}
	verifySigningTest(t, []byte(out.(starlark.Bytes)), id)
	generated, err := starlark.Call(thread, api["test_signing_identity"], starlark.Tuple{starlark.String("Trex VM test"), starlark.MakeInt64(1700000000), starlark.MakeInt64(2000000000)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	g := generated.(*peSigningIdentity)
	if err := g.validate(); err != nil {
		t.Fatal(err)
	}
	if err := g.certificate.CheckSignature(g.certificate.SignatureAlgorithm, g.certificate.RawTBSCertificate, g.certificate.Signature); err != nil {
		t.Fatal(err)
	}
	if g.certificate.IsCA || len(g.certificate.ExtKeyUsage) != 1 || g.certificate.ExtKeyUsage[0] != x509.ExtKeyUsageCodeSigning {
		t.Fatal("wrong test certificate scope")
	}
}
