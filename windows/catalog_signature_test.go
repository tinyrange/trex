package windows

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"testing"

	"go.starlark.net/starlark"
)

// Construct independent signed CTLs with both PKCS#7 and CMS encapsulation.
// wrongEnvelope deliberately signs the other encoding's hash domain.
func signedCatalogFixture(t *testing.T, identity *peSigningIdentity, wrapped, wrongEnvelope bool) []byte {
	t.Helper()
	member := bytes.Repeat([]byte{0x5a}, 32)
	ctl := signingSequence(signingSequence(), signingTLV(23, []byte("261025000000Z")),
		signingSequence(signingOID(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 12, 1, 3})),
		signingSequence(signingSequence(signingTLV(4, member), signingSet())))
	var raw asn1.RawValue
	if err := signatureDER(ctl, &raw); err != nil {
		t.Fatal(err)
	}
	octets := raw.Bytes
	if wrapped != wrongEnvelope {
		octets = ctl
	}
	hash := sha256.Sum256(octets)
	attrs := signingSet(signingAttribute(pkcsContentTypeOID, signingOID(catalogCTLOID)),
		signingAttribute(pkcsMessageDigestOID, signingTLV(4, hash[:])))
	attrHash := sha256.Sum256(attrs)
	sig, err := rsa.SignPKCS1v15(rand.Reader, identity.key, crypto.SHA256, attrHash[:])
	if err != nil {
		t.Fatal(err)
	}
	attrs[0] = 0xa0
	serial, err := asn1.Marshal(identity.certificate.SerialNumber)
	if err != nil {
		t.Fatal(err)
	}
	version := []byte{2, 1, 1}
	signer := signingSequence(version, signingSequence(identity.certificate.RawIssuer, serial),
		signingAlgorithm(sha256OID), attrs, signingAlgorithm(rsaEncryptionOID), signingTLV(4, sig))
	if wrapped {
		ctl = signingTLV(4, ctl)
		version = []byte{2, 1, 3}
	}
	sd := signingSequence(version, signingSet(signingAlgorithm(sha256OID)),
		signingSequence(signingOID(catalogCTLOID), signingTLV(0xa0, ctl)),
		signingTLV(0xa0, identity.certificate.Raw), signingSet(signer))
	return signingSequence(signingOID(pkcs7SignedDataOID), signingTLV(0xa0, sd))
}

func TestCatalogSignatureIntegrity(t *testing.T) {
	identity := signingTestIdentity(t)
	for _, wrapped := range []bool{false, true} {
		data := signedCatalogFixture(t, identity, wrapped, false)
		got, err := verifyCatalogIntegrity(data)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.signer.Raw, identity.certificate.Raw) {
			t.Fatal("wrong signer")
		}
		value, err := catalogSignatureBuiltin(nil, nil, starlark.Tuple{starlark.Bytes(data)}, nil)
		if err != nil || value == nil {
			t.Fatalf("binding: %v", err)
		}
		// Signature and CTL membership are independently tamper-sensitive.
		for _, needle := range [][]byte{bytes.Repeat([]byte{0x5a}, 32), got.signature} {
			at := bytes.Index(data, needle)
			if at < 0 {
				t.Fatal("fixture marker missing")
			}
			bad := bytes.Clone(data)
			bad[at] ^= 1
			if _, err := verifyCatalogIntegrity(bad); err == nil {
				t.Fatal("accepted tampering")
			}
		}
		for end := 0; end < len(data); end++ {
			if _, err := verifyCatalogIntegrity(data[:end]); err == nil {
				t.Fatalf("accepted truncation %d", end)
			}
		}
		if _, err := verifyCatalogIntegrity(append(bytes.Clone(data), 0)); err == nil {
			t.Fatal("accepted trailing data")
		}
		if _, err := verifyCatalogIntegrity(signedCatalogFixture(t, identity, wrapped, true)); err == nil {
			t.Fatal("accepted wrong hash domain")
		}
	}
	pe, err := signPE(signingTestPE(0x8664), identity, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyCatalogIntegrity(pe); err == nil {
		t.Fatal("accepted PE as catalog")
	}
	if _, err := catalogSignatureBuiltin(nil, nil, starlark.Tuple{starlark.MakeInt(1)}, nil); err == nil {
		t.Fatal("accepted nonbinary input")
	}
}
