package windows

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"testing"

	"go.starlark.net/starlark"
)

func TestCertificateExactPublicKeyMaterial(t *testing.T) {
	id := signingTestIdentity(t)
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.CreateCertificate(rand.Reader, id.certificate, id.certificate, &ec.PublicKey, id.key)
	if err != nil {
		t.Fatal(err)
	}
	ecParams, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name             string
		der, key, params []byte
		oid              string
	}{
		{"RSA", id.certificate.Raw, x509.MarshalPKCS1PublicKey(&id.key.PublicKey), []byte{5, 0}, "1.2.840.113549.1.1.1"},
		{"EC", ecDER, elliptic.Marshal(ec.Curve, ec.X, ec.Y), ecParams, "1.2.840.10045.2.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record, err := certificateBuiltin(nil, nil, starlark.Tuple{starlark.Bytes(tc.der)}, nil)
			if err != nil {
				t.Fatal(err)
			}
			attrs := record.(starlark.HasAttrs)
			for name, want := range map[string][]byte{"public_key_bits": tc.key, "public_key_parameters": tc.params} {
				got, err := attrs.Attr(name)
				if err != nil || !bytes.Equal([]byte(got.(starlark.Bytes)), want) {
					t.Fatalf("%s = %v, %v", name, got, err)
				}
			}
			oid, _ := attrs.Attr("public_key_algorithm")
			if string(oid.(starlark.String)) != tc.oid {
				t.Fatal(oid)
			}
			length, _ := attrs.Attr("public_key_bit_length")
			bits, ok := length.(starlark.Int).Int64()
			if !ok || bits != int64(len(tc.key)*8) {
				t.Fatal(length)
			}
			parsed, err := x509.ParseCertificate(tc.der)
			if err != nil {
				t.Fatal(err)
			}
			spki, _ := attrs.Attr("subject_public_key_info")
			if !bytes.Equal([]byte(spki.(starlark.Bytes)), parsed.RawSubjectPublicKeyInfo) {
				t.Fatal("SPKI changed")
			}
		})
	}
}
