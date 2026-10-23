package windows

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"go.starlark.net/starlark"
	"testing"
)

func TestCertificateChainExplicitTrustTimeAndPurpose(t *testing.T) {
	identity := signingTestIdentity(t)
	wrong := signingTestIdentity(t)
	for _, tc := range []struct {
		name    string
		roots   []starlark.Value
		at      int64
		purpose string
		valid   bool
	}{
		{"explicit signer trust", []starlark.Value{starlark.Bytes(identity.certificate.Raw)}, 1800000000, "code_signing", true},
		{"no roots", nil, 1800000000, "code_signing", false},
		{"wrong root", []starlark.Value{starlark.Bytes(wrong.certificate.Raw)}, 1800000000, "code_signing", false},
		{"not yet valid", []starlark.Value{starlark.Bytes(identity.certificate.Raw)}, 1600000000, "code_signing", false},
		{"expired", []starlark.Value{starlark.Bytes(identity.certificate.Raw)}, 2100000000, "code_signing", false},
		{"wrong EKU", []starlark.Value{starlark.Bytes(identity.certificate.Raw)}, 1800000000, "timestamping", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value, err := certificateChainBuiltin(nil, nil, starlark.Tuple{starlark.Bytes(identity.certificate.Raw), starlark.NewList(tc.roots), starlark.NewList(nil), starlark.MakeInt64(tc.at), starlark.String(tc.purpose)}, nil)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v: %v", tc.valid, err)
			}
			if tc.valid && value.(*starlark.List).Len() != 1 {
				t.Fatal("missing verified path")
			}
		})
	}
}

func TestRFC3161ExclusiveCriticalEKU(t *testing.T) {
	id := signingTestIdentity(t)
	for _, tc := range []struct {
		name     string
		critical bool
		usages   []asn1.ObjectIdentifier
		valid    bool
	}{
		{"exclusive critical", true, []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}}, true},
		{"noncritical", false, []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}}, false},
		{"mixed usage", true, []asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}, {1, 3, 6, 1, 5, 5, 7, 3, 3}}, false},
		{"any usage", true, []asn1.ObjectIdentifier{{2, 5, 29, 37, 0}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			template := *id.certificate
			encoded, err := asn1.Marshal(tc.usages)
			if err != nil {
				t.Fatal(err)
			}
			template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: tc.critical, Value: encoded}}
			der, err := x509.CreateCertificate(rand.Reader, &template, &template, &id.key.PublicKey, id.key)
			if err != nil {
				t.Fatal(err)
			}
			_, err = certificateChainBuiltin(nil, nil, starlark.Tuple{starlark.Bytes(der), starlark.NewList([]starlark.Value{starlark.Bytes(der)}), starlark.NewList(nil), starlark.MakeInt64(1800000000), starlark.String("timestamping")}, nil)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
		})
	}
}
