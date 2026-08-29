package windows

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"

	"go.starlark.net/starlark"
)

// pkcs7CertificatesBuiltin scans a PKCS#7/CMS value for embedded DER
// certificates. The tolerant scanner supports legacy Windows catalogs whose
// signatures modern Go may decline to verify.
func pkcs7CertificatesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("pkcs7_certificates", args, kwargs, "value", &value); err != nil {
		return nil, err
	}
	data, err := bytesForValue(value)
	if err != nil {
		return nil, fmt.Errorf("pkcs7_certificates: %w", err)
	}
	certificates := make([]*x509.Certificate, 0)
	scanDERCertificates(data, &certificates, make(map[string]struct{}))
	values := make([]starlark.Value, 0, len(certificates))
	for _, certificate := range certificates {
		digest := sha1.Sum(certificate.Raw)
		values = append(values, certificateStarlarkValue(certificate, digest))
	}
	return starlark.NewList(values), nil
}

func certificateBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("certificate", args, kwargs, "value", &value); err != nil {
		return nil, err
	}
	data, err := bytesForValue(value)
	if err != nil {
		return nil, fmt.Errorf("certificate: %w", err)
	}
	certificate, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("certificate: %w", err)
	}
	digest := sha1.Sum(certificate.Raw)
	return certificateStarlarkValue(certificate, digest), nil
}

func certificateStarlarkValue(certificate *x509.Certificate, digest [sha1.Size]byte) starlark.Value {
	return starfile.NewRecord(starlark.StringDict{
		"der":         starlark.Bytes(certificate.Raw),
		"issuer":      starlark.String(certificate.Issuer.String()),
		"self_signed": starlark.Bool(bytes.Equal(certificate.RawSubject, certificate.RawIssuer)),
		"sha1":        starlark.String(fmt.Sprintf("%x", digest)),
		"subject":     starlark.String(certificate.Subject.String()),
	})
}

func scanDERCertificates(data []byte, certificates *[]*x509.Certificate, seen map[string]struct{}) {
	for offset := 0; offset < len(data); offset++ {
		if data[offset] != 0x30 {
			continue
		}
		size, ok := derElementSize(data[offset:])
		if !ok {
			continue
		}
		if certificate, err := x509.ParseCertificate(data[offset : offset+size]); err == nil {
			key := string(certificate.Raw)
			if _, exists := seen[key]; !exists {
				seen[key] = struct{}{}
				*certificates = append(*certificates, certificate)
			}
		}
	}
}

func derElementSize(data []byte) (int, bool) {
	if len(data) < 2 {
		return 0, false
	}
	length, header := int(data[1]), 2
	if length&0x80 != 0 {
		count := length & 0x7f
		if count == 0 || count > 4 || len(data) < 2+count {
			return 0, false
		}
		length = 0
		for _, value := range data[2 : 2+count] {
			length = length<<8 | int(value)
		}
		header += count
	}
	if length < 0 || header+length > len(data) {
		return 0, false
	}
	return header + length, true
}
