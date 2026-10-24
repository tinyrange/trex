package native

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// Explicit roots are isolated to this client. They do not augment the system
// pool or change any process-global TLS state. Standard hostname, validity and
// chain verification remain enabled. No AIA fetch or insecure fallback occurs.
func httpClientWithRoots(value starlark.Value) (*http.Client, error) {
	if value == nil || value == starlark.None {
		return &http.Client{}, nil
	}
	sequence, ok := value.(starlark.Indexable)
	if !ok || sequence.Len() < 1 || sequence.Len() > 16 {
		return nil, fmt.Errorf("tls_roots: expected 1..16 DER/PEM certificate files or bytes")
	}
	pool := x509.NewCertPool()
	for i := 0; i < sequence.Len(); i++ {
		data, err := starfile.BytesForValue(sequence.Index(i), 1<<20)
		if err != nil {
			return nil, fmt.Errorf("tls_roots: %w", err)
		}
		if block, rest := pem.Decode(data); block != nil {
			if block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
				return nil, fmt.Errorf("tls_roots: each item must contain one certificate")
			}
			data = block.Bytes
		}
		cert, err := x509.ParseCertificate(data)
		if err != nil {
			return nil, fmt.Errorf("tls_roots: %w", err)
		}
		if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, fmt.Errorf("tls_roots: certificate is not a signing CA")
		}
		pool.AddCert(cert)
	}
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("tls_roots: default transport does not support TLS configuration")
	}
	transport := base.Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: transport}, nil
}

// Preserve verification failures and report bounded public certificate metadata.
// Never retry or change trust based on certificates from a failed handshake.
func describeTLSError(err error) error {
	var verification *tls.CertificateVerificationError
	if !errors.As(err, &verification) {
		return err
	}
	detail := ""
	for i, cert := range verification.UnverifiedCertificates {
		if i == 4 {
			break
		}
		detail += fmt.Sprintf("; certificate[%d] subject=%q issuer=%q", i, boundedCertificateText(cert.Subject.String()), boundedCertificateText(cert.Issuer.String()))
		for j, location := range cert.IssuingCertificateURL {
			if j == 4 {
				break
			}
			detail += fmt.Sprintf(" issuer_url=%q", boundedCertificateText(location))
		}
	}
	return fmt.Errorf("%w%s", err, detail)
}

func boundedCertificateText(text string) string {
	if len(text) > 1024 {
		return text[:1024] + "..."
	}
	return text
}
