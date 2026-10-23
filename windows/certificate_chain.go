package windows

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"go.starlark.net/starlark"
	"time"
)

// Explicit roots and time keep this operation portable and deterministic.
// This is X.509 path validation, not Windows provider/revocation policy.
func certificateChainBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var leafValue starlark.Value
	var roots, intermediates starlark.Iterable
	var at int64
	var purpose string
	if err := starlark.UnpackArgs("certificate_chain", args, kwargs, "certificate", &leafValue, "roots", &roots, "intermediates", &intermediates, "unix_time", &at, "purpose", &purpose); err != nil {
		return nil, err
	}
	usage := x509.ExtKeyUsageCodeSigning
	switch purpose {
	case "code_signing":
	case "timestamping":
		usage = x509.ExtKeyUsageTimeStamping
	default:
		return nil, fmt.Errorf("certificate_chain: unsupported purpose %q", purpose)
	}
	der, err := signingDER(leafValue, "certificate")
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	if usage == x509.ExtKeyUsageTimeStamping {
		critical := false
		for _, extension := range leaf.Extensions {
			if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 37}) {
				critical = extension.Critical
			}
		}
		if !critical || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageTimeStamping || len(leaf.UnknownExtKeyUsage) != 0 {
			return nil, fmt.Errorf("certificate_chain: RFC3161 signer requires a critical, exclusive timestamping EKU")
		}
	}
	rootPool, err := explicitCertificatePool(roots, 64)
	if err != nil {
		return nil, fmt.Errorf("roots: %w", err)
	}
	intermediatePool, err := explicitCertificatePool(intermediates, 32)
	if err != nil {
		return nil, fmt.Errorf("intermediates: %w", err)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: rootPool, Intermediates: intermediatePool, CurrentTime: time.Unix(at, 0), KeyUsages: []x509.ExtKeyUsage{usage}})
	if err != nil {
		return nil, fmt.Errorf("certificate_chain: %w", err)
	}
	result := make([]starlark.Value, 0, len(chains))
	for _, chain := range chains {
		values := make([]starlark.Value, 0, len(chain))
		for _, cert := range chain {
			values = append(values, starlark.Bytes(cert.Raw))
		}
		result = append(result, starlark.NewList(values))
	}
	return starlark.NewList(result), nil
}
func explicitCertificatePool(values starlark.Iterable, maximum int) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	iterator := values.Iterate()
	defer iterator.Done()
	var value starlark.Value
	for count := 0; iterator.Next(&value); count++ {
		if count >= maximum {
			return nil, fmt.Errorf("certificate count exceeds %d", maximum)
		}
		der, err := signingDER(value, "certificate")
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		pool.AddCert(cert)
	}
	return pool, nil
}
