package windows

// Embedded Authenticode integrity is distinct from certificate trust. This
// parser never consults host roots, a host clock, or a network service.
import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"math/big"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type signatureContent struct {
	Type    asn1.ObjectIdentifier
	Content asn1.RawValue `asn1:"explicit,tag:0"`
}
type signatureAttribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}
type signatureSigner struct {
	Version      int
	IssuerSerial struct {
		Issuer asn1.RawValue
		Serial *big.Int
	}
	Digest     pkix.AlgorithmIdentifier
	Attributes asn1.RawValue `asn1:"tag:0"`
	Encryption pkix.AlgorithmIdentifier
	Signature  []byte
	Unsigned   asn1.RawValue `asn1:"optional,tag:1"`
}
type signatureSignedData struct {
	Version      int
	Digests      []pkix.AlgorithmIdentifier `asn1:"set"`
	Content      signatureContent
	Certificates asn1.RawValue     `asn1:"tag:0"`
	CRLs         asn1.RawValue     `asn1:"optional,tag:1"`
	Signers      []signatureSigner `asn1:"set"`
}
type signatureIndirect struct {
	Data struct {
		Type  asn1.ObjectIdentifier
		Value asn1.RawValue
	}
	Digest struct {
		Algorithm pkix.AlgorithmIdentifier
		Value     []byte
	}
}
type verifiedPEIntegrity struct {
	signer       *x509.Certificate
	certificates []*x509.Certificate
	unsigned     []byte
	signature    []byte
}

func signatureDER(data []byte, value any) error {
	rest, err := asn1.Unmarshal(data, value)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return fmt.Errorf("trailing DER data")
	}
	return nil
}
func signatureAlgorithm(a pkix.AlgorithmIdentifier, oid asn1.ObjectIdentifier) bool {
	return a.Algorithm.Equal(oid) && (len(a.Parameters.FullBytes) == 0 || bytes.Equal(a.Parameters.FullBytes, []byte{5, 0}))
}
func verifyPEIntegrity(data []byte) (*verifiedPEIntegrity, error) {
	layout, err := signingPELayout(data)
	if err != nil {
		return nil, err
	}
	if layout.certificateSize == 0 {
		return nil, fmt.Errorf("PE has no embedded signature")
	}
	if layout.certificateSize > 4<<20 {
		return nil, fmt.Errorf("certificate table exceeds 4 MiB")
	}
	entry := data[layout.certificate:]
	size := int(binary.LittleEndian.Uint32(entry))
	if (size+7)&^7 != len(entry) {
		return nil, fmt.Errorf("multiple WIN_CERTIFICATE entries are unsupported")
	}
	if binary.LittleEndian.Uint16(entry[4:]) != 0x200 || binary.LittleEndian.Uint16(entry[6:]) != 2 {
		return nil, fmt.Errorf("unsupported WIN_CERTIFICATE type or revision")
	}
	var outer signatureContent
	padding, err := asn1.Unmarshal(entry[8:size], &outer)
	if err != nil {
		return nil, fmt.Errorf("ContentInfo: %w", err)
	}
	if len(padding) > 7 || !bytes.Equal(padding, make([]byte, len(padding))) || !bytes.Equal(entry[size:], make([]byte, len(entry)-size)) {
		return nil, fmt.Errorf("invalid certificate padding")
	}
	if !outer.Type.Equal(pkcs7SignedDataOID) {
		return nil, fmt.Errorf("not PKCS#7 SignedData")
	}
	var sd signatureSignedData
	if err := signatureDER(outer.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("SignedData: %w", err)
	}
	if sd.Version != 1 || len(sd.Digests) != 1 || len(sd.Signers) != 1 || !signatureAlgorithm(sd.Digests[0], sha256OID) || !sd.Content.Type.Equal(spcIndirectOID) {
		return nil, fmt.Errorf("only single-signer SHA-256 Authenticode is supported")
	}
	var indirect signatureIndirect
	if err := signatureDER(sd.Content.Content.Bytes, &indirect); err != nil {
		return nil, fmt.Errorf("indirect data: %w", err)
	}
	if !indirect.Data.Type.Equal(spcPEImageOID) || !signatureAlgorithm(indirect.Digest.Algorithm, sha256OID) {
		return nil, fmt.Errorf("unsupported image digest")
	}
	digest, err := peSigningDigest(data, layout)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(digest, indirect.Digest.Value) {
		return nil, fmt.Errorf("Authenticode image digest mismatch")
	}
	var content asn1.RawValue
	if err := signatureDER(sd.Content.Content.Bytes, &content); err != nil {
		return nil, err
	}
	return verifySignedContent(sd, spcIndirectOID, content.Bytes)
}

func verifySignedContent(sd signatureSignedData, expectedType asn1.ObjectIdentifier, contentOctets []byte) (*verifiedPEIntegrity, error) {
	if len(sd.Signers) != 1 || len(sd.Digests) != 1 || !signatureAlgorithm(sd.Digests[0], sha256OID) {
		return nil, fmt.Errorf("only single-signer SHA-256 SignedData is supported")
	}
	si := sd.Signers[0]
	if si.Version != 1 || si.IssuerSerial.Serial == nil || !signatureAlgorithm(si.Digest, sha256OID) || !(signatureAlgorithm(si.Encryption, rsaEncryptionOID) || signatureAlgorithm(si.Encryption, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11})) {
		return nil, fmt.Errorf("unsupported signer identity or algorithm: version=%d digest=%s encryption=%s", si.Version, si.Digest.Algorithm, si.Encryption.Algorithm)
	}
	certificates, err := signatureCertificates(sd.Certificates.Bytes)
	if err != nil {
		return nil, fmt.Errorf("certificates: %w", err)
	}
	if len(certificates) == 0 || len(certificates) > 32 {
		return nil, fmt.Errorf("certificate count outside 1..32")
	}
	var signer *x509.Certificate
	for _, cert := range certificates {
		if bytes.Equal(cert.RawIssuer, si.IssuerSerial.Issuer.FullBytes) && cert.SerialNumber.Cmp(si.IssuerSerial.Serial) == 0 {
			if signer != nil {
				return nil, fmt.Errorf("ambiguous signer certificate")
			}
			signer = cert
		}
	}
	if signer == nil {
		return nil, fmt.Errorf("signer certificate missing")
	}
	attrs := append([]byte(nil), si.Attributes.FullBytes...)
	if len(attrs) == 0 || attrs[0] != 0xa0 {
		return nil, fmt.Errorf("authenticated attributes missing")
	}
	attrs[0] = 0x31
	var attributes []signatureAttribute
	rest, err := asn1.UnmarshalWithParams(attrs, &attributes, "set")
	if err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("malformed authenticated attributes: %v", err)
	}
	if len(attributes) > 64 {
		return nil, fmt.Errorf("too many authenticated attributes")
	}
	seen := map[string]bool{}
	var contentType asn1.ObjectIdentifier
	var contentDigest []byte
	for _, attr := range attributes {
		oid := attr.Type.String()
		if seen[oid] {
			return nil, fmt.Errorf("duplicate authenticated attribute %s", oid)
		}
		seen[oid] = true
		switch {
		case attr.Type.Equal(pkcsContentTypeOID):
			if len(attr.Values) != 1 {
				return nil, fmt.Errorf("invalid content-type attribute")
			}
			if err := signatureDER(attr.Values[0].FullBytes, &contentType); err != nil {
				return nil, err
			}
		case attr.Type.Equal(pkcsMessageDigestOID):
			if len(attr.Values) != 1 {
				return nil, fmt.Errorf("invalid message-digest attribute")
			}
			if err := signatureDER(attr.Values[0].FullBytes, &contentDigest); err != nil {
				return nil, err
			}
		}
	}
	if !contentType.Equal(expectedType) {
		return nil, fmt.Errorf("authenticated content type mismatch")
	}
	hash := sha256.Sum256(contentOctets)
	if !bytes.Equal(hash[:], contentDigest) {
		return nil, fmt.Errorf("authenticated content digest mismatch")
	}
	if err := signer.CheckSignature(x509.SHA256WithRSA, attrs, si.Signature); err != nil {
		return nil, fmt.Errorf("Authenticode signature: %w", err)
	}
	return &verifiedPEIntegrity{signer: signer, certificates: certificates, unsigned: si.Unsigned.FullBytes, signature: si.Signature}, nil
}
func peSignatureBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("pe_signature", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	data, err := bytesForBinaryValueLimited(value, 256<<20)
	if err != nil {
		return nil, err
	}
	result, err := verifyPEIntegrity(data)
	if err != nil {
		return nil, fmt.Errorf("pe_signature: %w", err)
	}
	timestamp, err := verifySignatureTimestamp(result)
	if err != nil {
		return nil, fmt.Errorf("pe_signature timestamp: %w", err)
	}
	var timestampValue starlark.Value = starlark.None
	if timestamp != nil {
		chain := make([]starlark.Value, 0, len(timestamp.integrity.certificates))
		for _, cert := range timestamp.integrity.certificates {
			chain = append(chain, starlark.Bytes(cert.Raw))
		}
		timestampValue = starfile.NewRecord(starlark.StringDict{
			"unix":         starlark.MakeInt64(timestamp.time.Unix()),
			"signer":       starlark.Bytes(timestamp.integrity.signer.Raw),
			"certificates": starlark.NewList(chain),
		})
	}
	certs := make([]starlark.Value, 0, len(result.certificates))
	for _, cert := range result.certificates {
		certs = append(certs, starlark.Bytes(cert.Raw))
	}
	return starfile.NewRecord(starlark.StringDict{
		"signer":              starlark.Bytes(result.signer.Raw),
		"certificates":        starlark.NewList(certs),
		"signature":           starlark.Bytes(result.signature),
		"unsigned_attributes": starlark.Bytes(result.unsigned),
		"timestamp":           timestampValue,
		"digest_algorithm":    starlark.String("sha256"),
	}), nil
}

func signatureCertificates(data []byte) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	elements := 0
	for len(data) != 0 {
		elements++
		if elements > 32 {
			return nil, fmt.Errorf("certificate count exceeds 32")
		}
		var raw asn1.RawValue
		rest, err := asn1.Unmarshal(data, &raw)
		if err != nil {
			return nil, err
		}
		// CMS CertificateChoices [1] is a v1 attribute certificate, not
		// an X.509 public-key certificate. It cannot supply the signer or
		// any trust anchor and is excluded from the returned X.509 set.
		if raw.Class == 2 && raw.Tag == 1 {
			data = rest
			continue
		}
		cert, err := x509.ParseCertificate(raw.FullBytes)
		if err != nil {
			return nil, fmt.Errorf("certificate %d (class=%d tag=%d size=%d): %w", len(certificates), raw.Class, raw.Tag, len(raw.FullBytes), err)
		}
		certificates = append(certificates, cert)
		data = rest
	}
	return certificates, nil
}
