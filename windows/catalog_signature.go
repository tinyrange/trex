package windows

import (
	"encoding/asn1"
	"fmt"

	"github.com/tinyrange/trex/windows/catalog"
	"go.starlark.net/starlark"
)

var catalogCTLOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 1}

// verifyCatalogIntegrity authenticates the catalog content, not its publisher.
// Trust roots, time and revocation policy are deliberately not supplied here.
func verifyCatalogIntegrity(data []byte) (*verifiedPEIntegrity, error) {
	if _, err := catalog.ParseIndex(data); err != nil {
		return nil, fmt.Errorf("catalog membership: %w", err)
	}
	return verifyCatalogSignedContent(data)
}

// The caller must validate CTL membership against these same owned bytes.
func verifyCatalogSignedContent(data []byte) (*verifiedPEIntegrity, error) {
	if len(data) > 64<<20 {
		return nil, fmt.Errorf("catalog exceeds 64 MiB")
	}
	var outer signatureContent
	if err := signatureDER(data, &outer); err != nil {
		return nil, fmt.Errorf("ContentInfo: %w", err)
	}
	if !outer.Type.Equal(pkcs7SignedDataOID) {
		return nil, fmt.Errorf("not PKCS#7 SignedData")
	}
	var sd signatureSignedData
	if err := signatureDER(outer.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("SignedData: %w", err)
	}
	if (sd.Version != 1 && sd.Version != 3) || !sd.Content.Type.Equal(catalogCTLOID) {
		return nil, fmt.Errorf("unsupported catalog SignedData version or content type")
	}
	var content asn1.RawValue
	if err := signatureDER(sd.Content.Content.Bytes, &content); err != nil {
		return nil, fmt.Errorf("catalog content: %w", err)
	}
	// PKCS#7 hashes the value octets of the directly carried SEQUENCE;
	// CMS hashes the OCTET STRING contents, including the enclosed CTL header.
	if content.Class != 0 || !((content.Tag == asn1.TagSequence && content.IsCompound) || (content.Tag == asn1.TagOctetString && !content.IsCompound)) {
		return nil, fmt.Errorf("unsupported catalog content encoding")
	}
	return verifySignedContent(sd, catalogCTLOID, content.Bytes)
}

func catalogSignatureBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("catalog_signature", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	if parsed, ok := value.(*parsedCatalog); ok {
		return parsed.signature()
	}
	data, err := bytesForBinaryValueLimited(value, 64<<20)
	if err != nil {
		return nil, err
	}
	result, err := verifyCatalogIntegrity(data)
	if err != nil {
		return nil, fmt.Errorf("catalog_signature: %w", err)
	}
	return signatureIntegrityRecord(result, "catalog_signature")
}
