package windows

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"
)

var microsoftRFC3161OID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 3, 3, 1}
var timestampContentOID = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}

type signatureTimestampInfo struct {
	Version int
	Policy  asn1.ObjectIdentifier
	Imprint struct {
		Algorithm pkix.AlgorithmIdentifier
		Digest    []byte
	}
	Serial     *big.Int
	Time       time.Time     `asn1:"generalized"`
	Accuracy   asn1.RawValue `asn1:"optional"`
	Ordering   bool          `asn1:"optional,default:false"`
	Nonce      *big.Int      `asn1:"optional"`
	TSA        asn1.RawValue `asn1:"optional,tag:0"`
	Extensions asn1.RawValue `asn1:"optional,tag:1"`
}
type verifiedSignatureTimestamp struct {
	integrity *verifiedPEIntegrity
	time      time.Time
}

// Verifies only token integrity and its binding to the primary signature.
// A valid signature from an untrusted TSA is not evidence of a trusted time.
func verifySignatureTimestamp(primary *verifiedPEIntegrity) (*verifiedSignatureTimestamp, error) {
	if len(primary.unsigned) == 0 {
		return nil, nil
	}
	raw := append([]byte(nil), primary.unsigned...)
	if raw[0] != 0xa1 {
		return nil, fmt.Errorf("invalid unsigned attribute tag")
	}
	raw[0] = 0x31
	var attributes []signatureAttribute
	rest, err := asn1.UnmarshalWithParams(raw, &attributes, "set")
	if err != nil || len(rest) != 0 || len(attributes) > 64 {
		return nil, fmt.Errorf("invalid unsigned attributes")
	}
	var timestamp *verifiedSignatureTimestamp
	for _, attr := range attributes {
		if !attr.Type.Equal(microsoftRFC3161OID) {
			continue
		}
		if timestamp != nil || len(attr.Values) != 1 {
			return nil, fmt.Errorf("ambiguous RFC3161 timestamp")
		}
		var outer signatureContent
		if err := signatureDER(attr.Values[0].FullBytes, &outer); err != nil {
			return nil, err
		}
		if !outer.Type.Equal(pkcs7SignedDataOID) {
			return nil, fmt.Errorf("timestamp is not SignedData")
		}
		var sd signatureSignedData
		if err := signatureDER(outer.Content.Bytes, &sd); err != nil {
			return nil, err
		}
		if sd.Version != 3 || !sd.Content.Type.Equal(timestampContentOID) {
			return nil, fmt.Errorf("unsupported timestamp content")
		}
		var content []byte
		if err := signatureDER(sd.Content.Content.Bytes, &content); err != nil {
			return nil, err
		}
		integrity, err := verifySignedContent(sd, timestampContentOID, content)
		if err != nil {
			return nil, fmt.Errorf("timestamp signature: %w", err)
		}
		var info signatureTimestampInfo
		if err := signatureDER(content, &info); err != nil {
			return nil, err
		}
		if info.Version != 1 || len(info.Policy) == 0 || info.Serial == nil || info.Serial.Sign() <= 0 || !signatureAlgorithm(info.Imprint.Algorithm, sha256OID) {
			return nil, fmt.Errorf("unsupported timestamp info")
		}
		hash := sha256.Sum256(primary.signature)
		if !bytes.Equal(hash[:], info.Imprint.Digest) {
			return nil, fmt.Errorf("timestamp does not bind primary signature")
		}
		timestamp = &verifiedSignatureTimestamp{integrity: integrity, time: info.Time}
	}
	return timestamp, nil
}
