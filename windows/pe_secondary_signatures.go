package windows

import (
	"encoding/asn1"
	"fmt"
)

var spcNestedSignatureOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 4, 1}

// Counts advertised secondary signatures, not trusted or verified signatures.
// In particular, zero proves that primary-only verification did not silently
// select one of several advertised signatures. No nested signature is executed
// or promoted to trust material by this observation.
func secondarySignatureCount(unsigned []byte) (int, error) {
	if len(unsigned) == 0 {
		return 0, nil
	}
	if len(unsigned) > 4<<20 || unsigned[0] != 0xa1 {
		return 0, fmt.Errorf("invalid unsigned signature attributes")
	}
	raw := append([]byte(nil), unsigned...)
	raw[0] = 0x31
	var attributes []signatureAttribute
	rest, err := asn1.UnmarshalWithParams(raw, &attributes, "set")
	if err != nil || len(rest) != 0 || len(attributes) > 64 {
		return 0, fmt.Errorf("invalid unsigned signature attributes")
	}
	count := 0
	for _, attr := range attributes {
		if !attr.Type.Equal(spcNestedSignatureOID) {
			continue
		}
		if count != 0 || len(attr.Values) == 0 || len(attr.Values) > 64 {
			return 0, fmt.Errorf("ambiguous secondary signature attribute")
		}
		count = len(attr.Values)
	}
	return count, nil
}
