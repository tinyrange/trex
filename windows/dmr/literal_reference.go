package dmr

import "fmt"

const maxReferenceSize = 8192

// EncodeLiteralResourceReference encodes the native MRM literal-string blob.
// The caller must classify the manifest value first: this is not a fallback
// for unresolved ms-resource references, which require their own representation.
func EncodeLiteralResourceReference(value string) ([]byte, error) {
	payload, err := terminatedString(value, maxReferenceSize-8)
	if err != nil {
		return nil, err
	}
	// GetLiteralBlob includes the terminating NUL even for an empty literal.
	if len(payload) == 0 {
		payload = []byte{0, 0}
	}
	out := make([]byte, 8+align4(len(payload)))
	le.PutUint16(out, 0x100)
	le.PutUint16(out[2:], uint16(len(out)))
	le.PutUint16(out[6:], uint16(len(payload)))
	copy(out[8:], payload)
	return out, nil
}

// ParseLiteralResourceReference accepts only the literal form of an MRM blob.
// Other valid MRM reference flags are deliberately not interpreted as text.
// It validates the writer's canonical zero padding and exact payload extent.
func ParseLiteralResourceReference(data []byte) (string, error) {
	if len(data) < 12 || len(data) > maxReferenceSize || len(data)%4 != 0 ||
		le.Uint16(data) != 0x100 || int(le.Uint16(data[2:])) != len(data) || le.Uint16(data[4:]) != 0 {
		return "", fmt.Errorf("dmr: invalid or nonliteral MRM reference")
	}
	n := int(le.Uint16(data[6:]))
	if n < 2 || n%2 != 0 || 8+align4(n) != len(data) {
		return "", fmt.Errorf("dmr: invalid literal resource extent")
	}
	if !zeroBytes(data[8+n:]) {
		return "", fmt.Errorf("dmr: nonzero literal resource padding")
	}
	if n == 2 {
		if le.Uint16(data[8:]) != 0 {
			return "", fmt.Errorf("dmr: unterminated empty literal")
		}
		return "", nil
	}
	return parseIdentityString(data[8 : 8+n])
}
