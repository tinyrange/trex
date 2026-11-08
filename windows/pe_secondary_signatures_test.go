package windows

import (
	"encoding/asn1"
	"testing"
)

func TestSecondarySignatureMetadata(t *testing.T) {
	encode := func(attributes []signatureAttribute) []byte {
		t.Helper()
		data, err := asn1.MarshalWithParams(attributes, "set")
		if err != nil {
			t.Fatal(err)
		}
		data[0] = 0xa1
		return data
	}
	nested := signatureAttribute{Type: spcNestedSignatureOID, Values: []asn1.RawValue{{FullBytes: []byte{0x30, 0}}, {FullBytes: []byte{0x30, 0}}}}
	unrelated := signatureAttribute{Type: microsoftRFC3161OID, Values: []asn1.RawValue{{FullBytes: []byte{0x30, 0}}}}
	for _, tc := range []struct {
		raw  []byte
		want int
	}{
		{nil, 0}, {encode([]signatureAttribute{unrelated}), 0},
		{encode([]signatureAttribute{unrelated, nested}), 2},
	} {
		got, err := secondarySignatureCount(tc.raw)
		if err != nil || got != tc.want {
			t.Fatalf("count=%d error=%v want=%d", got, err, tc.want)
		}
	}
	valid := encode([]signatureAttribute{nested})
	for _, raw := range [][]byte{
		{0xa1}, {0x31, 0}, valid[:len(valid)-1], append(append([]byte(nil), valid...), 0),
		encode([]signatureAttribute{nested, nested}),
		encode([]signatureAttribute{{Type: spcNestedSignatureOID}}),
	} {
		if _, err := secondarySignatureCount(raw); err == nil {
			t.Fatalf("accepted malformed attributes %x", raw)
		}
	}
}
