package windows

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"testing"
)

func TestSerializedCertificateProperties(t *testing.T) {
	der := signingTestIdentity(t).certificate.Raw
	property := func(id uint32, data []byte) []byte {
		result := make([]byte, 12+len(data))
		binary.LittleEndian.PutUint32(result, id)
		binary.LittleEndian.PutUint32(result[4:], 1)
		binary.LittleEndian.PutUint32(result[8:], uint32(len(data)))
		copy(result[12:], data)
		return result
	}
	hash := sha1.Sum(der)
	blob := append(property(3, hash[:]), property(32, der)...)
	blob = append(blob, property(105, []byte{1, 2, 3})...)
	cert, props, err := parseSerializedCertificate(blob)
	if err != nil || !bytes.Equal(cert.Raw, der) || !bytes.Equal(props[105], []byte{1, 2, 3}) {
		t.Fatalf("properties: %v", err)
	}
	// Unknown properties remain observations, never automatic trust policy.
	blob[len(blob)-1] ^= 1
	if props[105][2] != 3 {
		t.Fatal("properties alias input")
	}
	for _, bad := range [][]byte{
		nil, property(3, hash[:]), property(32, []byte{1}),
		append(property(32, der), property(32, der)...),
		append(property(32, der), property(3, make([]byte, 20))...),
		append(property(32, der), 1),
	} {
		if _, _, err := parseSerializedCertificate(bad); err == nil {
			t.Fatal("accepted malformed certificate blob")
		}
	}
	for end := 0; end < len(property(32, der)); end++ {
		if _, _, err := parseSerializedCertificate(property(32, der)[:end]); err == nil {
			t.Fatalf("accepted truncation %d", end)
		}
	}
	for _, offset := range []int{4, 8} {
		bad := property(32, der)
		binary.LittleEndian.PutUint32(bad[offset:], 0xffffffff)
		if _, _, err := parseSerializedCertificate(bad); err == nil {
			t.Fatal("accepted invalid encoding/size")
		}
	}
	excessive := property(32, der)
	for i := uint32(1000); i < 1256; i++ {
		excessive = append(excessive, property(i, nil)...)
	}
	if _, _, err := parseSerializedCertificate(excessive); err == nil {
		t.Fatal("accepted excessive properties")
	}
}
