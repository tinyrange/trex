package windows

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestPESignatureIntegrityAndTampering(t *testing.T) {
	identity := signingTestIdentity(t)
	for _, machine := range []uint16{0x14c, 0x8664, 0xaa64} {
		signed, err := signPE(signingTestPE(machine), identity, false)
		if err != nil {
			t.Fatal(err)
		}
		got, err := verifyPEIntegrity(signed)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.signer.Raw, identity.certificate.Raw) || len(got.certificates) != 1 {
			t.Fatal("incorrect signer")
		}
		layout, err := signingPELayout(signed)
		if err != nil {
			t.Fatal(err)
		}
		signatureOffset := bytes.Index(signed, got.signature)
		if signatureOffset < 0 {
			t.Fatal("signature absent")
		}
		for _, offset := range []int{0x210, 0x440, signatureOffset, layout.certificate + 8} {
			bad := append([]byte(nil), signed...)
			bad[offset] ^= 1
			if _, err := verifyPEIntegrity(bad); err == nil {
				t.Fatalf("tampering at %x accepted", offset)
			}
		}
		checksum := append([]byte(nil), signed...)
		binary.LittleEndian.PutUint32(checksum[0x98+64:], 0x12345678)
		if _, err := verifyPEIntegrity(checksum); err != nil {
			t.Fatalf("excluded checksum: %v", err)
		}
		for _, size := range []int{0, 0x40, 0x98, layout.certificate + 4, len(signed) - 1} {
			if _, err := verifyPEIntegrity(signed[:size]); err == nil {
				t.Fatalf("truncation %d accepted", size)
			}
		}
	}
	if _, err := verifyPEIntegrity(signingTestPE(0x8664)); err == nil {
		t.Fatal("unsigned accepted")
	}
}
