package windows

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

func TestSignatureTimestampBinding(t *testing.T) {
	identity := signingTestIdentity(t)
	primary := &verifiedPEIntegrity{signature: []byte("primary authenticode signature")}
	info := signatureTimestampInfo{Version: 1, Policy: asn1.ObjectIdentifier{1, 2, 3, 4}, Serial: big.NewInt(1), Time: time.Unix(1746602099, 0).UTC()}
	info.Imprint.Algorithm.Algorithm = sha256OID
	imprint := sha256.Sum256(primary.signature)
	info.Imprint.Digest = imprint[:]
	content, err := asn1.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	contentHash := sha256.Sum256(content)
	attrs := signingSet(signingAttribute(pkcsContentTypeOID, signingOID(timestampContentOID)), signingAttribute(pkcsMessageDigestOID, signingTLV(4, contentHash[:])))
	attrsHash := sha256.Sum256(attrs)
	sig, err := rsa.SignPKCS1v15(rand.Reader, identity.key, crypto.SHA256, attrsHash[:])
	if err != nil {
		t.Fatal(err)
	}
	attrs[0] = 0xa0
	serial, err := asn1.Marshal(identity.certificate.SerialNumber)
	if err != nil {
		t.Fatal(err)
	}
	signer := signingSequence([]byte{2, 1, 1}, signingSequence(identity.certificate.RawIssuer, serial), signingAlgorithm(sha256OID), attrs, signingAlgorithm(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}), signingTLV(4, sig))
	certs := signingTLV(0xa0, append(append([]byte(nil), identity.certificate.Raw...), []byte{0xa1, 0}...))
	sd := signingSequence([]byte{2, 1, 3}, signingSet(signingAlgorithm(sha256OID)), signingSequence(signingOID(timestampContentOID), signingTLV(0xa0, signingTLV(4, content))), certs, signingSet(signer))
	token := signingSequence(signingOID(pkcs7SignedDataOID), signingTLV(0xa0, sd))
	attribute := signingAttribute(microsoftRFC3161OID, token)
	primary.unsigned = signingSet(attribute)
	primary.unsigned[0] = 0xa1
	timestamp, err := verifySignatureTimestamp(primary)
	if err != nil {
		t.Fatal(err)
	}
	if timestamp == nil || !timestamp.time.Equal(info.Time) || !bytes.Equal(timestamp.integrity.signer.Raw, identity.certificate.Raw) || len(timestamp.integrity.certificates) != 1 {
		t.Fatal("timestamp identity/time")
	}
	copied := *primary
	copied.signature = []byte("a different executable signature")
	if _, err := verifySignatureTimestamp(&copied); err == nil {
		t.Fatal("replayed timestamp accepted")
	}
	copied = *primary
	copied.unsigned = append([]byte(nil), primary.unsigned...)
	offset := bytes.Index(copied.unsigned, sig)
	if offset < 0 {
		t.Fatal("signature missing")
	}
	copied.unsigned[offset] ^= 1
	if _, err := verifySignatureTimestamp(&copied); err == nil {
		t.Fatal("forged timestamp accepted")
	}
	copied = *primary
	copied.unsigned = signingSet(attribute, attribute)
	copied.unsigned[0] = 0xa1
	if _, err := verifySignatureTimestamp(&copied); err == nil {
		t.Fatal("duplicate timestamp accepted")
	}
	copied.unsigned = nil
	if got, err := verifySignatureTimestamp(&copied); err != nil || got != nil {
		t.Fatal("absent timestamp must remain absent")
	}
}
