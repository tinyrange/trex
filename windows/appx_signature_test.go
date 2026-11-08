package windows

import (
	"archive/zip"
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"testing"
)

func appxTestZIP(t *testing.T, signature []byte, zip64 bool) []byte {
	t.Helper()
	var out bytes.Buffer
	z := zip.NewWriter(&out)
	for _, entry := range []struct {
		name string
		data []byte
	}{
		{"payload.bin", []byte("authenticated payload bytes")},
		{"AppxBlockMap.xml", []byte("<BlockMap/>")},
		{"[Content_Types].xml", []byte("<Types/>")},
		{"AppxSignature.p7x", signature},
	} {
		w, err := z.CreateHeader(&zip.FileHeader{Name: entry.name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	data := out.Bytes()
	if !zip64 {
		return data
	}
	end := append([]byte(nil), data[len(data)-22:]...)
	le := binary.LittleEndian
	tail := make([]byte, 76)
	le.PutUint32(tail, 0x06064b50)
	le.PutUint64(tail[4:], 44)
	le.PutUint16(tail[12:], 45)
	le.PutUint16(tail[14:], 45)
	le.PutUint64(tail[24:], 4)
	le.PutUint64(tail[32:], 4)
	le.PutUint64(tail[40:], uint64(le.Uint32(end[12:])))
	le.PutUint64(tail[48:], uint64(le.Uint32(end[16:])))
	le.PutUint32(tail[56:], 0x07064b50)
	le.PutUint64(tail[64:], uint64(len(data)-22))
	le.PutUint32(tail[72:], 1)
	le.PutUint16(end[8:], 0xffff)
	le.PutUint16(end[10:], 0xffff)
	le.PutUint32(end[12:], 0xffffffff)
	le.PutUint32(end[16:], 0xffffffff)
	return append(append(data[:len(data)-22], tail...), end...)
}

func TestAppxSignatureIntegrityAndTampering(t *testing.T) {
	identity := signingTestIdentity(t)
	for _, zip64 := range []bool{false, true} {
		placeholder := appxTestZIP(t, []byte("PKCX"), zip64)
		parts, err := appxPackageHashes(placeholder)
		if err != nil {
			t.Fatal(err)
		}
		table := []byte("APPX")
		for _, name := range []string{"AXPC", "AXCD", "AXCT", "AXBM"} {
			table = append(table, []byte(name)...)
			table = append(table, parts.hashes[name]...)
		}
		sip, err := asn1.Marshal(appxSIPInfo{Version: 0x01010000, UUID: appxSIPUUID})
		if err != nil {
			t.Fatal(err)
		}
		sign := func(digest []byte) []byte {
			indirect := signingSequence(signingSequence(signingOID(appxSIPOID), sip), signingSequence(signingAlgorithm(sha256OID), signingTLV(4, digest)))
			signed, err := signPKCS7Content(indirect, spcIndirectOID, identity)
			if err != nil {
				t.Fatal(err)
			}
			return append([]byte("PKCX"), signed...)
		}
		signature := sign(table)
		data := appxTestZIP(t, signature, zip64)
		got, err := verifyAppxIntegrity(data)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.signer.Raw, identity.certificate.Raw) {
			t.Fatal("incorrect signer")
		}
		// A correctly re-signed but false declaration of any digest domain
		// must fail independently of the CMS signature's mathematical validity.
		for i := 0; i < 4; i++ {
			wrong := append([]byte(nil), table...)
			wrong[8+36*i] ^= 1
			if _, err := verifyAppxIntegrity(appxTestZIP(t, sign(wrong), zip64)); err == nil {
				t.Fatalf("accepted digest domain %d", i)
			}
		}
		// Duplicate domains cannot stand in for a missing domain.
		wrong := append([]byte(nil), table...)
		copy(wrong[40:44], "AXPC")
		if _, err := verifyAppxIntegrity(appxTestZIP(t, sign(wrong), zip64)); err == nil {
			t.Fatal("duplicate digest accepted")
		}
		broken := append([]byte(nil), signature...)
		pos := bytes.Index(broken, got.signature)
		if pos < 0 {
			t.Fatal("signature bytes absent")
		}
		broken[pos] ^= 1
		if _, err := verifyAppxIntegrity(appxTestZIP(t, broken, zip64)); err == nil {
			t.Fatal("invalid RSA signature accepted")
		}
		for _, offset := range []int{0, 35, len(data) - 1, len(data) - 10} {
			corrupt := append([]byte(nil), data...)
			corrupt[offset] ^= 1
			if _, err := verifyAppxIntegrity(corrupt); err == nil {
				t.Fatalf("accepted mutation at %d", offset)
			}
		}
		for _, size := range []int{0, 21, len(data) - 1} {
			if _, err := verifyAppxIntegrity(data[:size]); err == nil {
				t.Fatal("truncation accepted")
			}
		}
	}
}
