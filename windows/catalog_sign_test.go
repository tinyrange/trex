package windows

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func TestCatalogSignMembersAndSignature(t *testing.T) {
	identity := signingTestIdentity(t)
	image := signingTestPE(0x8664)[:0x400]
	signedImage, err := signPE(image, identity, false)
	if err != nil {
		t.Fatal(err)
	}
	inf := []byte("[Version]\r\nSignature=\"$Windows NT$\"\r\nCatalogFile=test.cat\r\n")
	members := starlark.NewDict(2)
	_ = members.SetKey(starlark.String("Test.sys"), starlark.Bytes(signedImage))
	_ = members.SetKey(starlark.String("Test.inf"), starlark.Bytes(inf))
	value, err := catalogSignBuiltin(nil, nil, starlark.Tuple{members, identity, starlark.MakeInt64(1800000000)}, []starlark.Tuple{{starlark.String("os_attributes"), starlark.String("2:10.0")}})
	if err != nil {
		t.Fatal(err)
	}
	encoded := []byte(value.(starlark.Bytes))
	var outer testContentInfo
	unmarshalSigningTest(t, encoded, &outer)
	var sd testSignedData
	unmarshalSigningTest(t, outer.Content.Bytes, &sd)
	if !outer.Type.Equal(pkcs7SignedDataOID) || !sd.Content.Type.Equal(catalogCTLOID) || len(sd.Signers) != 1 {
		t.Fatal("wrong SignedData")
	}
	certs, err := x509.ParseCertificates(sd.Certificates.Bytes)
	if err != nil || len(certs) != 1 || !bytes.Equal(certs[0].Raw, identity.certificate.Raw) {
		t.Fatal("missing signer certificate", err)
	}
	signer := sd.Signers[0]
	attrs := bytes.Clone(signer.Attrs.FullBytes)
	attrs[0] = 0x31
	if err := identity.certificate.CheckSignature(x509.SHA256WithRSA, attrs, signer.Signature); err != nil {
		t.Fatal(err)
	}
	bad := bytes.Clone(attrs)
	bad[len(bad)-1] ^= 1
	if identity.certificate.CheckSignature(x509.SHA256WithRSA, bad, signer.Signature) == nil {
		t.Fatal("accepted altered authenticated attributes")
	}
	var ctl asn1.RawValue
	unmarshalSigningTest(t, sd.Content.Content.Bytes, &ctl)
	contentHash := sha256.Sum256(ctl.Bytes)
	var attributes []testAttribute
	rest, err := asn1.UnmarshalWithParams(attrs, &attributes, "set")
	if err != nil || len(rest) != 0 {
		t.Fatal(err)
	}
	foundHash, foundType := false, false
	for _, attr := range attributes {
		if attr.Type.Equal(pkcsMessageDigestOID) {
			var digest []byte
			unmarshalSigningTest(t, attr.Values[0].FullBytes, &digest)
			foundHash = bytes.Equal(digest, contentHash[:])
		}
		if attr.Type.Equal(pkcsContentTypeOID) {
			var typ asn1.ObjectIdentifier
			unmarshalSigningTest(t, attr.Values[0].FullBytes, &typ)
			foundType = typ.Equal(catalogCTLOID)
		}
	}
	if !foundHash || !foundType {
		t.Fatal("missing or incorrect authenticated content digest/type")
	}
	changed := bytes.Clone(ctl.Bytes)
	changed[len(changed)-1] ^= 1
	if sha256.Sum256(changed) == contentHash {
		t.Fatal("catalog tamper did not change content digest")
	}
	// Decode the CTL independently from the production index scanner.
	var decoded struct {
		Usage      []asn1.ObjectIdentifier
		Identifier []byte
		Created    time.Time
		Algorithm  struct {
			OID  asn1.ObjectIdentifier
			Null asn1.RawValue
		}
		Entries []struct {
			Tag        []byte
			Attributes []testAttribute `asn1:"set"`
		}
		Extensions asn1.RawValue `asn1:"explicit,tag:0"`
	}
	unmarshalSigningTest(t, ctl.FullBytes, &decoded)
	if len(decoded.Entries) != 2 || decoded.Created.Unix() != 1800000000 || len(decoded.Identifier) != 16 || !decoded.Algorithm.OID.Equal(catalogMemberOID) {
		t.Fatal("incorrect CTL header")
	}
	wantInf := sha256.Sum256(inf)
	wantImage, err := windowsCatalogHash(image, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	wants := [][]byte{wantInf[:], wantImage}
	for i, entry := range decoded.Entries {
		wantTag := catalogUTF16(strings.ToUpper(hex.EncodeToString(wants[i])), binary.LittleEndian, true)
		if !bytes.Equal(entry.Tag, wantTag) {
			t.Fatal("incorrect subject identifier")
		}
		var indirect testIndirect
		found := false
		for _, attr := range entry.Attributes {
			if attr.Type.Equal(spcIndirectOID) {
				unmarshalSigningTest(t, attr.Values[0].FullBytes, &indirect)
				found = true
			}
		}
		if !found || !indirect.Digest.Algorithm.Algorithm.Equal(sha256OID) || !bytes.Equal(indirect.Digest.Value, wants[i]) {
			t.Fatal("wrong member hash")
		}
		wantType := catalogFlatFileOID
		if i == 1 {
			wantType = spcPEImageOID
		}
		if !indirect.Data.Type.Equal(wantType) {
			t.Fatal("wrong subject interface")
		}
	}
	index, err := parseCatalogIndex(encoded)
	if err != nil || len(index) != 2 || !bytes.Equal(index[0], wants[0]) || !bytes.Equal(index[1], wants[1]) {
		t.Fatal("catalog index round trip", err)
	}
}

func TestCatalogSignRejectsInvalidInputs(t *testing.T) {
	identity := signingTestIdentity(t)
	for _, name := range []string{"", "../a.sys", "a\\b.sys", "C:a", "a\x00b", strings.Repeat("a", 256)} {
		members := starlark.NewDict(1)
		_ = members.SetKey(starlark.String(name), starlark.Bytes("file"))
		if _, err := catalogSignBuiltin(nil, nil, starlark.Tuple{members, identity, starlark.MakeInt64(1800000000)}, nil); err == nil {
			t.Fatalf("accepted name %q", name)
		}
	}
	members := starlark.NewDict(2)
	_ = members.SetKey(starlark.String("a.inf"), starlark.Bytes("a"))
	_ = members.SetKey(starlark.String("A.INF"), starlark.Bytes("a"))
	if _, err := catalogSignBuiltin(nil, nil, starlark.Tuple{members, identity, starlark.MakeInt64(1800000000)}, nil); err == nil {
		t.Fatal("accepted duplicate case-insensitive member")
	}
	if _, err := catalogSignBuiltin(nil, nil, starlark.Tuple{starlark.NewDict(0), identity, starlark.MakeInt64(1800000000)}, nil); err == nil {
		t.Fatal("accepted empty catalog")
	}
}

type catalogOversizedReader struct{ reads int }

func (*catalogOversizedReader) Size() int64 { return (64 << 20) + 1 }
func (r *catalogOversizedReader) ReadAt([]byte, int64) (int, error) {
	r.reads++
	return 0, fmt.Errorf("oversized catalog member must not be read")
}

func TestCatalogSignChecksDeclaredExtentBeforeReading(t *testing.T) {
	source := &catalogOversizedReader{}
	members := starlark.NewDict(1)
	_ = members.SetKey(starlark.String("large.sys"), starfile.NewReader("large", source))
	_, err := catalogSignBuiltin(nil, nil, starlark.Tuple{members, signingTestIdentity(t), starlark.MakeInt64(1800000000)}, nil)
	if err == nil || source.reads != 0 {
		t.Fatalf("error=%v, reads=%d", err, source.reads)
	}
}
