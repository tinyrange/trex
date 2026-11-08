package uup

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"strings"
	"testing"
)

func TestAssemblyDigestPrecedence(t *testing.T) {
	data := []byte("managed assembly content")
	sha := sha256.Sum256(data)
	legacy := sha1.Sum(data)
	file := AssemblyFile{Hash: "28edee27ab45e57e50c62675de8928ce2f9c3161", HashAlgorithm: "SHA1", Digest: &AssemblyFileDigest{
		Algorithm: assemblyDigestNamespace + "sha256", Transforms: []string{assemblyIdentityTransform}, Value: base64.StdEncoding.EncodeToString(sha[:]),
	}}
	got, err := assemblyFileSHA256(file)
	if err != nil || got == nil || *got != sha {
		t.Fatalf("independent digests: %v %v", got, err)
	}
	old, err := assemblyFileSHA1(file)
	if err != nil || old != nil {
		t.Fatalf("nested digest did not supersede legacy attribute: %v %v", old, err)
	}
	stage := &CumulativeStage{assemblyNameResolver: func(string) (storage.Reader, error) { return &starfile.Bytes{Data: data}, nil }}
	effect := StageFileEffect{SourceMode: "installed", SourceName: "assembly.dll", ExpectedSHA256: got, ExpectedSHA1: old}
	if _, err := stage.OpenPlannedFile(effect); err != nil {
		t.Fatal(err)
	}
	effect.ExpectedSHA1 = &[20]byte{}
	if _, err := stage.OpenPlannedFile(effect); err == nil || !strings.Contains(err.Error(), "SHA-1") {
		t.Fatalf("legacy mismatch not rejected: %v", err)
	}
	effect.ExpectedSHA1, effect.ExpectedSHA256 = old, &[32]byte{}
	if _, err := stage.OpenPlannedFile(effect); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("modern mismatch not rejected: %v", err)
	}
	// Legacy-only declarations remain mandatory, not merely advisory.
	file.Digest = nil
	file.Hash = hex.EncodeToString(legacy[:])
	old, err = assemblyFileSHA1(file)
	if err != nil || old == nil || *old != legacy {
		t.Fatalf("legacy-only digest: %v %v", old, err)
	}
	effect.ExpectedSHA1, effect.ExpectedSHA256 = old, nil
	if _, err := stage.OpenPlannedFile(effect); err != nil {
		t.Fatal(err)
	}
	file.Digest = &AssemblyFileDigest{
		Algorithm: assemblyDigestNamespace + "sha256", Transforms: []string{assemblyIdentityTransform}, Value: base64.StdEncoding.EncodeToString(sha[:]),
	}
	for _, bad := range []string{"", "0011", strings.Repeat("z", 40)} {
		file.Hash = bad
		if _, err := assemblyFileSHA1(file); err == nil {
			t.Fatalf("accepted malformed legacy digest %q", bad)
		}
	}
	file.Hash = hex.EncodeToString(legacy[:])
	file.Digest.Transforms = []string{"unsupported"}
	if _, err := assemblyFileSHA1(file); err == nil {
		t.Fatal("invalid nested digest fell back to legacy")
	}
	file.Digest.Transforms = []string{assemblyIdentityTransform}
	file.Hash, file.HashAlgorithm = strings.Repeat("0", 64), "SHA256"
	if _, err := assemblyFileSHA256(file); err == nil {
		t.Fatal("accepted conflicting SHA256")
	}
	file.Hash, file.HashAlgorithm = hex.EncodeToString(legacy[:]), "MD5"
	if _, err := assemblyFileSHA256(file); err == nil {
		t.Fatal("accepted unknown attribute algorithm")
	}
}
