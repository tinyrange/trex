package uup

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestAssemblyNestedFileDigest(t *testing.T) {
	const declaration = `<h:hash xmlns:h="urn:schemas-microsoft-com:asm.v2" xmlns:d="http://www.w3.org/2000/09/xmldsig#"><d:Transforms><d:Transform Algorithm="urn:schemas-microsoft-com:HashTransforms.Identity"/></d:Transforms><d:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha256"/><d:DigestValue>ZF4nwEU46AebDbYs7xS2NT3YOhsJpop9bBtp6Dz9ZeM=</d:DigestValue></h:hash>`
	parse := func(hash string) (*AssemblyManifest, error) {
		return ParseAssemblyManifest(strings.NewReader(`<assembly><assemblyIdentity name="control"/><file name="comctl32.dll">` + hash + `</file><file name="other"/></assembly>`))
	}
	manifest, err := parse(declaration)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := assemblyFileSHA256(manifest.Files[0])
	if err != nil || digest == nil || hex.EncodeToString(digest[:]) != "645e27c04538e8079b0db62cef14b6353dd83a1b09a68a7d6c1b69e83cfd65e3" || manifest.Files[1].Digest != nil {
		t.Fatalf("digest/scoping: %+v %v", digest, err)
	}
	for _, bad := range []string{
		declaration + declaration,
		strings.Replace(declaration, "</h:hash>", "<d:DigestValue>bad</d:DigestValue></h:hash>", 1),
		strings.Replace(declaration, "<d:Transforms>", "<d:Unknown>", 1),
		strings.Replace(declaration, "ZF4nwEU46AebDbYs7xS2NT3YOhsJpop9bBtp6Dz9ZeM=", strings.Repeat("A", 4097), 1),
		strings.Replace(declaration, "<d:DigestValue>", "<d:DigestValue><d:DigestValue>", 1),
	} {
		if _, err := parse(bad); err == nil {
			t.Fatal("accepted malformed/duplicate digest")
		}
	}
	for _, bad := range []string{
		strings.Replace(declaration, "HashTransforms.Identity", "HashTransforms.PEImage", 1),
		strings.Replace(declaration, "#sha256", "#sha1", 1),
		strings.Replace(declaration, "ZF4nwEU46AebDbYs7xS2NT3YOhsJpop9bBtp6Dz9ZeM=", "AAAA", 1),
	} {
		manifest, err := parse(bad)
		if err != nil {
			t.Fatal("inspection must retain declared unsupported digest", err)
		}
		if _, err := assemblyFileSHA256(manifest.Files[0]); err == nil {
			t.Fatal("accepted non-raw or malformed SHA-256")
		}
	}
	file := manifest.Files[0]
	file.Hash, file.HashAlgorithm = strings.Repeat("0", 64), "sha256"
	if _, err := assemblyFileSHA256(file); err == nil {
		t.Fatal("accepted conflicting attribute digest")
	}
}
