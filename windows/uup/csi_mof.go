package uup

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"strings"
)

// AssemblyMOF is an ordered CSI MOF declaration. UninstallPresent distinguishes
// an omitted uninstallmof attribute from one with an empty value.
type AssemblyMOF struct {
	Name             string
	Uninstall        string
	UninstallPresent bool
	Attributes       []ManifestAttribute
}

func parseAssemblyMOF(decoder *xml.Decoder, root xml.StartElement) (AssemblyMOF, error) {
	result := AssemblyMOF{Attributes: manifestAttributes(root.Attr)}
	seen := map[xml.Name]bool{}
	for _, a := range root.Attr {
		if seen[a.Name] {
			return result, fmt.Errorf("duplicate MOF attribute %s", a.Name)
		}
		seen[a.Name] = true
		if a.Name.Space != "" {
			continue
		}
		switch a.Name.Local {
		case "name":
			result.Name = a.Value
		case "uninstallmof":
			result.Uninstall, result.UninstallPresent = a.Value, true
		}
	}
	if result.Name == "" {
		return result, fmt.Errorf("missing MOF name")
	}
	for {
		token, err := decoder.Token()
		if err != nil {
			return result, err
		}
		switch t := token.(type) {
		case xml.EndElement:
			if t.Name != root.Name {
				return result, fmt.Errorf("unbalanced MOF declaration")
			}
			return result, nil
		case xml.CharData:
			if strings.TrimSpace(string(t)) != "" {
				return result, fmt.Errorf("unexpected MOF text")
			}
		case xml.Comment:
		default:
			return result, fmt.Errorf("unsupported MOF child content")
		}
	}
}

// CSIFileHashesEqual implements the comparable-hash part of WCP's file
// equivalence predicate, not file verification. Either comparable mismatch
// vetoes equality; absent or incomparable hashes alone cannot prove equality.
// The supported subset is SHA1/SHA256 and zero or one Identity transform.
// Unsupported algorithms/transforms are errors, not evidence of equality.
func CSIFileHashesEqual(left, right AssemblyFile) (bool, error) {
	nested := 0 // unknown=0, mismatch=1, match=2, as in WCP
	if left.Digest != nil && right.Digest != nil {
		la, err := csiDigestKind(left.Digest)
		if err != nil {
			return false, err
		}
		ra, err := csiDigestKind(right.Digest)
		if err != nil {
			return false, err
		}
		if la == ra && len(left.Digest.Transforms) == len(right.Digest.Transforms) {
			nested = 1
			// WCP compares the digest's text by ordinal, not decoded digest bytes.
			if left.Digest.Value == right.Digest.Value {
				nested = 2
			}
		}
	}
	if nested == 1 {
		return false, nil
	}
	legacy := 0
	if left.Hash != "" && right.Hash != "" {
		if left.HashAlgorithm != "SHA1" || right.HashAlgorithm != "SHA1" {
			return false, fmt.Errorf("unsupported CSI legacy file hash algorithm")
		}
		for _, value := range []string{left.Hash, right.Hash} {
			b, err := hex.DecodeString(value)
			if err != nil || len(b) != 20 {
				return false, fmt.Errorf("invalid CSI legacy SHA1")
			}
		}
		legacy = 1
		if strings.EqualFold(left.Hash, right.Hash) {
			legacy = 2
		}
	}
	return legacy != 1 && (legacy == 2 || nested == 2), nil
}

func csiDigestKind(d *AssemblyFileDigest) (string, error) {
	kind, size := "", 0
	switch d.Algorithm {
	case assemblyDigestNamespace + "sha1":
		kind, size = "sha1", 20
	case assemblyDigestNamespace + "sha256", "http://www.w3.org/2001/04/xmlenc#sha256":
		kind, size = "sha256", 32
	default:
		return "", fmt.Errorf("unsupported CSI file digest algorithm %q", d.Algorithm)
	}
	if len(d.Transforms) > 1 || (len(d.Transforms) == 1 && d.Transforms[0] != assemblyIdentityTransform) {
		return "", fmt.Errorf("unsupported CSI file digest transform sequence")
	}
	b, err := base64.StdEncoding.Strict().DecodeString(d.Value)
	if err != nil || len(b) != size {
		return "", fmt.Errorf("invalid CSI %s digest", kind)
	}
	return kind, nil
}

// CSIMOFEquivalent evaluates MofDiffer's ordered declaration/file-hash predicate
// observed in servicing stack 10.0.26100.9441. This is NOT an installer queue,
// a proof that inspection is unnecessary, or execution of MOF registration.
// File lookup is case insensitive; declaration strings are case sensitive.
// The native uninstall branch compares the uninstall string but rechecks the
// PRIMARY file's hash, not the uninstall file's hash. Do not silently strengthen
// this predicate into a different algorithm. Payload authenticity is separate.
func CSIMOFEquivalent(left, right *AssemblyManifest) (bool, error) {
	if left == nil || right == nil {
		return false, fmt.Errorf("MOF comparison requires two manifests")
	}
	if len(left.MOFs) != len(right.MOFs) {
		return false, nil
	}
	if len(left.MOFs) == 0 {
		return true, nil
	}
	indexes := [2]map[string]AssemblyFile{}
	for i, m := range []*AssemblyManifest{left, right} {
		indexes[i] = map[string]AssemblyFile{}
		for _, f := range m.Files {
			// Restrict this projection to ASCII: Go Unicode folding is not Windows
			// ordinal case folding. Do not substitute a different equivalence relation.
			if !csiASCII(f.Name) {
				return false, fmt.Errorf("non-ASCII CSI file lookup is not supported")
			}
			key := strings.ToLower(f.Name)
			if _, exists := indexes[i][key]; exists {
				return false, fmt.Errorf("ambiguous CSI file name %q", f.Name)
			}
			indexes[i][key] = f
		}
	}
	for i, a := range left.MOFs {
		b := right.MOFs[i]
		for _, m := range []AssemblyMOF{a, b} {
			for _, attr := range m.Attributes {
				if attr.Namespace == "xmlns" || (attr.Namespace == "" && attr.Name == "xmlns") {
					continue
				}
				if attr.Namespace != "" || (attr.Name != "name" && attr.Name != "uninstallmof") {
					return false, fmt.Errorf("unsupported MOF attribute %s:%s", attr.Namespace, attr.Name)
				}
			}
			if m.Name == "" || !csiASCII(m.Name) {
				return false, fmt.Errorf("unsupported MOF file name")
			}
		}
		if a.Name != b.Name || a.UninstallPresent != b.UninstallPresent || (a.UninstallPresent && a.Uninstall != b.Uninstall) {
			return false, nil
		}
		// GetLeafFileName splits on a backslash only, not host path separators.
		leaf := a.Name[strings.LastIndexByte(a.Name, 0x5c)+1:]
		if leaf == "" {
			return false, fmt.Errorf("empty MOF leaf name")
		}
		af, aok := indexes[0][strings.ToLower(leaf)]
		bf, bok := indexes[1][strings.ToLower(leaf)]
		if !aok || !bok {
			return false, nil
		}
		equal, err := CSIFileHashesEqual(af, bf)
		if err != nil || !equal {
			return false, err
		}
	}
	return true, nil
}

func csiASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 || s[i] == 0 {
			return false
		}
	}
	return true
}
