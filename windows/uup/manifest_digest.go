package uup

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"strings"
)

const assemblyDigestNamespace = "http://www.w3.org/2000/09/xmldsig#"
const assemblyIdentityTransform = "urn:schemas-microsoft-com:HashTransforms.Identity"

// Consume only the bounded file/hash subtree; prefixes are irrelevant, but
// namespace, shape, duplicate fields and text bounds are not.
func parseAssemblyFileDigest(decoder *xml.Decoder, root xml.StartElement, elements *int) (*AssemblyFileDigest, error) {
	result := &AssemblyFileDigest{}
	stack := []string{"hash"}
	seen := make(map[string]bool)
	for len(stack) != 0 {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		switch token := token.(type) {
		case xml.StartElement:
			*elements++
			if *elements > maximumManifestElements || len(stack) > 3 {
				return nil, fmt.Errorf("assembly file hash structure exceeds bound")
			}
			parent := stack[len(stack)-1]
			name := token.Name.Local
			if token.Name.Space != assemblyDigestNamespace || !((parent == "hash" && (name == "Transforms" || name == "DigestMethod" || name == "DigestValue")) || (parent == "Transforms" && name == "Transform")) {
				return nil, fmt.Errorf("unsupported assembly file hash element %s", token.Name)
			}
			if seen[name] && name != "Transform" {
				return nil, fmt.Errorf("duplicate assembly file hash element %s", name)
			}
			seen[name] = true
			algorithm := ""
			for _, a := range token.Attr {
				if a.Name.Local == "Algorithm" && a.Name.Space == "" {
					if algorithm != "" {
						return nil, fmt.Errorf("duplicate file hash algorithm")
					}
					algorithm = a.Value
				}
			}
			if name == "Transform" || name == "DigestMethod" {
				if algorithm == "" {
					return nil, fmt.Errorf("missing file hash algorithm")
				}
				if name == "Transform" {
					if len(result.Transforms) >= 16 {
						return nil, fmt.Errorf("too many file hash transforms")
					}
					result.Transforms = append(result.Transforms, algorithm)
				} else {
					result.Algorithm = algorithm
				}
			}
			stack = append(stack, name)
		case xml.CharData:
			if stack[len(stack)-1] == "DigestValue" {
				if len(result.Value)+len(token) > 4096 {
					return nil, fmt.Errorf("assembly file digest exceeds text bound")
				}
				result.Value += string(token)
			} else if strings.TrimSpace(string(token)) != "" {
				return nil, fmt.Errorf("unexpected assembly file hash text")
			}
		case xml.EndElement:
			if token.Name.Local != stack[len(stack)-1] || (len(stack) == 1 && token.Name != root.Name) {
				return nil, fmt.Errorf("unbalanced assembly file hash")
			}
			stack = stack[:len(stack)-1]
		}
	}
	if !seen["DigestMethod"] || !seen["DigestValue"] {
		return nil, fmt.Errorf("incomplete assembly file digest")
	}
	return result, nil
}

func assemblyNestedSHA256(d *AssemblyFileDigest) (string, error) {
	if d.Algorithm != assemblyDigestNamespace+"sha256" && d.Algorithm != "http://www.w3.org/2001/04/xmlenc#sha256" {
		return "", fmt.Errorf("unsupported assembly file digest algorithm %q", d.Algorithm)
	}
	for _, transform := range d.Transforms {
		if transform != assemblyIdentityTransform {
			return "", fmt.Errorf("unsupported assembly file digest transform %q", transform)
		}
	}
	value := strings.Join(strings.Fields(d.Value), "")
	data, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(data) != 32 {
		return "", fmt.Errorf("invalid assembly file SHA-256 digest")
	}
	return hex.EncodeToString(data), nil
}
