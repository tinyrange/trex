package uup

import (
	"fmt"
	"strings"
)

// CSIWinnerFamilyKey formats a SOFTWARE SideBySide/Winners family key from a
// full CSI identity. It omits version, but retains type and versionScope in the
// native hash. Neither attribute is a readable prefix (native typeName is a
// different, unsupported attribute). This does not select or install a winner.
func CSIWinnerFamilyKey(data []byte) (string, error) {
	id, err := parseCSIIdentity(data)
	if err != nil {
		return "", err
	}
	if err := validateCSIIdentity(id); err != nil {
		return "", err
	}
	hash, err := csiIdentityHash(id, true)
	if err != nil {
		return "", err
	}
	arch := strings.ToLower(id.ProcessorArchitecture)
	// Native LH key-form architecture table, not arbitrary path text.
	switch arch {
	case "x86", "ia64", "amd64", "arm", "arm64", "msil", "data", "wow64",
		"amd64.x86", "arm64.x86", "arm64.arm", "arm.x86":
	default:
		return "", fmt.Errorf("unsupported CSI key architecture %q", arch)
	}
	token := strings.ToLower(id.PublicKeyToken)
	if len(token) != 16 || strings.Trim(token, "0123456789abcdef") != "" {
		return "", fmt.Errorf("unsupported CSI key public key token %q", token)
	}
	name := csiKeyFormPart(id.Name, 40)
	if name == "" {
		return "", fmt.Errorf("CSI key name has no printable key characters")
	}
	culture := strings.ToLower(id.Language)
	if culture == "neutral" || culture == "none" {
		culture = "none"
	} else {
		culture = csiKeyFormPart(culture, 8)
	}
	if culture == "" {
		return "", fmt.Errorf("CSI key culture has no printable key characters")
	}
	return fmt.Sprintf("%s_%s_%s_%s_%016x", arch, name, token, culture, hash), nil
}

// Native LH key-form scans valid ASCII characters alternately from both ends.
// If the output fills while any raw input remains, the middle two characters
// become dots. Filtering first would be wrong when only punctuation remains
// at the midpoint. Non-ASCII has already been rejected by csiIdentityHash.
func csiKeyFormPart(text string, limit int) string {
	safe := func(c byte) byte {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' {
			return c
		}
		return 0
	}
	out := make([]byte, limit)
	left, right, front, back := 0, len(text)-1, 0, limit-1
	for left <= right && front <= back {
		var first, last byte
		for left <= right && first == 0 {
			first = safe(text[left])
			left++
		}
		if first == 0 {
			break
		}
		for left <= right && last == 0 {
			last = safe(text[right])
			right--
		}
		out[front] = first
		front++
		if last == 0 {
			break
		}
		out[back] = last
		back--
	}
	if front > back && left <= right {
		out[front-1], out[front] = '.', '.'
	}
	return string(out[:front]) + string(out[back+1:])
}
