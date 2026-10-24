package appx

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"strings"
	"unicode/utf16"
)

// PublisherID is the package identity hash, not a signature or trust decision.
// Windows hashes the exact UTF-16LE publisher and encodes its first 64 bits
// using the package identity base32 alphabet (most significant bits first).
func (i Identity) PublisherID() string {
	units := utf16.Encode([]rune(i.Publisher))
	data := make([]byte, len(units)*2)
	for n, u := range units {
		binary.LittleEndian.PutUint16(data[n*2:], u)
	}
	digest := sha256.Sum256(data)
	return base32.NewEncoding("0123456789abcdefghjkmnpqrstvwxyz").WithPadding(base32.NoPadding).EncodeToString(digest[:8])
}

func (i Identity) FamilyName() string { return i.Name + "_" + i.PublisherID() }

func (a *Archive) FullName() string {
	arch, resource := a.Identity.Architecture, a.Identity.ResourceID
	if a.Kind == "bundle" {
		arch, resource = "neutral", "~"
	}
	if arch == "" {
		arch = "neutral"
	}
	return strings.Join([]string{a.Identity.Name, a.Identity.Version, arch, resource, a.Identity.PublisherID()}, "_")
}
