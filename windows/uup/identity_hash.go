package uup

import (
	"github.com/tinyrange/trex/windows/internal/csihash"
	"strings"
)

// csiTextHash implements the CSI identity-name arithmetic as a polynomial over
// four interleaved 32-bit X65599 streams, combined in base (2^33 - 9). This is
// an identity discriminator, NOT a cryptographic/content-integrity hash.
// The equations were checked against 30,753 component identities and 4,143
// deployment appids in native 26300.9457 COMPONENTS. Only the observed ASCII
// identity alphabet is supported; Unicode folding must not be approximated.
func csiTextHash(text string) (uint64, error) {
	return csihash.Text(text)
}

func csiIdentityHash(id AssemblyIdentity, omitVersion bool) (uint64, error) {
	culture := id.Language
	if strings.EqualFold(culture, "neutral") {
		culture = ""
	}
	kind := ""
	for _, a := range id.Attributes {
		if a.Namespace == "" && strings.EqualFold(a.Name, "type") {
			kind = a.Value
		}
	}
	attributes := [][2]string{{"name", id.Name}, {"culture", culture}, {"type", kind}, {"version", id.Version}, {"publicKeyToken", id.PublicKeyToken}, {"processorArchitecture", id.ProcessorArchitecture}, {"versionScope", id.VersionScope}}
	const radix = uint64(1<<33) - 9
	var hash uint64
	for _, attribute := range attributes {
		if attribute[1] == "" || strings.EqualFold(attribute[1], "none") || (omitVersion && attribute[0] == "version") {
			continue
		}
		name, err := csiTextHash(attribute[0])
		if err != nil {
			return 0, err
		}
		value, err := csiTextHash(attribute[1])
		if err != nil {
			return 0, err
		}
		hash = radix*(hash+name) + value
	}
	return hash, nil
}
