package uup

import (
	"fmt"
	"strings"
)

// cbsPackageName is independent of the transport member name: aggregate
// packages arrive as update.mum/update.cat, but each has its own identity in
// the CBS package store and CatRoot. Transport aliases must never overwrite
// another stage's package or masquerade as the package identity.
func cbsPackageName(id AssemblyIdentity) (string, error) {
	if err := validateCSIIdentity(id); err != nil {
		return "", err
	}
	language := id.Language
	if strings.EqualFold(language, "neutral") || strings.EqualFold(language, "none") {
		language = ""
	}
	name := strings.Join([]string{id.Name, id.PublicKeyToken, id.ProcessorArchitecture, language, id.Version}, "~")
	parsed, err := ParsePackageManifestName(name + ".mum")
	if err != nil || parsed.ExactKey() != id.ExactKey() || strings.ContainsAny(name, `/\`) {
		return "", fmt.Errorf("invalid CBS package identity %q", name)
	}
	return name, nil
}
