package uup

import (
	"fmt"
	"strings"
)

// packageKey resolves immutable package names without reparsing an identity.
// The fallback retains the filename parser's validation and alias semantics.
func (index *CBSUpdateStateIndex) packageKey(name string) (string, error) {
	if index == nil {
		return "", fmt.Errorf("nil CBS update index")
	}
	if key, ok := index.names[name]; ok {
		return key, nil
	}
	if key, ok := index.names[strings.ToLower(name)]; ok {
		return key, nil
	}
	id, err := ParsePackageManifestName(name + ".mum")
	if err != nil {
		return "", err
	}
	return id.ExactKey(), nil
}

// PackageIdentity reuses validated immutable input identities. A caller must
// not mutate the returned identity's attribute slice.
func (index *CBSUpdateStateIndex) PackageIdentity(name string) (AssemblyIdentity, error) {
	key, err := index.packageKey(name)
	if err != nil {
		return AssemblyIdentity{}, err
	}
	if ctx := index.graph.packages.get(key); ctx != nil {
		return ctx.input.Manifest.Identity, nil
	}
	return ParsePackageManifestName(name + ".mum")
}

// PackageIntendedStateByName queries this snapshot, never a cached state from
// another execution. Only the name-to-key index is shared across snapshots.
func (index *CBSUpdateStateIndex) PackageIntendedStateByName(name string) (uint32, error) {
	key, err := index.packageKey(name)
	if err != nil {
		return 0, err
	}
	if ctx := index.graph.packages.get(key); ctx != nil {
		return ctx.input.IntendedState, nil
	}
	id, err := ParsePackageManifestName(name + ".mum")
	if err != nil {
		return 0, err
	}
	return index.PackageIntendedState(id)
}
