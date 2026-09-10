package uup

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type NamedAssemblyManifest struct {
	Path     string
	Manifest *AssemblyManifest
}

type AssemblyClosure struct {
	Packages   []NamedAssemblyManifest
	Components []NamedAssemblyManifest
}

type manifestCatalog struct {
	byExact  map[string]NamedAssemblyManifest
	byStable map[string][]NamedAssemblyManifest
}

// ResolveAssemblyClosure selects every updated package already represented in
// the image, then follows exact package/component references. References may
// also be satisfied by an unchanged exact identity already installed. Any
// other reference is rejected rather than silently producing a partial LCU.
func ResolveAssemblyClosure(installedPackages, installedComponents []AssemblyIdentity, targetPackages, targetComponents []NamedAssemblyManifest) (*AssemblyClosure, error) {
	packages, err := newManifestCatalog("package", targetPackages)
	if err != nil {
		return nil, err
	}
	components, err := newManifestCatalog("component", targetComponents)
	if err != nil {
		return nil, err
	}
	installedPackageExact := identitySet(installedPackages, false)
	installedComponentExact := identitySet(installedComponents, false)
	queue := make([]NamedAssemblyManifest, 0)
	queued := make(map[string]struct{})
	for _, identity := range installedPackages {
		candidate, ok := packages.latest(identity.StableKey())
		if !ok || compareVersions(candidate.Manifest.Identity.Version, identity.Version) <= 0 {
			continue
		}
		key := candidate.Manifest.Identity.ExactKey()
		if _, exists := queued[key]; !exists {
			queued[key] = struct{}{}
			queue = append(queue, candidate)
		}
	}
	closure := &AssemblyClosure{}
	selectedComponents := make(map[string]struct{})
	for len(queue) != 0 {
		current := queue[0]
		queue = queue[1:]
		closure.Packages = append(closure.Packages, current)
		for _, reference := range current.Manifest.References {
			identity := reference.Identity
			switch reference.Kind {
			case "package":
				candidate, found := packages.resolve(identity)
				if found {
					key := candidate.Manifest.Identity.ExactKey()
					if _, exists := queued[key]; !exists {
						queued[key] = struct{}{}
						queue = append(queue, candidate)
					}
					continue
				}
				if _, installed := installedPackageExact[identity.ExactKey()]; !installed {
					return nil, fmt.Errorf("uup servicing: package %q references unresolved package %q version %q", current.Manifest.Identity.Name, identity.Name, identity.Version)
				}
			case "component":
				candidate, found := components.resolve(identity)
				if found {
					key := candidate.Manifest.Identity.ExactKey()
					if _, exists := selectedComponents[key]; !exists {
						selectedComponents[key] = struct{}{}
						closure.Components = append(closure.Components, candidate)
					}
					continue
				}
				if _, installed := installedComponentExact[identity.ExactKey()]; !installed {
					return nil, fmt.Errorf("uup servicing: package %q references unresolved component %q version %q", current.Manifest.Identity.Name, identity.Name, identity.Version)
				}
			}
		}
	}
	sort.Slice(closure.Packages, func(i, j int) bool {
		return strings.ToLower(closure.Packages[i].Path) < strings.ToLower(closure.Packages[j].Path)
	})
	sort.Slice(closure.Components, func(i, j int) bool {
		return strings.ToLower(closure.Components[i].Path) < strings.ToLower(closure.Components[j].Path)
	})
	return closure, nil
}

func (i AssemblyIdentity) ExactKey() string {
	return i.StableKey() + "\x00" + strings.ToLower(i.Version)
}

func newManifestCatalog(kind string, manifests []NamedAssemblyManifest) (*manifestCatalog, error) {
	result := &manifestCatalog{byExact: make(map[string]NamedAssemblyManifest), byStable: make(map[string][]NamedAssemblyManifest)}
	for index, manifest := range manifests {
		if manifest.Manifest == nil || manifest.Manifest.Identity.Name == "" || manifest.Path == "" {
			return nil, fmt.Errorf("uup servicing: invalid %s manifest %d", kind, index)
		}
		exact := manifest.Manifest.Identity.ExactKey()
		if previous, exists := result.byExact[exact]; exists && !strings.EqualFold(previous.Path, manifest.Path) {
			return nil, fmt.Errorf("uup servicing: %s identity %q version %q has duplicate manifests", kind, manifest.Manifest.Identity.Name, manifest.Manifest.Identity.Version)
		}
		result.byExact[exact] = manifest
		stable := manifest.Manifest.Identity.StableKey()
		result.byStable[stable] = append(result.byStable[stable], manifest)
	}
	for key := range result.byStable {
		sort.Slice(result.byStable[key], func(i, j int) bool {
			return compareVersions(result.byStable[key][i].Manifest.Identity.Version, result.byStable[key][j].Manifest.Identity.Version) > 0
		})
	}
	return result, nil
}

func (c *manifestCatalog) latest(stable string) (NamedAssemblyManifest, bool) {
	values := c.byStable[stable]
	if len(values) == 0 {
		return NamedAssemblyManifest{}, false
	}
	return values[0], true
}

func (c *manifestCatalog) resolve(identity AssemblyIdentity) (NamedAssemblyManifest, bool) {
	if identity.Version != "" {
		value, found := c.byExact[identity.ExactKey()]
		return value, found
	}
	return c.latest(identity.StableKey())
}

func identitySet(identities []AssemblyIdentity, stable bool) map[string]struct{} {
	result := make(map[string]struct{}, len(identities))
	for _, identity := range identities {
		key := identity.ExactKey()
		if stable {
			key = identity.StableKey()
		}
		result[key] = struct{}{}
	}
	return result
}

func compareVersions(left, right string) int {
	leftParts := strings.Split(left, ".")
	rightParts := strings.Split(right, ".")
	count := max(len(leftParts), len(rightParts))
	for index := 0; index < count; index++ {
		leftValue, rightValue := int64(0), int64(0)
		leftOK, rightOK := true, true
		if index < len(leftParts) {
			var err error
			leftValue, err = strconv.ParseInt(leftParts[index], 10, 64)
			leftOK = err == nil
		}
		if index < len(rightParts) {
			var err error
			rightValue, err = strconv.ParseInt(rightParts[index], 10, 64)
			rightOK = err == nil
		}
		if !leftOK || !rightOK {
			return strings.Compare(strings.ToLower(left), strings.ToLower(right))
		}
		if leftValue < rightValue {
			return -1
		}
		if leftValue > rightValue {
			return 1
		}
	}
	return 0
}
