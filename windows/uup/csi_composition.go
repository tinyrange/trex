package uup

import (
	"fmt"
	"strings"
)

// CSICompositionMember is one exact member of a deployment's composition.
// Disposition is 1 (patch) or 2 (install), independently of whether any source
// installs the deployment. It is not an installed-mark count or a winner.
type CSICompositionMember struct {
	Identity    AssemblyIdentity
	Disposition uint32
}

// CalculateCSIComposition follows WCP's compositional install edges, not CBS
// package applicability or runtime binding dependencies. Only explicit
// dependencyType="install" edges introduce members. Prerequisites, omitted
// dependency types and supportedComponent declarations do not introduce owners.
// resolve must return the exact decoded component manifest, including resident
// components; a missing install edge fails the whole calculation. No inventory
// fallback, newer-version substitution, staging or registry writes occur here.
//
// Native draining is breadth-first in manifest order. Repeated paths overwrite
// the member's disposition in that order; they must not be collapsed before
// propagation. The top-level component starts with install disposition, even
// when its own deployment declaration says patch. Descendants inherit their
// incoming disposition unless their own explicit impact overrides it.
//
// Depth is bounded at the native 128 edges. workLimit additionally bounds total
// queued entries (including repeats); zero uses 1<<20, maximum is 1<<22.
func CalculateCSIComposition(root AssemblyIdentity, resolve func(AssemblyIdentity) (*AssemblyManifest, error), workLimit int) ([]CSICompositionMember, error) {
	if resolve == nil {
		return nil, fmt.Errorf("CSI composition requires a manifest resolver")
	}
	if workLimit == 0 {
		workLimit = 1 << 20
	}
	if workLimit < 1 || workLimit > 1<<22 {
		return nil, fmt.Errorf("invalid CSI composition work limit")
	}
	type pending struct {
		identity    AssemblyIdentity
		disposition uint32
		depth       int
	}
	queue := []pending{{identity: root}}
	cache := make(map[string]*AssemblyManifest)
	positions := make(map[string]int)
	var result []CSICompositionMember
	for cursor := 0; cursor < len(queue); cursor++ {
		current := queue[cursor]
		if current.depth > 128 {
			return nil, fmt.Errorf("CSI composition depth exceeds 128 at %q", current.identity.Name)
		}
		key, err := compositionIdentityKey(current.identity)
		if err != nil {
			return nil, err
		}
		manifest, ok := cache[key]
		if !ok {
			manifest, err = resolve(current.identity)
			if err != nil {
				return nil, fmt.Errorf("CSI composition %q: %w", current.identity.Name, err)
			}
			if manifest == nil || manifest.Package != nil {
				return nil, fmt.Errorf("CSI composition requires a component manifest for %q", current.identity.Name)
			}
			actual, err := compositionIdentityKey(manifest.Identity)
			if err != nil {
				return nil, err
			}
			if actual != key {
				return nil, fmt.Errorf("CSI composition resolver returned a different identity for %q", current.identity.Name)
			}
			cache[key] = manifest
		}
		disposition := current.disposition
		if manifest.Deployment != nil {
			seen := false
			for _, attribute := range manifest.Deployment.Attributes {
				if attribute.Namespace != "" || attribute.Name != "impact" {
					continue
				}
				if seen {
					return nil, fmt.Errorf("duplicate CSI deployment impact")
				}
				seen = true
				switch strings.ToLower(attribute.Value) {
				case "install":
					disposition = 2
				case "patch":
					disposition = 1
				default:
					return nil, fmt.Errorf("unsupported CSI deployment impact %q", attribute.Value)
				}
			}
		}
		if current.disposition == 0 {
			disposition = 2
		}
		member := CSICompositionMember{Identity: manifest.Identity, Disposition: disposition}
		// Do not expose the resolver's mutable attribute slice through the result.
		member.Identity.Attributes = append([]ManifestAttribute(nil), member.Identity.Attributes...)
		if position, exists := positions[key]; exists {
			result[position] = member
		} else {
			positions[key] = len(result)
			result = append(result, member)
		}
		for _, reference := range manifest.References {
			if reference.Kind != "dependentAssembly" {
				continue
			}
			switch strings.ToLower(reference.DependencyType) {
			case "", "prerequisite":
				continue
			case "install":
			default:
				return nil, fmt.Errorf("unsupported CSI dependency type %q", reference.DependencyType)
			}
			if len(reference.BindingRedirects) != 0 {
				return nil, fmt.Errorf("CSI install dependency contains binding redirects")
			}
			if _, err := compositionIdentityKey(reference.Identity); err != nil {
				return nil, err
			}
			if len(queue) >= workLimit {
				return nil, fmt.Errorf("CSI composition work limit %d exceeded", workLimit)
			}
			queue = append(queue, pending{identity: reference.Identity, disposition: disposition, depth: current.depth + 1})
		}
	}
	return result, nil
}

func compositionIdentityKey(identity AssemblyIdentity) (string, error) {
	data, err := marshalCSIIdentity(identity)
	if err != nil {
		return "", err
	}
	if strings.ContainsAny(string(data), "*?") {
		return "", fmt.Errorf("CSI composition requires an exact identity")
	}
	return strings.ToLower(string(data)), nil
}
