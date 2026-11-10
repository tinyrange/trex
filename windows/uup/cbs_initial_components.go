package uup

import (
	"fmt"
	"strings"
)

// CBSInitialDeployment is an explicit baseline, not a transaction result.
// Sources maps exact CBS primary names to resolved/staged/installed state.
type CBSInitialDeployment struct {
	Identity AssemblyIdentity
	Sources  map[string]uint32
}

// initialComponentKey intentionally includes version scope and type but not
// buildType, matching the ordinary CBS deployment-source identity join.
func initialComponentKey(id AssemblyIdentity) [7]string {
	language := strings.ToLower(id.Language)
	if language == "" || language == "none" {
		language = "neutral"
	}
	kind := ""
	for _, a := range id.Attributes {
		if a.Namespace == "" && a.Name == "type" {
			kind = a.Value
		}
	}
	return [7]string{strings.ToLower(id.Name), strings.ToLower(id.Version), strings.ToLower(id.PublicKeyToken), strings.ToLower(id.ProcessorArchitecture), language, strings.ToLower(id.VersionScope), strings.ToLower(kind)}
}

// InitialComponentStates joins immutable component/driver references to one
// explicit baseline. It preserves reference order and duplicates, including
// absent references (zero); it does not apply containing-package caps or share
// mutable execution state between stage and install.
func (index *CBSUpdateStateIndex) InitialComponentStates(packages []string, deployments []CBSInitialDeployment) (map[string]map[string][]uint32, error) {
	if len(packages) > MaxCBSPackageContexts || len(deployments) > 1<<20 {
		return nil, fmt.Errorf("CBS initial component input bound exceeded")
	}
	baseline := make(map[[7]string]map[string]uint32, len(deployments))
	sourceCount := 0
	for _, d := range deployments {
		key := initialComponentKey(d.Identity)
		if _, found := baseline[key]; found {
			return nil, fmt.Errorf("duplicate CBS initial deployment identity")
		}
		for _, state := range d.Sources {
			if state != 0x20 && state != CBSStateStaged && state != CBSStateInstalled {
				return nil, fmt.Errorf("invalid CBS initial source state %#x", state)
			}
			sourceCount++
			if sourceCount > 1<<20 {
				return nil, fmt.Errorf("CBS initial source bound exceeded")
			}
		}
		baseline[key] = d.Sources
	}
	out := make(map[string]map[string][]uint32, len(packages))
	seen := make(map[string]bool, len(packages))
	count := 0
	for _, name := range packages {
		id, err := index.PackageIdentity(name)
		if err != nil {
			return nil, err
		}
		key := id.ExactKey()
		if seen[key] {
			return nil, fmt.Errorf("duplicate CBS initial package")
		}
		seen[key] = true
		ctx := index.graph.packages.get(key)
		updates := make(map[string][]uint32, len(ctx.updates))
		for un := range ctx.updates {
			updates[un] = []uint32{}
		}
		for _, ref := range ctx.input.Manifest.References {
			if ref.Kind != "component" && ref.Kind != "driver" {
				continue
			}
			un := strings.ToLower(ref.UpdateName)
			update, known := ctx.updates[un]
			if !known {
				return nil, fmt.Errorf("CBS initial deployment lacks containing update")
			}
			state := baseline[initialComponentKey(ref.Identity)][name+"."+update.Name]
			updates[un] = append(updates[un], state)
			count++
			if count > 1<<20 {
				return nil, fmt.Errorf("CBS initial component result bound exceeded")
			}
		}
		out[name] = updates
	}
	return out, nil
}
