package uup

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// ErrInapplicableComponent means a resident assembly's explicit prerequisite
// is absent. It removes only that optional branch, never a missing install edge.
var ErrInapplicableComponent = errors.New("component prerequisites are not applicable")

// DeploymentOwnership associates one canonical deployment with every exact
// component in its applicable install closure, including resident assemblies.
// It does not apply registry changes or assume a deployment is active merely
// because one of its shared components is active through another source.
type DeploymentOwnership struct {
	Identity   AssemblyIdentity
	Sources    []PlannedDeploymentSource
	Components []PlannedComponent
}

// ResolveDeploymentOwnership resolves resident components only when reached;
// their dependencies must describe the applicable resident closure. Failure to
// resolve an install edge rejects the entire result. ErrInapplicableComponent
// prunes an optional resident branch whose explicit prerequisites are absent. The caller owns content and may
// cache parsed manifests; this boundary performs no host I/O.
func ResolveDeploymentOwnership(plan StageAssemblyPlan, resident func(AssemblyIdentity) (PlannedComponent, error)) ([]DeploymentOwnership, error) {
	components := make(map[string]PlannedComponent, len(plan.Components))
	for _, component := range plan.Components {
		key := component.Identity.ExactKey()
		if _, exists := components[key]; exists {
			return nil, fmt.Errorf("duplicate ownership component %q", component.Identity.Name)
		}
		components[key] = component
	}
	groups := make(map[string]*DeploymentOwnership)
	for _, source := range plan.DeploymentSources {
		key := source.Deployment.ExactKey()
		group := groups[key]
		if group == nil {
			group = &DeploymentOwnership{Identity: source.Deployment}
			groups[key] = group
		}
		group.Sources = append(group.Sources, source)
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]DeploymentOwnership, 0, len(keys))
	for _, key := range keys {
		group := groups[key]
		seen := map[string]bool{}
		queue := []AssemblyIdentity{group.Identity}
		for len(queue) != 0 {
			identity := queue[len(queue)-1]
			queue = queue[:len(queue)-1]
			key := identity.ExactKey()
			if seen[key] {
				continue
			}
			seen[key] = true
			if len(seen) > maximumManifestReferences {
				return nil, fmt.Errorf("deployment ownership closure exceeds bound")
			}
			component, ok := components[key]
			if !ok {
				if resident == nil {
					return nil, fmt.Errorf("deployment %q has unresolved resident %q", group.Identity.Name, identity.Name)
				}
				var err error
				component, err = resident(identity)
				if errors.Is(err, ErrInapplicableComponent) && key != group.Identity.ExactKey() {
					continue
				}
				if err != nil {
					return nil, fmt.Errorf("deployment %q resident %q: %w", group.Identity.Name, identity.Name, err)
				}
				if component.Identity.ExactKey() != key || component.Stem == "" {
					return nil, fmt.Errorf("resident resolver returned foreign or incomplete component %q", identity.Name)
				}
				components[key] = component
			}
			group.Components = append(group.Components, component)
			queue = append(queue, component.InstallDependencies...)
		}
		sort.Slice(group.Components, func(i, j int) bool {
			return strings.ToLower(group.Components[i].Stem) < strings.ToLower(group.Components[j].Stem)
		})
		result = append(result, *group)
	}
	return result, nil
}

func (state *assemblyImageState) resolveInstalledComponent(identity AssemblyIdentity) (manifestPath, error) {
	if !state.exactComponentInventory {
		return manifestPath{Identity: identity}, nil
	}
	if found, ok := state.exactComponents[identity.ExactKey()]; ok {
		return found, nil
	}
	if identity.Language != "*" {
		return manifestPath{}, fmt.Errorf("resident component %s is absent", formatAssemblyIdentity(identity))
	}
	var found *manifestPath
	for _, candidate := range state.exactComponents {
		if !assemblyIdentityMatches(candidate.Identity, identity) {
			continue
		}
		if found != nil {
			return manifestPath{}, fmt.Errorf("resident component selector %q is ambiguous", identity.Name)
		}
		copy := candidate
		found = &copy
	}
	if found == nil {
		return manifestPath{}, fmt.Errorf("resident component selector %q has no match", identity.Name)
	}
	return *found, nil
}

// resolveStageOwnership uses native manifests for unchanged leaves. Reading a
// new version's dependency graph and then grafting the predecessor's c! list
// would retain removed edges and miss newly introduced dependencies.
func (planner *AssemblyPlanner) resolveStageOwnership(stage *CumulativeStage, plan StageAssemblyPlan) ([]DeploymentOwnership, error) {
	cache := make(map[string]PlannedComponent)
	resident := func(identity AssemblyIdentity) (PlannedComponent, error) {
		key := identity.ExactKey()
		if component, ok := cache[key]; ok {
			return component, nil
		}
		if component, ok := planner.ownershipComponents[key]; ok {
			return component, nil
		}
		candidate, err := planner.state.resolveInstalledComponent(identity)
		if err != nil {
			return PlannedComponent{}, err
		}
		name := candidate.Component.Stem + ".manifest"
		file, _, err := openBaseAssemblyContent(planner.content.base, planner.content.imagePath, name)
		if err != nil {
			return PlannedComponent{}, err
		}
		if file.Size() < 4 || file.Size() > maximumAssemblyManifestSize {
			return PlannedComponent{}, fmt.Errorf("invalid resident manifest size")
		}
		var magic [4]byte
		if _, err = file.ReadAt(magic[:], 0); err != nil {
			return PlannedComponent{}, err
		}
		if magic == [4]byte{'D', 'C', 'M', 1} {
			file, err = stage.materializeDeltaCompressedManifest(name, file)
			if err != nil {
				return PlannedComponent{}, err
			}
			defer stage.releaseAssemblyFile(name)
		}
		manifest, err := ParseAssemblyManifest(io.NewSectionReader(file, 0, file.Size()))
		if err != nil {
			return PlannedComponent{}, err
		}
		if manifest.Identity.ExactKey() != key {
			return PlannedComponent{}, fmt.Errorf("resident manifest identity mismatch")
		}
		component := PlannedComponent{Identity: manifest.Identity, Stem: candidate.Component.Stem, Path: name}
		for _, reference := range manifest.References {
			if len(reference.BindingRedirects) != 0 {
				continue
			}
			if reference.Kind != "dependentAssembly" && reference.Kind != "component" {
				continue
			}
			if isWildcardResourceReference(reference) {
				continue
			}
			if reference.Kind == "dependentAssembly" {
				switch strings.ToLower(strings.TrimSpace(reference.DependencyType)) {
				case "prerequisite":
					if !planner.state.hasInstalledComponent(reference.Identity) {
						return PlannedComponent{}, fmt.Errorf("%w: resident prerequisite %q is absent", ErrInapplicableComponent, reference.Identity.Name)
					}
					continue
				case "", "install":
				default:
					return PlannedComponent{}, fmt.Errorf("unsupported resident dependency type %q", reference.DependencyType)
				}
			}
			if reference.Identity.Language == "*" && !planner.state.hasInstalledComponent(reference.Identity) {
				continue
			}
			dependency, err := planner.state.resolveInstalledComponent(reference.Identity)
			if err != nil {
				return PlannedComponent{}, err
			}
			component.InstallDependencies = append(component.InstallDependencies, dependency.Identity)
		}
		cache[key] = component
		return component, nil
	}
	return ResolveDeploymentOwnership(plan, resident)
}
