package uup

import (
	"fmt"
	"strconv"
	"strings"
)

// CBSDeploymentSourceData derives the native source payload for one exact update
// from its containing package MUM. The secondary string is not always empty:
// PopulateUpdateComponents formats the first component analyzer entry's flags
// as decimal, including bit 0 when its updateComponent has multiple targets.
// This does not decide whether the source is present, staged or installed.
func CBSDeploymentSourceData(manifest *AssemblyManifest, updateName string) ([]byte, error) {
	if manifest == nil || manifest.Package == nil {
		return nil, fmt.Errorf("CBS source requires a package manifest")
	}
	var update *AssemblyPackageUpdate
	for i := range manifest.PackageUpdates {
		candidate := &manifest.PackageUpdates[i]
		if strings.EqualFold(candidate.Name, updateName) {
			if update != nil {
				return nil, fmt.Errorf("ambiguous CBS source update %q", updateName)
			}
			update = candidate
		}
	}
	if update == nil {
		return nil, fmt.Errorf("missing CBS source update %q", updateName)
	}
	work := 0
	var first *uint32
	var visit func(ManifestCondition, int) error
	visit = func(node ManifestCondition, depth int) error {
		work++
		if depth > 128 || work > 1<<20 {
			return fmt.Errorf("CBS source condition traversal exceeds bound")
		}
		if node.Namespace != "" && node.Namespace != "urn:schemas-microsoft-com:asm.v3" {
			return fmt.Errorf("unsupported CBS source condition namespace")
		}
		// Native GetUpdateComponentList visits the direct list before nested
		// applicable groups, independently of their interleaving in XML.
		for _, child := range node.Children {
			if child.Name != "updateComponent" {
				continue
			}
			attrs, err := cbsConditionAttributes(child, "elevate")
			if err != nil {
				return err
			}
			elevation, ok := map[string]uint32{"revision": 2, "distribution": 4, "build": 8, "version": 32, "install": 128}[attrs["elevate"]]
			if !ok {
				return fmt.Errorf("unsupported CBS source elevation %q", attrs["elevate"])
			}
			if len(child.Children) == 0 {
				return fmt.Errorf("CBS source updateComponent has no targets")
			}
			for _, target := range child.Children {
				work++
				if work > 1<<20 {
					return fmt.Errorf("CBS source target count exceeds bound")
				}
				if target.Name != "assemblyIdentity" || len(target.Children) != 0 {
					return fmt.Errorf("invalid CBS source updateComponent target")
				}
				attrs, err := cbsConditionAttributes(target, "name", "version", "processorArchitecture", "language", "publicKeyToken", "buildType", "versionScope", "type")
				if err != nil {
					return err
				}
				if attrs["name"] == "" {
					return fmt.Errorf("CBS source target lacks identity name")
				}
			}
			if len(child.Children) > 1 {
				elevation |= 1
			}
			if first == nil {
				first = &elevation
			}
		}
		for _, child := range node.Children {
			if child.Name == "applicable" {
				if err := visit(child, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, condition := range update.Conditions {
		if condition.Name == "applicable" {
			if err := visit(condition, 0); err != nil {
				return nil, err
			}
		}
	}
	var secondary []byte
	if first != nil {
		secondary = []byte(strconv.FormatUint(uint64(*first), 10))
	}
	return marshalCBSDeploymentSource(cbsDeploymentSource{Package: manifest.Identity, Update: update.Name}, secondary)
}
