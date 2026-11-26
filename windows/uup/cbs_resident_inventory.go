package uup

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/tinyrange/trex/storage"
	"github.com/tinyrange/trex/windows/registry"
)

// CBSResidentInventory contains parsed declarations from an unchanged
// COMPONENTS hive. Population and update applicability use it as input.
type CBSResidentInventory struct {
	Components  []CBSComponentInventoryEntry
	deployments []residentCBSDeployment
}

type residentCBSDeployment struct {
	Identity AssemblyIdentity
	Sources  []residentCBSSource
}

type residentCBSSource struct {
	Primary string
	State   uint32
}

func (i *CBSResidentInventory) Deployments() []CBSInitialDeployment {
	result := make([]CBSInitialDeployment, len(i.deployments))
	for n, deployment := range i.deployments {
		sources := make(map[string]uint32, len(deployment.Sources))
		for _, source := range deployment.Sources {
			sources[source.Primary] = source.State
		}
		result[n] = CBSInitialDeployment{Identity: deployment.Identity, Sources: sources}
	}
	return result
}

func ReadCBSResidentInventory(ctx context.Context, hive *registry.Hive, records storage.DerivedCache) (*CBSResidentInventory, error) {
	if records == nil {
		return readCBSResidentInventory(hive)
	}
	digest, verified := hive.VerifiedSHA256()
	if !verified {
		return nil, fmt.Errorf("CBS resident inventory requires an immutable COMPONENTS hive")
	}
	key := storage.DerivedKey("windows.cbs.resident-inventory/v1", digest)
	var inventory *CBSResidentInventory
	var sourceError error
	record, err := records.GetOrBuild(ctx, key, maximumAssemblyRecord, func() ([]byte, error) {
		inventory, sourceError = readCBSResidentInventory(hive)
		if sourceError != nil {
			return nil, sourceError
		}
		wire := residentInventoryWire{inventory.Components, inventory.deployments}
		return packCBSRecord(reflect.ValueOf(wire))
	})
	if inventory != nil || sourceError != nil {
		return inventory, sourceError
	}
	if err == nil {
		var wire residentInventoryWire
		if err := unpackCBSRecord(record, reflect.ValueOf(&wire).Elem()); err == nil {
			return &CBSResidentInventory{Components: wire.Components, deployments: wire.Deployments}, nil
		}
	}
	return readCBSResidentInventory(hive)
}

type residentInventoryWire struct {
	Components  []CBSComponentInventoryEntry
	Deployments []residentCBSDeployment
}

func readCBSResidentInventory(hive *registry.Hive) (*CBSResidentInventory, error) {
	root, err := hive.LookupParts([]string{"CanonicalData", "Deployments"})
	if err != nil {
		return nil, err
	}
	deployments, err := hive.ReadSubkeys(root)
	if err != nil {
		return nil, err
	}
	derived, err := hive.LookupParts([]string{"DerivedData", "Components"})
	if err != nil {
		return nil, err
	}
	components, err := hive.ReadSubkeys(derived)
	if err != nil {
		return nil, err
	}
	if len(deployments) > 1<<20 || len(components) > 1<<20 {
		return nil, fmt.Errorf("CBS resident inventory exceeds key bound")
	}
	result := &CBSResidentInventory{
		Components:  make([]CBSComponentInventoryEntry, 0, len(components)),
		deployments: make([]residentCBSDeployment, 0, len(deployments)),
	}
	installed := make(map[string][]string, len(deployments))
	total, sourceCount := 0, 0
	for _, key := range deployments {
		cells, err := hive.ValueCells(key)
		if err != nil {
			return nil, err
		}
		var identity AssemblyIdentity
		sources := make(map[string]uint32)
		for _, cell := range cells {
			value, err := hive.ReadValue(cell)
			if err != nil {
				return nil, err
			}
			if value.Name == "appid" {
				if !residentRegistryBytes(value.Type) || len(value.Data) > 64<<10 {
					return nil, fmt.Errorf("invalid CBS resident deployment identity")
				}
				identity, err = ParseCSIIdentity(value.Data)
				if err != nil {
					return nil, err
				}
				total += len(value.Data)
				if total > 256<<20 {
					return nil, fmt.Errorf("CBS resident inventory exceeds source byte bound")
				}
				continue
			}
			var state uint32
			switch {
			case strings.HasPrefix(value.Name, "p!"):
				state = 0x20
			case strings.HasPrefix(value.Name, "s!"):
				state = 0x40
			case strings.HasPrefix(value.Name, "i!"):
				state = 0x70
			default:
				continue
			}
			total += len(value.Data)
			sourceCount++
			if !residentRegistryBytes(value.Type) || len(value.Data) > 64<<10 || total > 256<<20 || sourceCount > 1<<20 {
				return nil, fmt.Errorf("invalid or excessive CBS resident deployment source")
			}
			source, err := ParseCBSDeploymentSource(value.Data)
			if err != nil {
				return nil, err
			}
			sources[source.Primary] = max(sources[source.Primary], state)
			if state == 0x70 {
				installed[key.Name] = append(installed[key.Name], string(source.Secondary))
			}
		}
		if identity.Name == "" {
			return nil, fmt.Errorf("CBS resident deployment %q lacks appid", key.Name)
		}
		if _, found := installed[key.Name]; !found {
			installed[key.Name] = nil
		}
		names := make([]string, 0, len(sources))
		for name := range sources {
			names = append(names, name)
		}
		sort.Strings(names)
		record := residentCBSDeployment{Identity: identity, Sources: make([]residentCBSSource, 0, len(names))}
		for _, name := range names {
			record.Sources = append(record.Sources, residentCBSSource{Primary: name, State: sources[name]})
		}
		result.deployments = append(result.deployments, record)
	}
	for _, key := range components {
		cells, err := hive.ValueCells(key)
		if err != nil {
			return nil, err
		}
		var entry CBSComponentInventoryEntry
		for _, cell := range cells {
			value, err := hive.ReadValue(cell)
			if err != nil {
				return nil, err
			}
			if value.Name == "identity" {
				if !residentRegistryBytes(value.Type) || len(value.Data) > 64<<10 {
					return nil, fmt.Errorf("invalid CBS resident component identity")
				}
				entry.Identity = value.Data
			} else if strings.HasPrefix(value.Name, "c!") {
				owners, found := installed[value.Name[2:]]
				if !found {
					return nil, fmt.Errorf("missing CBS resident component owner %q", value.Name[2:])
				}
				for _, secondary := range owners {
					elevation := uint64(128)
					if secondary != "" {
						elevation, err = strconv.ParseUint(secondary, 10, 31)
						if err != nil {
							return nil, fmt.Errorf("invalid CBS resident owner elevation: %w", err)
						}
					}
					entry.Owners = append(entry.Owners, uint32(elevation))
				}
			}
		}
		if len(entry.Identity) == 0 {
			return nil, fmt.Errorf("CBS resident component %q lacks identity", key.Name)
		}
		result.Components = append(result.Components, entry)
	}
	return result, nil
}

// The existing hive adapter exposes unconverted value types as byte strings.
func residentRegistryBytes(kind uint32) bool {
	switch kind {
	case 1, 2, 4, 7, 11:
		return false
	default:
		return true
	}
}
