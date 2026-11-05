package uup

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/tinyrange/trex/archive/wim"
	"github.com/tinyrange/trex/windows/catalog"
)

// CSIDeploymentRecord describes one exact canonical deployment. CatalogThumbprint
// is the SHA-256 of an actual package catalog containing the decoded root
// manifest hash. Sources name the p!/s! values and, only when Installed, i!.
// Applying these records alone is not a complete CBS servicing transaction.
type CSIDeploymentRecord struct {
	Name              string
	AppID             []byte
	CatalogThumbprint string
	Sources           []CSIDeploymentSourceRecord
}

type CSIDeploymentSourceRecord struct {
	Name      string
	Data      []byte
	Installed bool
}

// CSIDeploymentPlanner retains native source framing and manifest hashes across
// stages. A failed stage does not publish any new predecessor state.
type CSIDeploymentPlanner struct {
	hashes  map[string][sha256.Size]byte
	sources map[string][]byte
}

func NewCSIDeploymentPlanner(base *wim.Archive, imagePath string) (*CSIDeploymentPlanner, error) {
	hive, err := openOfflineHive(base, strings.TrimSuffix(imagePath, "/")+"/Windows/System32/config/COMPONENTS", "COMPONENTS")
	if err != nil {
		return nil, err
	}
	p := &CSIDeploymentPlanner{hashes: make(map[string][sha256.Size]byte), sources: make(map[string][]byte)}
	values, err := hive.SubkeyValues(cbsComponentsKey, "S256H")
	if err != nil {
		return nil, err
	}
	for _, v := range values {
		if !v.Found {
			continue
		}
		if v.Value.Type != 3 || len(v.Value.Data) != sha256.Size {
			return nil, fmt.Errorf("component %q has invalid S256H", v.Key)
		}
		var hash [sha256.Size]byte
		copy(hash[:], v.Value.Data)
		p.hashes[strings.ToLower(v.Key)] = hash
	}
	root, err := hive.LookupParts([]string{"CanonicalData", "Deployments"})
	if err != nil {
		return nil, err
	}
	keys, err := hive.ReadSubkeys(root)
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		cells, err := hive.ValueCells(key)
		if err != nil {
			return nil, err
		}
		for _, cell := range cells {
			v, err := hive.ReadValue(cell)
			if err != nil {
				return nil, err
			}
			if !strings.HasPrefix(v.Name, "p!CBS_") {
				continue
			}
			if v.Type != 3 {
				return nil, fmt.Errorf("nonbinary CBS source %q", v.Name)
			}
			if _, err := parseCBSDeploymentSource(v.Data); err != nil {
				return nil, err
			}
			p.sources[strings.ToLower(key.Name)+"\x00"+strings.ToLower(v.Name[2:])] = append([]byte(nil), v.Data...)
		}
	}
	return p, nil
}

type csiCatalog struct {
	thumbprint string
	members    map[[sha256.Size]byte]bool
}

func (p *CSIDeploymentPlanner) PlanStage(stage *CumulativeStage, plan StageAssemblyPlan, effects StageEffectPlan, components CSIComponentStatePlan) ([]CSIDeploymentRecord, error) {
	if p == nil || stage == nil {
		return nil, fmt.Errorf("CSI deployment planner and stage are required")
	}
	needed := make(map[string]bool)
	for _, deployment := range plan.Deployments {
		for _, source := range deployment.Sources {
			needed[source.Package.ExactKey()] = true
		}
	}
	catalogs := make(map[string]csiCatalog)
	packagesByCatalog := make(map[string]AssemblyIdentity)
	for _, pack := range plan.Packages {
		name, err := cbsPackageName(pack.Manifest.Identity)
		if err != nil {
			return nil, err
		}
		name = strings.ToLower(name) + ".cat"
		if _, exists := packagesByCatalog[name]; exists {
			return nil, fmt.Errorf("ambiguous package catalog %q", name)
		}
		packagesByCatalog[name] = pack.Manifest.Identity
	}
	for _, effect := range effects.Files {
		if effect.Kind != "package-catalog" {
			continue
		}
		id, found := packagesByCatalog[strings.ToLower(path.Base(effect.StorePath))]
		if !found {
			return nil, fmt.Errorf("catalog %q has no exact selected package", effect.StorePath)
		}
		key := id.ExactKey()
		if !needed[key] {
			continue
		}
		if _, exists := catalogs[key]; exists {
			return nil, fmt.Errorf("duplicate catalog for %q", id.Name)
		}
		file, err := stage.OpenPlannedFile(effect)
		if err != nil {
			return nil, err
		}
		if file.Size() < 0 || file.Size() > 64<<20 {
			return nil, fmt.Errorf("catalog size exceeds bound")
		}
		data, err := io.ReadAll(io.NewSectionReader(file, 0, file.Size()))
		if err != nil {
			return nil, err
		}
		parsed, err := catalog.ParseIndex(data)
		if err != nil {
			return nil, fmt.Errorf("catalog %q: %w", effect.StorePath, err)
		}
		digest := sha256.Sum256(data)
		cat := csiCatalog{thumbprint: hex.EncodeToString(digest[:]), members: make(map[[sha256.Size]byte]bool)}
		for _, member := range parsed {
			if len(member) != sha256.Size {
				continue
			}
			var hash [sha256.Size]byte
			copy(hash[:], member)
			cat.members[hash] = true
		}
		catalogs[key] = cat
	}
	return p.plan(plan, components, catalogs)
}

func (p *CSIDeploymentPlanner) plan(plan StageAssemblyPlan, components CSIComponentStatePlan, catalogs map[string]csiCatalog) ([]CSIDeploymentRecord, error) {
	manifests := make(map[string]*AssemblyManifest)
	for _, pack := range plan.Packages {
		if pack.Manifest == nil {
			return nil, fmt.Errorf("CSI source package has no manifest")
		}
		key := pack.Manifest.Identity.ExactKey()
		if _, found := manifests[key]; found {
			return nil, fmt.Errorf("duplicate CSI source package metadata")
		}
		manifests[key] = pack.Manifest
	}
	newHashes := make(map[string][sha256.Size]byte)
	for _, component := range components.Components {
		newHashes[strings.ToLower(component.Stem)] = component.ManifestSHA256
	}
	newSources := make(map[string][]byte)
	result := make([]CSIDeploymentRecord, 0, len(plan.Deployments))
	seen := make(map[string]bool)
	for _, deployment := range plan.Deployments {
		name, err := csiDeploymentKey(deployment.Identity)
		if err != nil {
			return nil, err
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate canonical deployment %q", name)
		}
		seen[name] = true
		appid, err := marshalCSIIdentity(deployment.Identity)
		if err != nil {
			return nil, err
		}
		rootStem := ""
		for _, component := range deployment.Components {
			if component.Identity.ExactKey() == deployment.Identity.ExactKey() {
				if err := validateCSIComponentStem(component); err != nil {
					return nil, err
				}
				check := component
				check.Identity = deployment.Identity
				if err := validateCSIComponentStem(check); err != nil {
					return nil, err
				}
				rootStem = strings.ToLower(component.Stem)
			}
		}
		hash, found := newHashes[rootStem]
		if !found {
			hash, found = p.hashes[rootStem]
		}
		if rootStem == "" || !found {
			return nil, fmt.Errorf("deployment %q has no exact root manifest hash", name)
		}
		record := CSIDeploymentRecord{Name: name, AppID: appid}
		sourceNames := make(map[string]int)
		for _, source := range deployment.Sources {
			if source.Deployment.ExactKey() != deployment.Identity.ExactKey() {
				return nil, fmt.Errorf("foreign deployment source in %q", name)
			}
			cat, found := catalogs[source.Package.ExactKey()]
			if !found || !cat.members[hash] {
				return nil, fmt.Errorf("deployment %q root manifest is not a SHA-256 member of source package %q catalog", name, source.Package.Name)
			}
			// Every candidate is a real catalog owning the exact manifest. Deterministic
			// selection avoids associating a deployment with an unrelated package or a
			// catalog selected solely by approximate component names.
			if record.CatalogThumbprint == "" || cat.thumbprint < record.CatalogThumbprint {
				record.CatalogThumbprint = cat.thumbprint
			}
			data, err := CBSDeploymentSourceData(manifests[source.Package.ExactKey()], source.UpdateName)
			if err != nil {
				return nil, err
			}
			length := binary.LittleEndian.Uint32(data[:4])
			sourceName, err := cbsSourceKey(string(data[8 : 8+length]))
			if err != nil {
				return nil, err
			}
			key := strings.ToLower(name) + "\x00" + strings.ToLower(sourceName)
			if old, exists := p.sources[key]; exists {
				oldSource, err := parseCBSDeploymentSource(old)
				if err != nil || oldSource.Package.ExactKey() != source.Package.ExactKey() || oldSource.Update != source.UpdateName {
					return nil, fmt.Errorf("canonical source collision for %q", sourceName)
				}
				data = append([]byte(nil), old...)
			}
			newSources[key] = data
			if at, exists := sourceNames[sourceName]; exists {
				if record.Sources[at].Installed != !source.StagedOnly {
					return nil, fmt.Errorf("conflicting source activation for %q", sourceName)
				}
				continue
			}
			sourceNames[sourceName] = len(record.Sources)
			record.Sources = append(record.Sources, CSIDeploymentSourceRecord{Name: sourceName, Data: data, Installed: !source.StagedOnly})
		}
		if len(record.Sources) == 0 {
			return nil, fmt.Errorf("canonical deployment %q has no sources", name)
		}
		sort.Slice(record.Sources, func(i, j int) bool { return record.Sources[i].Name < record.Sources[j].Name })
		result = append(result, record)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	for k, v := range newHashes {
		p.hashes[k] = v
	}
	for k, v := range newSources {
		p.sources[k] = append([]byte(nil), v...)
	}
	return result, nil
}
