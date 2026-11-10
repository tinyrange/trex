package uup

import (
	"fmt"
	"path"
	"strings"

	"github.com/tinyrange/trex/archive/wim"
	"github.com/tinyrange/trex/storage"
)

// ComponentMetadataIndex addresses the complete raw/express manifest namespace,
// independently of preliminary payload selection. It neither evaluates install
// prerequisites nor authorizes staging, ownership changes or driver operations.
type ComponentMetadataIndex struct {
	byHash          map[string][]manifestPath
	open            func(string) (storage.Reader, error)
	release         func(string)
	bindPredecessor func(AssemblyIdentity, string)
}

func NewComponentMetadataIndex(stage *CumulativeStage) (*ComponentMetadataIndex, error) {
	if stage == nil {
		return nil, fmt.Errorf("component metadata requires a stage")
	}
	entries, err := stage.assemblyEntries()
	if err != nil {
		return nil, err
	}
	index, err := newComponentMetadataIndex(entries, stage.openAssemblyFile, stage.releaseAssemblyFile)
	if err == nil {
		index.bindPredecessor = stage.bindComponentPredecessor
	}
	return index, err
}

func newComponentMetadataIndex(entries []stageMetadataEntry, open func(string) (storage.Reader, error), release func(string)) (*ComponentMetadataIndex, error) {
	index := &ComponentMetadataIndex{byHash: map[string][]manifestPath{}, open: open, release: release}
	seen := map[string]string{}
	var records []manifestPath
	names := graphStringStore{seen: make(map[string]string)}
	for _, entry := range entries {
		if !strings.EqualFold(path.Ext(entry.Name), ".manifest") {
			continue
		}
		// Own densely stored immutable names, not one directory allocation per
		// name. Parse only after ownership so identity substrings share it.
		entry.Name, entry.Path = names.copy(entry.Name), names.copy(entry.Path)
		component, err := ParseComponentManifestName(entry.Name)
		if err != nil {
			if _, _, contentErr := ParseComponentContentName(entry.Path); contentErr == nil {
				continue
			}
			return nil, err
		}
		if len(seen) >= 1<<20 {
			return nil, fmt.Errorf("component metadata index exceeds bound")
		}
		key := strings.ToLower(component.Stem)
		if previous, exists := seen[key]; exists {
			if previous == entry.Path {
				continue
			}
			return nil, fmt.Errorf("ambiguous component metadata %q", component.Stem)
		}
		seen[key] = entry.Path
		hash := strings.ToLower(component.Suffix)
		if len(index.byHash[hash]) == 0 {
			if len(records) == 0 {
				records = make([]manifestPath, 128)
			}
			index.byHash[hash] = records[:0:1]
			records = records[1:]
		}
		index.byHash[hash] = append(index.byHash[hash], manifestPath{Path: entry.Path, Component: component})
	}
	return index, nil
}

// Open takes a full canonical CSI UTF-8 identity, not a lossy path or selector.
// False means unavailable in this stage. Malformed or conflicting metadata is
// an error, never absence. The returned reader contains the decoded manifest.
func (index *ComponentMetadataIndex) Open(identity []byte) (storage.Reader, bool, error) {
	file, _, found, err := index.resolve(identity)
	return file, found, err
}

// PlanComponents resolves exactly the caller's component set for store staging.
// It performs no applicability, dependency expansion, winner selection or runtime
// activation. The caller must supply the complete authorized composition. Missing
// metadata is fatal; resident components belong to the resident store instead.
func (index *ComponentMetadataIndex) PlanComponents(identities [][]byte) ([]PlannedComponent, error) {
	return index.PlanComponentsWithManifests(identities, nil)
}

// PlanComponentsWithManifests reuses owned snapshots previously resolved by
// this exact index. It does not accept arbitrary equal bytes or another stage's
// readers, and creates no cache extending the caller's snapshot lifetime.
func (index *ComponentMetadataIndex) PlanComponentsWithManifests(identities [][]byte, manifests []*ParsedAssemblyFile) ([]PlannedComponent, error) {
	if manifests != nil && len(manifests) != len(identities) {
		return nil, fmt.Errorf("component manifest snapshot count differs from identities")
	}
	if len(identities) > 1<<20 {
		return nil, fmt.Errorf("component staging request exceeds bound")
	}
	result := make([]PlannedComponent, 0, len(identities))
	seen := make(map[string]bool)
	for i, identity := range identities {
		var component PlannedComponent
		var found bool
		var err error
		if manifests == nil {
			_, component, found, err = index.resolve(identity)
		} else {
			component, err = index.planFromSnapshot(identity, manifests[i])
			found = err == nil
		}
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, fmt.Errorf("missing exact staging component %q", identity)
		}
		key := strings.ToLower(component.Stem)
		if seen[key] {
			return nil, fmt.Errorf("duplicate staging component %q", identity)
		}
		seen[key] = true
		result = append(result, component)
	}
	return result, nil
}

func (index *ComponentMetadataIndex) resolve(identity []byte) (storage.Reader, PlannedComponent, bool, error) {
	if index == nil || index.open == nil {
		return nil, PlannedComponent{}, false, fmt.Errorf("missing component metadata index")
	}
	wanted, err := parseCSIIdentity(identity)
	if err != nil {
		return nil, PlannedComponent{}, false, err
	}
	canonical, err := marshalCSIIdentity(wanted)
	if err != nil {
		return nil, PlannedComponent{}, false, err
	}
	if strings.Contains(string(canonical), "*") {
		return nil, PlannedComponent{}, false, fmt.Errorf("component metadata requires an exact identity")
	}
	hash, err := csiIdentityHash(wanted, false)
	if err != nil {
		return nil, PlannedComponent{}, false, err
	}
	var found storage.Reader
	var component PlannedComponent
	for _, candidate := range index.byHash[fmt.Sprintf("%016x", hash)] {
		if !componentPathMayMatch(candidate.Component, wanted) {
			continue
		}
		file, err := index.read(candidate, canonical)
		if err != nil {
			return nil, PlannedComponent{}, false, err
		}
		if found != nil {
			return nil, PlannedComponent{}, false, fmt.Errorf("ambiguous component metadata for %q", wanted.Name)
		}
		found = file
		component = PlannedComponent{Path: candidate.Path, Stem: candidate.Component.Stem, Identity: wanted, StagedOnly: true, preparedManifest: file, preparedPath: candidate.Path}
	}
	if found != nil {
		if index.bindPredecessor != nil {
			index.bindPredecessor(wanted, component.Stem)
		}
		snapshot := found.(*ParsedAssemblyFile)
		snapshot.componentIndex = index
		snapshot.componentPath = component.Path
		snapshot.componentStem = component.Stem
		snapshot.componentIdentity = strings.ToLower(string(canonical))
	}
	return found, component, found != nil, nil
}

func (index *ComponentMetadataIndex) planFromSnapshot(identity []byte, file *ParsedAssemblyFile) (PlannedComponent, error) {
	if index == nil || file == nil || file.componentIndex != index {
		return PlannedComponent{}, fmt.Errorf("component manifest snapshot belongs to a different metadata index")
	}
	wanted, err := parseCSIIdentity(identity)
	if err != nil {
		return PlannedComponent{}, err
	}
	canonical, err := marshalCSIIdentity(wanted)
	if err != nil {
		return PlannedComponent{}, err
	}
	if strings.Contains(string(canonical), "*") || strings.ToLower(string(canonical)) != file.componentIdentity {
		return PlannedComponent{}, fmt.Errorf("component manifest snapshot identity mismatch")
	}
	return PlannedComponent{Path: file.componentPath, Stem: file.componentStem, Identity: wanted, StagedOnly: true, preparedManifest: file, preparedPath: file.componentPath}, nil
}

func (index *ComponentMetadataIndex) read(candidate manifestPath, wanted []byte) (*ParsedAssemblyFile, error) {
	file, err := index.open(candidate.Path)
	if err != nil {
		return nil, err
	}
	if index.release != nil {
		defer index.release(candidate.Path)
	}
	if file.Size() < 0 || file.Size() > maximumAssemblyManifestSize {
		return nil, fmt.Errorf("component metadata exceeds manifest size bound")
	}
	parsed, err := parseAssemblyFile(file)
	if err != nil {
		return nil, fmt.Errorf("component metadata %q: %w", candidate.Path, err)
	}
	manifest := parsed.Manifest()
	if manifest.Package != nil {
		return nil, fmt.Errorf("component metadata %q contains a package", candidate.Path)
	}
	if err := validateCSIComponentStem(PlannedComponent{Stem: candidate.Component.Stem, Identity: manifest.Identity}); err != nil {
		return nil, err
	}
	actual, err := marshalCSIIdentity(manifest.Identity)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(string(actual), string(wanted)) {
		return nil, fmt.Errorf("component metadata identity mismatch for %q", candidate.Path)
	}
	return parsed, nil
}

// NewResidentComponentMetadataIndex uses the base COMPONENTS identity inventory
// and its native wcp dictionary. It does not use a later update's selected plan,
// substitute a newer component, or infer deployment ownership from availability.
func NewResidentComponentMetadataIndex(base *wim.Archive, imagePath string) (*ComponentMetadataIndex, error) {
	if base == nil {
		return nil, fmt.Errorf("resident component metadata requires a base WIM")
	}
	imagePath = strings.TrimSuffix(imagePath, "/")
	candidates, err := installedComponentIdentities(base, imagePath)
	if err != nil {
		return nil, err
	}
	entries := make([]stageMetadataEntry, 0, len(candidates))
	for _, candidate := range candidates {
		entries = append(entries, stageMetadataEntry{Name: candidate.Component.Stem + ".manifest", Path: candidate.Component.Stem + ".manifest"})
	}
	// Reuse the bounded portable DCM decoder and cache, with only a base-image
	// dictionary resolver. This decoding context has no update payload graph.
	content := &assemblyContentState{base: base, imagePath: imagePath}
	decoder := &CumulativeStage{assemblyDictionary: content.dictionaryResolver()}
	open := func(name string) (storage.Reader, error) {
		file, _, err := openBaseAssemblyContent(base, imagePath, name)
		if err != nil {
			return nil, err
		}
		if file.Size() >= 4 {
			var signature [4]byte
			if _, err := file.ReadAt(signature[:], 0); err != nil {
				return nil, err
			}
			if signature == [4]byte{'D', 'C', 'M', 1} {
				return decoder.materializeDeltaCompressedManifest(name, file)
			}
		}
		return file, nil
	}
	return newComponentMetadataIndex(entries, open, decoder.releaseAssemblyFile)
}
