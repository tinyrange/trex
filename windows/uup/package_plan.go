package uup

import (
	"encoding/binary"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/tinyrange/trex/archive/wim"
	portablepe "github.com/tinyrange/trex/binary/pe"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	registryhive "github.com/tinyrange/trex/windows/registry"
)

const maximumAssemblyManifestSize = int64(64 << 20)

type PlannedComponent struct {
	Path         string
	Identity     AssemblyIdentity
	Stem         string
	PreviousStem string
	// SelectedBy identifies the first exact package or component install edge
	// that made this component part of the stage closure. It is diagnostic
	// provenance, not an additional applicability rule.
	SelectedBy string
}

type StageAssemblyPlan struct {
	Packages   []NamedAssemblyManifest
	Components []PlannedComponent
}

type manifestPath struct {
	Path      string
	Identity  AssemblyIdentity
	Component ComponentPathIdentity
}

type stageManifestCatalog struct {
	stage               *CumulativeStage
	aggregateRoot       *NamedAssemblyManifest
	packagesByExact     map[string]manifestPath
	packagesByStable    map[string][]manifestPath
	componentCandidates []manifestPath
	componentsByName    map[string][]manifestPath
	abbreviatedByShape  map[string][]manifestPath
	abbreviatedByLocale map[string][]manifestPath
	componentsByCore    map[string][]manifestPath
	parsedPackages      map[string]*AssemblyManifest
	parsedComponents    map[string]*AssemblyManifest
}

type assemblyImageState struct {
	packagesByExact         map[string]AssemblyIdentity
	latestPackageByStable   map[string]AssemblyIdentity
	componentCandidates     []manifestPath
	componentsByName        map[string][]manifestPath
	abbreviatedByShape      map[string][]manifestPath
	abbreviatedByLocale     map[string][]manifestPath
	componentsByCore        map[string][]manifestPath
	installedComponentExact map[string]struct{}
	componentFamilies       map[string]struct{}
	latestComponentByFamily map[string]manifestPath
	absentComponentFamilies map[string]struct{}
	familyAbbreviated       map[string][]manifestPath
	familyAbbreviatedLocale map[string][]manifestPath
}

// PlanAssemblyStages evaluates update package applicability against the
// installed package/component identities and follows every package reference
// in stage order. Later stages see the identities installed by earlier ones.
func PlanAssemblyStages(base *wim.Archive, imagePath string, stages []*CumulativeStage) ([]StageAssemblyPlan, error) {
	return PlanAssemblyStagesObserved(base, imagePath, stages, nil)
}

// PlanAssemblyStagesObserved is the REPL inspection variant. observe is called
// once after each exact stage closure; it must not mutate the returned plan.
func PlanAssemblyStagesObserved(base *wim.Archive, imagePath string, stages []*CumulativeStage, observe func(int, StageAssemblyPlan)) ([]StageAssemblyPlan, error) {
	planner, err := NewAssemblyPlanner(base, imagePath)
	if err != nil {
		return nil, err
	}
	result := make([]StageAssemblyPlan, len(stages))
	for index, stage := range stages {
		plan, err := planner.PlanStage(stage)
		if err != nil {
			return nil, fmt.Errorf("uup servicing: stage %d package closure: %w", index+1, err)
		}
		result[index] = plan
		if observe != nil {
			observe(index, plan)
		}
	}
	return result, nil
}

// AssemblyPlanner incrementally evaluates stages in dependency order. A stage
// can resolve content only from the base image and stages already passed to
// PlanStage; unopened future stages are neither visible nor retained.
type AssemblyPlanner struct {
	state   *assemblyImageState
	content *assemblyContentState
}

func NewAssemblyPlanner(base *wim.Archive, imagePath string) (*AssemblyPlanner, error) {
	if base == nil {
		return nil, fmt.Errorf("uup servicing: base WIM is required")
	}
	imagePath = strings.TrimSuffix(imagePath, "/")
	packageNames, err := installedPackageManifestNames(base, imagePath)
	if err != nil {
		return nil, err
	}
	componentNames, err := installedComponentManifestNames(base, imagePath)
	if err != nil {
		return nil, err
	}
	state, err := newAssemblyImageState(packageNames, componentNames)
	if err != nil {
		return nil, err
	}
	return &AssemblyPlanner{state: state, content: &assemblyContentState{base: base, imagePath: imagePath}}, nil
}

const cbsPackagesKey = `/Microsoft/Windows/CurrentVersion/Component Based Servicing/Packages`
const cbsComponentsKey = `/DerivedData/Components`
const maximumOfflineCBSHive = int64(1 << 30)

func openOfflineHive(base *wim.Archive, name, label string) (*registryhive.Hive, error) {
	file, err := base.OpenFile(name)
	if err != nil {
		return nil, fmt.Errorf("uup servicing: open offline %s hive: %w", label, err)
	}
	if file.Size() < 0 || file.Size() > maximumOfflineCBSHive {
		return nil, fmt.Errorf("uup servicing: offline %s hive size %d exceeds %d-byte bound", label, file.Size(), maximumOfflineCBSHive)
	}
	data, err := starfile.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("uup servicing: read offline %s hive: %w", label, err)
	}
	hive, err := registryhive.Open(&starfile.Bytes{Name: "offline-" + label, Data: data})
	if err != nil {
		return nil, fmt.Errorf("uup servicing: parse offline %s hive: %w", label, err)
	}
	return hive, nil
}

func installedPackageManifestNames(base *wim.Archive, imagePath string) ([]string, error) {
	hive, err := openOfflineHive(base, strings.TrimSuffix(imagePath, "/")+"/Windows/System32/config/SOFTWARE", "SOFTWARE")
	if err != nil {
		return nil, err
	}
	states, err := hive.SubkeyValues(cbsPackagesKey, "CurrentState")
	if err != nil {
		return nil, fmt.Errorf("uup servicing: enumerate CBS package state: %w", err)
	}
	result := make([]string, 0, len(states))
	for _, state := range states {
		if !state.Found || state.Value.Type != 4 || len(state.Value.Data) != 4 {
			return nil, fmt.Errorf("uup servicing: CBS package %q has no DWORD CurrentState", state.Key)
		}
		if !cbsPackageStateInstalled(binary.LittleEndian.Uint32(state.Value.Data)) {
			continue
		}
		manifestName := state.Key + ".mum"
		if _, err := ParsePackageManifestName(manifestName); err != nil {
			return nil, fmt.Errorf("uup servicing: installed CBS package key %q is not an assembly identity: %w", state.Key, err)
		}
		result = append(result, manifestName)
	}
	return result, nil
}

func installedComponentManifestNames(base *wim.Archive, imagePath string) ([]string, error) {
	hive, err := openOfflineHive(base, strings.TrimSuffix(imagePath, "/")+"/Windows/System32/config/COMPONENTS", "COMPONENTS")
	if err != nil {
		return nil, err
	}
	names, err := hive.Subkeys(cbsComponentsKey)
	if err != nil {
		return nil, fmt.Errorf("uup servicing: enumerate CBS component state: %w", err)
	}
	result := make([]string, 0, len(names))
	for _, name := range names {
		manifestName := name + ".manifest"
		if _, err := ParseComponentManifestName(manifestName); err != nil {
			continue
		}
		result = append(result, manifestName)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("uup servicing: COMPONENTS hive contains no parseable installed component identities")
	}
	return result, nil
}

func cbsPackageStateInstalled(state uint32) bool {
	// CBS persists the DISM install-state enum in the high nibble. Staged (4)
	// is not installed; superseded (5), install-pending (6), installed (7),
	// and permanent (8) all belong to the installed package lineage.
	return state >= 0x50 && state <= 0x80 && state&0x0f == 0
}

func (planner *AssemblyPlanner) PlanStage(stage *CumulativeStage) (StageAssemblyPlan, error) {
	if planner == nil || planner.state == nil || planner.content == nil {
		return StageAssemblyPlan{}, fmt.Errorf("uup servicing: assembly planner is required")
	}
	stage.assemblyResolver = planner.content.snapshotResolver()
	stage.assemblyNameResolver = planner.content.snapshotNameResolver()
	stage.assemblyReadOrder = planner.content.snapshotReadOrder()
	stage.assemblyNameReadOrder = planner.content.snapshotNameReadOrder()
	stage.assemblyDictionary = planner.content.dictionaryResolver()
	catalog, err := newStageManifestCatalog(stage)
	if err != nil {
		return StageAssemblyPlan{}, fmt.Errorf("manifest catalog: %w", err)
	}
	plan, err := catalog.plan(planner.state)
	if err != nil {
		return StageAssemblyPlan{}, err
	}
	completed := newCompletedAssemblyStage(stage, plan)
	stage.predecessorByStem = completed.predecessorByStem
	planner.content.prior = append(planner.content.prior, completed)
	return plan, nil
}

// PlanAssemblyStagesFromInventory is the portable inventory boundary used by
// filesystem-backed images. Names are CBS package and WinSxS manifest paths;
// their host or container origin is irrelevant.
func PlanAssemblyStagesFromInventory(packageNames, componentNames []string, stages []*CumulativeStage) ([]StageAssemblyPlan, error) {
	return planAssemblyStagesFromInventory(packageNames, componentNames, stages, nil, nil)
}

func planAssemblyStagesFromInventory(packageNames, componentNames []string, stages []*CumulativeStage, observe func(int, StageAssemblyPlan), content *assemblyContentState) ([]StageAssemblyPlan, error) {
	state, err := newAssemblyImageState(packageNames, componentNames)
	if err != nil {
		return nil, err
	}
	result := make([]StageAssemblyPlan, len(stages))
	for index, stage := range stages {
		if content != nil {
			stage.assemblyResolver = content.snapshotResolver()
			stage.assemblyNameResolver = content.snapshotNameResolver()
			stage.assemblyReadOrder = content.snapshotReadOrder()
			stage.assemblyNameReadOrder = content.snapshotNameReadOrder()
			stage.assemblyDictionary = content.dictionaryResolver()
		}
		catalog, err := newStageManifestCatalog(stage)
		if err != nil {
			return nil, fmt.Errorf("uup servicing: stage %d manifest catalog: %w", index+1, err)
		}
		plan, err := catalog.plan(state)
		if err != nil {
			return nil, fmt.Errorf("uup servicing: stage %d package closure: %w", index+1, err)
		}
		result[index] = plan
		if content != nil {
			completed := newCompletedAssemblyStage(stage, plan)
			stage.predecessorByStem = completed.predecessorByStem
			content.prior = append(content.prior, completed)
		}
		if observe != nil {
			observe(index, plan)
		}
	}
	return result, nil
}

// assemblyContentState is the exact predecessor-content boundary for express
// reconstruction. A stage receives a snapshot containing the base image and
// only stages whose CBS closure has already completed.
type assemblyContentState struct {
	base      *wim.Archive
	imagePath string
	prior     []completedAssemblyStage
	dictOnce  sync.Once
	dict      storage.Reader
	dictErr   error
}

type completedAssemblyStage struct {
	stage             *CumulativeStage
	plan              StageAssemblyPlan
	predecessorByStem map[string]string
}

func newCompletedAssemblyStage(stage *CumulativeStage, plan StageAssemblyPlan) completedAssemblyStage {
	predecessors := make(map[string]string)
	for _, component := range plan.Components {
		if component.PreviousStem != "" {
			predecessors[normalizeCIXName(component.Stem)] = component.PreviousStem
		}
	}
	return completedAssemblyStage{stage: stage, plan: plan, predecessorByStem: predecessors}
}

func (state *assemblyContentState) snapshotResolver() func(ContentDescriptor) (storage.Reader, error) {
	base, imagePath := state.base, state.imagePath
	prior := append([]completedAssemblyStage(nil), state.prior...)
	return func(descriptor ContentDescriptor) (storage.Reader, error) {
		for index := len(prior) - 1; index >= 0; index-- {
			file, ok, err := prior[index].stage.openTargetDescriptor(descriptor)
			if err != nil {
				return nil, fmt.Errorf("predecessor stage %d: %w", index+1, err)
			}
			if !ok {
				continue
			}
			// Content length and SHA-256 are authoritative. The latest stage is
			// the correct logical owner even when multiple cumulative updates
			// carry the same bytes under successive WinSxS target names.
			return file, nil
		}
		if descriptor.Name == "" {
			return nil, fmt.Errorf("basis SHA-256 %x is absent from completed stages and has no base-image name", descriptor.SHA256)
		}
		if base == nil {
			return nil, fmt.Errorf("base WIM is unavailable")
		}
		return resolveBaseAssemblyDescriptor(base, imagePath, descriptor)
	}
}

func (state *assemblyContentState) snapshotNameResolver() func(string) (storage.Reader, error) {
	base, imagePath := state.base, state.imagePath
	prior := append([]completedAssemblyStage(nil), state.prior...)
	return func(name string) (storage.Reader, error) {
		current := strings.TrimPrefix(strings.ReplaceAll(name, "/", `\`), `\`)
		for index := len(prior) - 1; index >= 0; index-- {
			completed := prior[index]
			if completed.stage.hasContentTarget(current) {
				file, err := completed.stage.OpenContentTarget(current)
				if err != nil {
					return nil, fmt.Errorf("installed content stage %d target %q: %w", index+1, current, err)
				}
				return file, nil
			}
			identity, relative, err := ParseComponentContentName(current)
			if err != nil {
				continue
			}
			previous, found := completed.predecessorByStem[normalizeCIXName(identity.Stem)]
			if found {
				current = strings.TrimSuffix(previous, `\`) + `\` + relative
			}
		}
		file, resolvedPath, err := openBaseAssemblyContent(base, imagePath, current)
		if err != nil {
			return nil, fmt.Errorf("installed content %q is absent from completed stages and base image: %w", current, err)
		}
		_ = resolvedPath
		return file, nil
	}
}

func (state *assemblyContentState) dictionaryResolver() func() (storage.Reader, error) {
	return func() (storage.Reader, error) {
		state.dictOnce.Do(func() {
			state.dict, state.dictErr = openDCMDictionary(state.base, state.imagePath)
		})
		return state.dict, state.dictErr
	}
}

func openDCMDictionary(base *wim.Archive, imagePath string) (storage.Reader, error) {
	type candidate struct {
		path    string
		version string
	}
	var candidates []candidate
	if _, err := base.OpenFile(imagePath + "/Windows/System32/wcp.dll"); err == nil {
		wcp, err := base.OpenFile(imagePath + "/Windows/System32/wcp.dll")
		if err != nil {
			return nil, err
		}
		return portablepe.OpenNumericResource(wcp, 0x266, 1, maximumAssemblyManifestSize)
	} else if err := base.Walk(imagePath+"/Windows/WinSxS", func(entry wim.EntryInfo) error {
		if !entry.Directory && strings.EqualFold(entry.Name, "wcp.dll") {
			prefix := strings.TrimSuffix(imagePath, "/") + "/Windows/WinSxS/"
			relative := strings.TrimPrefix(entry.Path, prefix)
			identity, fileName, parseErr := ParseComponentContentName(relative)
			if parseErr != nil || !strings.EqualFold(fileName, "wcp.dll") ||
				!strings.EqualFold(identity.Identity.ProcessorArchitecture, "amd64") ||
				!strings.EqualFold(identity.Identity.Name, "microsoft-windows-servicingstack") {
				return nil
			}
			candidates = append(candidates, candidate{path: entry.Path, version: identity.Identity.Version})
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("enumerate component-store wcp.dll: %w", err)
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("wcp.dll is absent from the base image")
	}
	sort.Slice(candidates, func(i, j int) bool {
		order := compareVersions(candidates[i].version, candidates[j].version)
		if order != 0 {
			return order > 0
		}
		return strings.ToLower(candidates[i].path) < strings.ToLower(candidates[j].path)
	})
	if len(candidates) > 1 && compareVersions(candidates[0].version, candidates[1].version) == 0 && !strings.EqualFold(candidates[0].path, candidates[1].path) {
		return nil, fmt.Errorf("latest amd64 servicing-stack wcp.dll version %q is ambiguous between %q and %q", candidates[0].version, candidates[0].path, candidates[1].path)
	}
	wcp, err := base.OpenFile(candidates[0].path)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", candidates[0].path, err)
	}
	dictionary, err := portablepe.OpenNumericResource(wcp, 0x266, 1, maximumAssemblyManifestSize)
	if err != nil {
		return nil, fmt.Errorf("open DCM dictionary in %q: %w", candidates[0].path, err)
	}
	return dictionary, nil
}

func openBaseAssemblyContent(base *wim.Archive, imagePath, name string) (storage.Reader, string, error) {
	if base == nil {
		return nil, "", fmt.Errorf("base WIM is unavailable")
	}
	candidate, err := baseAssemblyContentPath(imagePath, name)
	if err != nil {
		return nil, "", err
	}
	file, err := base.OpenFile(candidate)
	return file, candidate, err
}

func baseAssemblyContentPath(imagePath, name string) (string, error) {
	clean := strings.TrimPrefix(strings.ReplaceAll(name, "\\", "/"), "/")
	if clean == "" || clean == "." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("invalid assembly content name %q", name)
	}
	// A catalog/manifest below a component directory is payload, not CBS
	// package metadata. Preserve its full component-relative path.
	if strings.Contains(clean, "/") {
		return imagePath + "/Windows/WinSxS/" + clean, nil
	}
	switch strings.ToLower(path.Ext(clean)) {
	case ".mum", ".cat":
		return imagePath + "/Windows/servicing/Packages/" + clean, nil
	case ".manifest":
		return imagePath + "/Windows/WinSxS/Manifests/" + clean, nil
	default:
		return imagePath + "/Windows/WinSxS/" + clean, nil
	}
}

func newAssemblyImageState(packageNames, componentNames []string) (*assemblyImageState, error) {
	state := &assemblyImageState{
		packagesByExact: make(map[string]AssemblyIdentity), latestPackageByStable: make(map[string]AssemblyIdentity),
		componentsByName: make(map[string][]manifestPath), abbreviatedByShape: make(map[string][]manifestPath),
		abbreviatedByLocale: make(map[string][]manifestPath), componentsByCore: make(map[string][]manifestPath),
		installedComponentExact: make(map[string]struct{}), componentFamilies: make(map[string]struct{}),
		latestComponentByFamily: make(map[string]manifestPath),
		absentComponentFamilies: make(map[string]struct{}),
		familyAbbreviated:       make(map[string][]manifestPath), familyAbbreviatedLocale: make(map[string][]manifestPath),
	}
	for _, name := range packageNames {
		identity, err := ParsePackageManifestName(name)
		if err != nil {
			return nil, err
		}
		state.packagesByExact[identity.ExactKey()] = identity
		stable := identity.StableKey()
		if current, found := state.latestPackageByStable[stable]; !found || compareVersions(identity.Version, current.Version) > 0 {
			state.latestPackageByStable[stable] = identity
		}
	}
	for _, name := range componentNames {
		component, err := ParseComponentManifestName(name)
		if err != nil {
			return nil, err
		}
		state.componentCandidates = append(state.componentCandidates, manifestPath{Path: name, Identity: component.Identity, Component: component})
		candidate := state.componentCandidates[len(state.componentCandidates)-1]
		coreKey := componentCoreShapeKey(component.Identity)
		state.componentsByCore[coreKey] = append(state.componentsByCore[coreKey], candidate)
		if strings.Contains(component.Identity.Language, "..") {
			state.abbreviatedByLocale[coreKey] = append(state.abbreviatedByLocale[coreKey], candidate)
		}
		if strings.Contains(component.Identity.Name, "..") {
			key := componentShapeKey(component.Identity)
			state.abbreviatedByShape[key] = append(state.abbreviatedByShape[key], candidate)
		} else {
			key := componentCanonicalKey(component.Identity)
			state.componentsByName[key] = append(state.componentsByName[key], candidate)
		}
		state.componentFamilies[componentFamilyKey(component.Identity)] = struct{}{}
		family := componentFamilyKey(component.Identity)
		if current, found := state.latestComponentByFamily[family]; !found || compareVersions(component.Identity.Version, current.Identity.Version) > 0 {
			state.latestComponentByFamily[family] = candidate
		}
		if strings.Contains(component.Identity.Name, "..") {
			key := componentFamilyShapeKey(component.Identity)
			state.familyAbbreviated[key] = append(state.familyAbbreviated[key], candidate)
		}
		if strings.Contains(component.Identity.Language, "..") {
			key := componentFamilyCoreKey(component.Identity)
			state.familyAbbreviatedLocale[key] = append(state.familyAbbreviatedLocale[key], candidate)
		}
	}
	return state, nil
}

func newStageManifestCatalog(stage *CumulativeStage) (*stageManifestCatalog, error) {
	if stage == nil {
		return nil, fmt.Errorf("stage metadata is required")
	}
	catalog := &stageManifestCatalog{
		stage: stage, packagesByExact: make(map[string]manifestPath), packagesByStable: make(map[string][]manifestPath),
		componentsByName: make(map[string][]manifestPath), abbreviatedByShape: make(map[string][]manifestPath),
		abbreviatedByLocale: make(map[string][]manifestPath),
		componentsByCore:    make(map[string][]manifestPath),
		parsedPackages:      make(map[string]*AssemblyManifest), parsedComponents: make(map[string]*AssemblyManifest),
	}
	entries, err := stage.assemblyEntries()
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		switch strings.ToLower(path.Ext(entry.Name)) {
		case ".mum":
			identity, err := ParsePackageManifestName(entry.Name)
			if err != nil {
				if !strings.EqualFold(entry.Name, "update.mum") || catalog.aggregateRoot != nil {
					return nil, err
				}
				file, openErr := stage.openAssemblyFile(entry.Path)
				if openErr != nil {
					return nil, openErr
				}
				if file.Size() < 0 || file.Size() > maximumAssemblyManifestSize {
					return nil, fmt.Errorf("aggregate package manifest %q exceeds %d-byte bound", entry.Path, maximumAssemblyManifestSize)
				}
				manifest, parseErr := ParseAssemblyManifest(io.NewSectionReader(file, 0, file.Size()))
				stage.releaseAssemblyFile(entry.Path)
				if parseErr != nil {
					return nil, fmt.Errorf("parse aggregate package manifest %q: %w", entry.Path, parseErr)
				}
				catalog.aggregateRoot = &NamedAssemblyManifest{Path: entry.Path, Manifest: manifest}
				catalog.parsedPackages[strings.ToLower(entry.Path)] = manifest
				continue
			}
			candidate := manifestPath{Path: entry.Path, Identity: identity}
			exact := identity.ExactKey()
			if previous, exists := catalog.packagesByExact[exact]; exists && !strings.EqualFold(previous.Path, entry.Path) {
				return nil, fmt.Errorf("duplicate package identity %q version %q", identity.Name, identity.Version)
			}
			catalog.packagesByExact[exact] = candidate
			catalog.packagesByStable[identity.StableKey()] = append(catalog.packagesByStable[identity.StableKey()], candidate)
		case ".manifest":
			component, err := ParseComponentManifestName(entry.Name)
			if err != nil {
				if _, _, contentErr := ParseComponentContentName(entry.Path); contentErr == nil {
					// A .manifest below a canonical component directory is
					// component payload, not the component's CBS identity file.
					continue
				}
				return nil, err
			}
			candidate := manifestPath{Path: entry.Path, Identity: component.Identity, Component: component}
			catalog.componentCandidates = append(catalog.componentCandidates, candidate)
			coreKey := componentCoreShapeKey(component.Identity)
			catalog.componentsByCore[coreKey] = append(catalog.componentsByCore[coreKey], candidate)
			if strings.Contains(component.Identity.Language, "..") {
				key := componentCoreShapeKey(component.Identity)
				catalog.abbreviatedByLocale[key] = append(catalog.abbreviatedByLocale[key], candidate)
			}
			if strings.Contains(component.Identity.Name, "..") {
				key := componentShapeKey(component.Identity)
				catalog.abbreviatedByShape[key] = append(catalog.abbreviatedByShape[key], candidate)
			} else {
				key := componentCanonicalKey(component.Identity)
				catalog.componentsByName[key] = append(catalog.componentsByName[key], candidate)
			}
		}
	}
	for key := range catalog.packagesByStable {
		sort.Slice(catalog.packagesByStable[key], func(i, j int) bool {
			return compareVersions(catalog.packagesByStable[key][i].Identity.Version, catalog.packagesByStable[key][j].Identity.Version) > 0
		})
	}
	return catalog, nil
}

func (catalog *stageManifestCatalog) plan(state *assemblyImageState) (StageAssemblyPlan, error) {
	var plan StageAssemblyPlan
	var queue []manifestPath
	queued := make(map[string]struct{})
	for stable, installed := range state.latestPackageByStable {
		candidates := catalog.packagesByStable[stable]
		if len(candidates) == 0 || compareVersions(candidates[0].Identity.Version, installed.Version) <= 0 {
			continue
		}
		queue = append(queue, candidates[0])
		queued[candidates[0].Identity.ExactKey()] = struct{}{}
	}
	if catalog.aggregateRoot != nil {
		applicable := false
		for _, reference := range catalog.aggregateRoot.Manifest.References {
			if reference.Kind == "parent" && state.hasInstalledIdentity(reference.Identity) {
				applicable = true
				break
			}
		}
		if applicable {
			plan.Packages = append(plan.Packages, NamedAssemblyManifest{Path: catalog.aggregateRoot.Path, Manifest: &AssemblyManifest{Identity: catalog.aggregateRoot.Manifest.Identity}})
			var pendingApplicability []manifestPath
			for _, reference := range catalog.aggregateRoot.Manifest.References {
				if reference.Kind != "package" {
					continue
				}
				candidate, found := catalog.packagesByExact[reference.Identity.ExactKey()]
				if !found {
					return StageAssemblyPlan{}, fmt.Errorf("aggregate package references missing package %q version %q", reference.Identity.Name, reference.Identity.Version)
				}
				_, alreadyInstalled := state.latestPackageByStable[reference.Identity.StableKey()]
				if !alreadyInstalled {
					pendingApplicability = append(pendingApplicability, candidate)
					continue
				}
				exact := candidate.Identity.ExactKey()
				if _, exists := queued[exact]; !exists {
					queued[exact] = struct{}{}
					queue = append(queue, candidate)
				}
			}
			catalog.sortForRead(pendingApplicability)
			for _, candidate := range pendingApplicability {
				manifest, err := catalog.parsePackage(candidate)
				if err != nil {
					return StageAssemblyPlan{}, err
				}
				applicable := false
				for _, childReference := range manifest.References {
					if childReference.Kind == "parent" && state.hasInstalledIdentity(childReference.Identity) {
						applicable = true
						break
					}
				}
				if !applicable {
					delete(catalog.parsedPackages, strings.ToLower(candidate.Path))
					continue
				}
				exact := candidate.Identity.ExactKey()
				if _, exists := queued[exact]; !exists {
					queued[exact] = struct{}{}
					queue = append(queue, candidate)
				}
			}
		}
	}
	catalog.sortForRead(queue)
	type componentWork struct {
		candidate manifestPath
		identity  AssemblyIdentity
	}
	var componentQueue []componentWork
	selectedComponents := make(map[string]AssemblyIdentity)
	componentOrigins := make(map[string]string)
	componentPredecessors := make(map[string]string)
	componentRoots := make(map[string]struct{})
	componentDependencies := make(map[string][]string)
	componentPrerequisites := make(map[string][]AssemblyIdentity)
	queueComponent := func(candidate manifestPath, identity AssemblyIdentity, selectedBy string) {
		exact := identity.ExactKey()
		if _, exists := selectedComponents[exact]; exists {
			return
		}
		selectedComponents[exact] = identity
		if previous, found := state.latestInstalledComponent(identity); found {
			componentPredecessors[exact] = previous.Component.Stem
		}
		componentOrigins[exact] = selectedBy
		componentQueue = append(componentQueue, componentWork{candidate: candidate, identity: identity})
	}
	queueComponentRoot := func(candidate manifestPath, identity AssemblyIdentity, selectedBy string) {
		queueComponent(candidate, identity, selectedBy)
		componentRoots[identity.ExactKey()] = struct{}{}
	}
	for len(queue) != 0 {
		candidate := queue[0]
		queue = queue[1:]
		manifest, err := catalog.parsePackage(candidate)
		if err != nil {
			return StageAssemblyPlan{}, err
		}
		plan.Packages = append(plan.Packages, NamedAssemblyManifest{Path: candidate.Path, Manifest: &AssemblyManifest{Identity: manifest.Identity}})
		for _, reference := range manifest.References {
			switch reference.Kind {
			case "package":
				exact := reference.Identity.ExactKey()
				if next, found := catalog.packagesByExact[exact]; found {
					if _, exists := queued[exact]; !exists {
						child, err := catalog.parsePackage(next)
						if err != nil {
							return StageAssemblyPlan{}, err
						}
						if !packageManifestApplicable(child, state, queued) {
							delete(catalog.parsedPackages, strings.ToLower(next.Path))
							continue
						}
						queued[exact] = struct{}{}
						queue = append(queue, next)
					}
					continue
				}
				if _, installed := state.packagesByExact[exact]; installed {
					continue
				}
				if state.hasInstalledPackageFamily(reference.Identity) {
					return StageAssemblyPlan{}, fmt.Errorf("package %q references unresolved update for installed package %q version %q", manifest.Identity.Name, reference.Identity.Name, reference.Identity.Version)
				}
				// An unavailable entry for a package family absent from the
				// image is one of the parent's inapplicable SKU/feature children.
			case "component", "driver":
				// Dual-mode driver assemblies are package roots just like
				// components. Their manifests declare runtime driver files,
				// DriverStore destinations, registry effects and dependencies.
				component, found, err := catalog.findComponent(reference.Identity)
				if err != nil {
					return StageAssemblyPlan{}, err
				}
				if found {
					queueComponentRoot(component, component.Identity, formatComponentSelection("package", manifest.Identity, reference))
					continue
				}
				if !state.hasInstalledComponent(reference.Identity) {
					if strings.TrimSpace(reference.Identity.Language) == "*" {
						continue
					}
					return StageAssemblyPlan{}, fmt.Errorf("package %q references unresolved component %q version %q", manifest.Identity.Name, reference.Identity.Name, reference.Identity.Version)
				}
			}
		}
		delete(catalog.parsedPackages, strings.ToLower(candidate.Path))
	}
	sort.Slice(componentQueue, func(i, j int) bool {
		return lessStageReadOrder(catalog.stage.metadataReadOrder(componentQueue[i].candidate.Path), catalog.stage.metadataReadOrder(componentQueue[j].candidate.Path))
	})
	for len(componentQueue) != 0 {
		current := componentQueue[0]
		componentQueue = componentQueue[1:]
		manifest, err := catalog.parseComponent(current.candidate, current.identity)
		if err != nil {
			return StageAssemblyPlan{}, err
		}
		plan.Components = append(plan.Components, PlannedComponent{
			Path: current.candidate.Path, Identity: current.identity, Stem: current.candidate.Component.Stem,
			PreviousStem: componentPredecessors[current.identity.ExactKey()], SelectedBy: componentOrigins[current.identity.ExactKey()],
		})
		currentKey := current.identity.ExactKey()
		for _, reference := range manifest.References {
			if reference.Kind != "dependentAssembly" && reference.Kind != "component" {
				continue
			}
			if isWildcardResourceReference(reference) {
				// A wildcard resource identity selects already applicable
				// language satellites; it is not itself an installable exact
				// component identity. CBS uses both component and
				// dependentAssembly wrappers for this selector.
				continue
			}
			if reference.Kind == "dependentAssembly" {
				switch strings.ToLower(strings.TrimSpace(reference.DependencyType)) {
				case "", "install":
					// A selected assembly's install edge can introduce a new
					// component family (for example a new boot-critical CI
					// policy). Prior installation is not an applicability
					// requirement. Prerequisites are evaluated over the full
					// dependency closure below, including optional branches.
				case "prerequisite":
					componentPrerequisites[currentKey] = append(componentPrerequisites[currentKey], reference.Identity)
					continue
				default:
					return StageAssemblyPlan{}, fmt.Errorf("component %q uses unsupported dependency type %q for %q", manifest.Identity.Name, reference.DependencyType, reference.Identity.Name)
				}
			}
			component, found, err := catalog.findComponent(reference.Identity)
			if err != nil {
				return StageAssemblyPlan{}, err
			}
			if found {
				queueComponent(component, component.Identity, formatComponentSelection("component", manifest.Identity, reference))
				componentDependencies[currentKey] = append(componentDependencies[currentKey], component.Identity.ExactKey())
				continue
			}
			if !state.hasInstalledComponent(reference.Identity) {
				if strings.TrimSpace(reference.Identity.Language) == "*" {
					// A non-resource wildcard is a selector over available
					// component instances. No matches is a valid empty selection;
					// one match is handled above and multiple matches are rejected
					// by findComponent as ambiguous.
					continue
				}
				return StageAssemblyPlan{}, fmt.Errorf("component %q references unresolved component %s; stage candidates: %s; base candidates: %s",
					manifest.Identity.Name, formatAssemblyIdentity(reference.Identity), summarizeComponentCandidates(catalog.componentCandidates, reference.Identity), summarizeComponentCandidates(state.componentCandidates, reference.Identity))
			}
		}
		delete(catalog.parsedComponents, strings.ToLower(current.candidate.Path))
	}
	applicableComponents := resolveApplicableComponents(componentRoots, componentDependencies, componentPrerequisites, selectedComponents, state)
	filteredComponents := plan.Components[:0]
	for _, component := range plan.Components {
		if _, applicable := applicableComponents[component.Identity.ExactKey()]; applicable {
			filteredComponents = append(filteredComponents, component)
		}
	}
	plan.Components = filteredComponents
	for _, pack := range plan.Packages {
		identity := pack.Manifest.Identity
		state.packagesByExact[identity.ExactKey()] = identity
		state.latestPackageByStable[identity.StableKey()] = identity
	}
	for _, component := range plan.Components {
		state.installedComponentExact[component.Identity.ExactKey()] = struct{}{}
		family := componentFamilyKey(component.Identity)
		state.componentFamilies[family] = struct{}{}
		state.latestComponentByFamily[family] = manifestPath{
			Path: component.Path, Identity: component.Identity,
			Component: ComponentPathIdentity{Identity: component.Identity, Stem: component.Stem},
		}
		delete(state.absentComponentFamilies, family)
	}
	sort.Slice(plan.Packages, func(i, j int) bool {
		return strings.ToLower(plan.Packages[i].Path) < strings.ToLower(plan.Packages[j].Path)
	})
	sort.Slice(plan.Components, func(i, j int) bool {
		return strings.ToLower(plan.Components[i].Path) < strings.ToLower(plan.Components[j].Path)
	})
	return plan, nil
}

func resolveApplicableComponents(roots map[string]struct{}, dependencies map[string][]string, prerequisites map[string][]AssemblyIdentity, selected map[string]AssemblyIdentity, state *assemblyImageState) map[string]struct{} {
	applicable := make(map[string]struct{}, len(selected))
	for key := range selected {
		applicable[key] = struct{}{}
	}
	type prerequisiteWatch struct {
		owner     string
		remaining int
	}
	var watches []prerequisiteWatch
	reverse := make(map[string][]int)
	invalid := make([]string, 0)
	invalidQueued := make(map[string]struct{})
	queueInvalid := func(owner string) {
		if _, queued := invalidQueued[owner]; queued {
			return
		}
		invalidQueued[owner] = struct{}{}
		invalid = append(invalid, owner)
	}
	for owner, requirements := range prerequisites {
		for _, requirement := range requirements {
			if state.hasInstalledComponent(requirement) {
				continue
			}
			providers := selectedComponentProviders(selected, requirement)
			if len(providers) == 0 {
				queueInvalid(owner)
				continue
			}
			watchIndex := len(watches)
			watches = append(watches, prerequisiteWatch{owner: owner, remaining: len(providers)})
			for _, provider := range providers {
				reverse[provider] = append(reverse[provider], watchIndex)
			}
		}
	}
	for len(invalid) != 0 {
		current := invalid[len(invalid)-1]
		invalid = invalid[:len(invalid)-1]
		if _, present := applicable[current]; !present {
			continue
		}
		delete(applicable, current)
		for _, watchIndex := range reverse[current] {
			watch := &watches[watchIndex]
			watch.remaining--
			if watch.remaining == 0 {
				queueInvalid(watch.owner)
			}
		}
	}
	reachable := make(map[string]struct{}, len(applicable))
	queue := make([]string, 0, len(roots))
	for root := range roots {
		if _, present := applicable[root]; present {
			queue = append(queue, root)
		}
	}
	for len(queue) != 0 {
		current := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		if _, seen := reachable[current]; seen {
			continue
		}
		reachable[current] = struct{}{}
		for _, dependency := range dependencies[current] {
			if _, present := applicable[dependency]; present {
				queue = append(queue, dependency)
			}
		}
	}
	return reachable
}

func selectedComponentProviders(selected map[string]AssemblyIdentity, requirement AssemblyIdentity) []string {
	if identity, found := selected[requirement.ExactKey()]; found && assemblyIdentityMatches(identity, requirement) {
		return []string{requirement.ExactKey()}
	}
	if strings.TrimSpace(requirement.Language) != "*" {
		return nil
	}
	providers := make([]string, 0, 1)
	for key, identity := range selected {
		if assemblyIdentityMatches(identity, requirement) {
			providers = append(providers, key)
		}
	}
	return providers
}

func (catalog *stageManifestCatalog) sortForRead(paths []manifestPath) {
	orders := make(map[string]stageReadOrder, len(paths))
	for _, candidate := range paths {
		orders[candidate.Path] = catalog.stage.metadataReadOrder(candidate.Path)
	}
	sort.Slice(paths, func(i, j int) bool { return lessStageReadOrder(orders[paths[i].Path], orders[paths[j].Path]) })
}

func lessStageReadOrder(left, right stageReadOrder) bool {
	if left.archive != right.archive {
		return left.archive < right.archive
	}
	if left.wim.Source != right.wim.Source {
		return left.wim.Source < right.wim.Source
	}
	if left.wim.ResourceOffset != right.wim.ResourceOffset {
		return left.wim.ResourceOffset < right.wim.ResourceOffset
	}
	if left.wim.BlobOffset != right.wim.BlobOffset {
		return left.wim.BlobOffset < right.wim.BlobOffset
	}
	return left.name < right.name
}

func (catalog *stageManifestCatalog) parsePackage(candidate manifestPath) (*AssemblyManifest, error) {
	key := strings.ToLower(candidate.Path)
	if manifest := catalog.parsedPackages[key]; manifest != nil {
		return manifest, nil
	}
	file, err := catalog.stage.openAssemblyFile(candidate.Path)
	if err != nil {
		return nil, err
	}
	if file.Size() < 0 || file.Size() > maximumAssemblyManifestSize {
		return nil, fmt.Errorf("package manifest %q exceeds %d-byte bound", candidate.Path, maximumAssemblyManifestSize)
	}
	manifest, err := ParseAssemblyManifest(io.NewSectionReader(file, 0, file.Size()))
	catalog.stage.releaseAssemblyFile(candidate.Path)
	if err != nil {
		return nil, fmt.Errorf("parse package manifest %q: %w", candidate.Path, err)
	}
	if manifest.Identity.ExactKey() != candidate.Identity.ExactKey() {
		return nil, fmt.Errorf("package manifest %q identity does not match its filename", candidate.Path)
	}
	catalog.parsedPackages[key] = manifest
	return manifest, nil
}

func (catalog *stageManifestCatalog) parseComponent(candidate manifestPath, wanted AssemblyIdentity) (*AssemblyManifest, error) {
	manifest, err := catalog.loadComponent(candidate)
	if err != nil {
		return nil, err
	}
	if manifest.Identity.ExactKey() != wanted.ExactKey() {
		return nil, fmt.Errorf("component manifest %q identity does not match dependency %q version %q", candidate.Path, wanted.Name, wanted.Version)
	}
	return manifest, nil
}

func (catalog *stageManifestCatalog) loadComponent(candidate manifestPath) (*AssemblyManifest, error) {
	key := strings.ToLower(candidate.Path)
	if manifest := catalog.parsedComponents[key]; manifest != nil {
		return manifest, nil
	}
	file, err := catalog.stage.openAssemblyFile(candidate.Path)
	if err != nil {
		return nil, err
	}
	if file.Size() < 0 || file.Size() > maximumAssemblyManifestSize {
		return nil, fmt.Errorf("component manifest %q exceeds %d-byte bound", candidate.Path, maximumAssemblyManifestSize)
	}
	manifest, err := ParseAssemblyManifest(io.NewSectionReader(file, 0, file.Size()))
	catalog.stage.releaseAssemblyFile(candidate.Path)
	if err != nil {
		return nil, fmt.Errorf("parse component manifest %q: %w", candidate.Path, err)
	}
	catalog.parsedComponents[key] = manifest
	return manifest, nil
}

func (catalog *stageManifestCatalog) findComponent(identity AssemblyIdentity) (manifestPath, bool, error) {
	var found *manifestPath
	var identityMismatches []string
	visit := func(candidates []manifestPath) error {
		for index := range candidates {
			candidate := &candidates[index]
			if !componentPathMayMatch(candidate.Component, identity) {
				continue
			}
			manifest, err := catalog.loadComponent(*candidate)
			if err != nil {
				return err
			}
			if !assemblyIdentityMatches(manifest.Identity, identity) {
				if len(identityMismatches) < 3 {
					identityMismatches = append(identityMismatches, fmt.Sprintf("%q -> %s", candidate.Path, formatAssemblyIdentity(manifest.Identity)))
				}
				delete(catalog.parsedComponents, strings.ToLower(candidate.Path))
				continue
			}
			if found != nil && !strings.EqualFold(found.Path, candidate.Path) {
				return fmt.Errorf("component %q version %q has ambiguous target manifests %q and %q", identity.Name, identity.Version, found.Path, candidate.Path)
			}
			resolved := *candidate
			resolved.Identity = manifest.Identity
			found = &resolved
		}
		return nil
	}
	coreKey := componentCoreShapeKey(identity)
	if strings.TrimSpace(identity.Language) == "*" {
		if err := visit(catalog.componentsByCore[coreKey]); err != nil {
			return manifestPath{}, false, err
		}
	} else {
		for _, candidates := range [][]manifestPath{
			catalog.componentsByName[componentCanonicalKey(identity)],
			catalog.abbreviatedByShape[componentShapeKey(identity)],
			catalog.abbreviatedByLocale[coreKey],
		} {
			if err := visit(candidates); err != nil {
				return manifestPath{}, false, err
			}
		}
	}
	if found == nil {
		if len(identityMismatches) != 0 {
			return manifestPath{}, false, fmt.Errorf("component %s candidate manifest identities do not match: %s", formatAssemblyIdentity(identity), strings.Join(identityMismatches, "; "))
		}
		return manifestPath{}, false, nil
	}
	return *found, true, nil
}

func componentShapeKey(identity AssemblyIdentity) string {
	return strings.ToLower(strings.Join([]string{
		identity.ProcessorArchitecture, identity.PublicKeyToken, identity.Version, normalizedLanguage(identity.Language),
	}, "\x00"))
}

func componentFamilyKey(identity AssemblyIdentity) string {
	return strings.ToLower(strings.Join([]string{
		identity.ProcessorArchitecture, componentPathName(identity.Name), identity.PublicKeyToken, normalizedLanguage(identity.Language),
	}, "\x00"))
}

func componentFamilyShapeKey(identity AssemblyIdentity) string {
	return strings.ToLower(strings.Join([]string{
		identity.ProcessorArchitecture, identity.PublicKeyToken, normalizedLanguage(identity.Language),
	}, "\x00"))
}

func componentFamilyCoreKey(identity AssemblyIdentity) string {
	return strings.ToLower(strings.Join([]string{identity.ProcessorArchitecture, identity.PublicKeyToken}, "\x00"))
}

func componentPathFamilyMayMatch(candidate ComponentPathIdentity, wanted AssemblyIdentity) bool {
	if !strings.EqualFold(candidate.Identity.ProcessorArchitecture, wanted.ProcessorArchitecture) ||
		!strings.EqualFold(candidate.Identity.PublicKeyToken, wanted.PublicKeyToken) ||
		!sameManifestLanguage(candidate.Identity.Language, wanted.Language) {
		return false
	}
	candidateName := componentPathName(candidate.Identity.Name)
	wantedName := componentPathName(wanted.Name)
	if split := strings.Index(candidateName, ".."); split >= 0 {
		suffix := split + 2
		for suffix < len(candidateName) && candidateName[suffix] == '.' {
			suffix++
		}
		return strings.HasPrefix(wantedName, candidateName[:split]) && strings.HasSuffix(wantedName, candidateName[suffix:])
	}
	return candidateName == wantedName
}

func componentCoreShapeKey(identity AssemblyIdentity) string {
	return strings.ToLower(strings.Join([]string{
		identity.ProcessorArchitecture, identity.PublicKeyToken, identity.Version,
	}, "\x00"))
}

func assemblyIdentityMatches(actual, wanted AssemblyIdentity) bool {
	return strings.EqualFold(actual.Name, wanted.Name) &&
		strings.EqualFold(actual.Version, wanted.Version) &&
		strings.EqualFold(actual.ProcessorArchitecture, wanted.ProcessorArchitecture) &&
		strings.EqualFold(actual.PublicKeyToken, wanted.PublicKeyToken) &&
		sameManifestLanguage(actual.Language, wanted.Language)
}

func componentCanonicalKey(identity AssemblyIdentity) string {
	return componentShapeKey(identity) + "\x00" + componentPathName(identity.Name)
}

func (state *assemblyImageState) hasInstalledComponent(identity AssemblyIdentity) bool {
	if _, found := state.installedComponentExact[identity.ExactKey()]; found {
		return true
	}
	matches := func(candidates []manifestPath) bool {
		for _, candidate := range candidates {
			if componentPathMayMatch(candidate.Component, identity) {
				return true
			}
		}
		return false
	}
	coreKey := componentCoreShapeKey(identity)
	if strings.TrimSpace(identity.Language) == "*" {
		return matches(state.componentsByCore[coreKey])
	}
	for _, candidates := range [][]manifestPath{
		state.componentsByName[componentCanonicalKey(identity)],
		state.abbreviatedByShape[componentShapeKey(identity)],
		state.abbreviatedByLocale[coreKey],
	} {
		if matches(candidates) {
			return true
		}
	}
	return false
}

func (state *assemblyImageState) hasInstalledComponentFamily(identity AssemblyIdentity) bool {
	_, found := state.latestInstalledComponent(identity)
	return found
}

func (state *assemblyImageState) latestInstalledComponent(identity AssemblyIdentity) (manifestPath, bool) {
	family := componentFamilyKey(identity)
	if current, found := state.latestComponentByFamily[family]; found {
		return current, true
	}
	if _, knownAbsent := state.absentComponentFamilies[family]; knownAbsent {
		return manifestPath{}, false
	}
	var found *manifestPath
	visit := func(candidates []manifestPath) {
		for index := range candidates {
			candidate := &candidates[index]
			if !componentPathFamilyMayMatch(candidate.Component, identity) {
				continue
			}
			if found == nil || compareVersions(candidate.Identity.Version, found.Identity.Version) > 0 {
				copy := *candidate
				found = &copy
			}
		}
	}
	if strings.TrimSpace(identity.Language) == "*" {
		visit(state.componentCandidates)
	} else {
		visit(state.familyAbbreviated[componentFamilyShapeKey(identity)])
		visit(state.familyAbbreviatedLocale[componentFamilyCoreKey(identity)])
	}
	if found == nil {
		state.absentComponentFamilies[family] = struct{}{}
		return manifestPath{}, false
	}
	// Memoize the full manifest identity as an alias for the abbreviated
	// component-store key. Later dependency and predecessor checks are O(1).
	state.latestComponentByFamily[family] = *found
	return *found, true
}

func (state *assemblyImageState) hasInstalledIdentity(identity AssemblyIdentity) bool {
	if _, found := state.packagesByExact[identity.ExactKey()]; found {
		return true
	}
	return state.hasInstalledComponent(identity)
}

func (state *assemblyImageState) hasInstalledPackageFamily(identity AssemblyIdentity) bool {
	_, found := state.latestPackageByStable[identity.StableKey()]
	return found
}

func packageManifestApplicable(manifest *AssemblyManifest, state *assemblyImageState, selected map[string]struct{}) bool {
	hasParent := false
	for _, reference := range manifest.References {
		if reference.Kind != "parent" {
			continue
		}
		hasParent = true
		if state.hasInstalledIdentity(reference.Identity) {
			return true
		}
		if _, found := selected[reference.Identity.ExactKey()]; found {
			return true
		}
	}
	return !hasParent
}

func isWildcardResourceReference(reference AssemblyReference) bool {
	if strings.TrimSpace(reference.Identity.Language) != "*" {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(reference.ResourceType), "Resources") ||
		strings.HasSuffix(strings.ToLower(strings.TrimSpace(reference.Identity.Name)), ".resources")
}

func (component PlannedComponent) ComponentFamilyKey() string {
	return strings.ToLower(strings.Join([]string{component.Identity.ProcessorArchitecture, component.Identity.Name, component.Identity.PublicKeyToken, normalizedLanguage(component.Identity.Language)}, "\x00"))
}

func normalizedLanguage(language string) string {
	if language == "" {
		return "neutral"
	}
	return language
}

func formatAssemblyIdentity(identity AssemblyIdentity) string {
	return fmt.Sprintf("%q version %q architecture %q language %q token %q", identity.Name, identity.Version, identity.ProcessorArchitecture, normalizedLanguage(identity.Language), identity.PublicKeyToken)
}

func formatComponentSelection(ownerKind string, owner AssemblyIdentity, reference AssemblyReference) string {
	return fmt.Sprintf("%s %s via %s dependencyType=%q resourceType=%q attributes=%v", ownerKind, formatAssemblyIdentity(owner), reference.Kind, reference.DependencyType, reference.ResourceType, reference.Attributes)
}

func summarizeComponentCandidates(candidates []manifestPath, wanted AssemblyIdentity) string {
	type scored struct {
		path  string
		score int
	}
	wantedName := componentPathName(wanted.Name)
	var matches []scored
	for _, candidate := range candidates {
		identity := candidate.Component.Identity
		if !strings.EqualFold(identity.ProcessorArchitecture, wanted.ProcessorArchitecture) ||
			!strings.EqualFold(identity.PublicKeyToken, wanted.PublicKeyToken) ||
			!strings.EqualFold(identity.Version, wanted.Version) ||
			!sameManifestLanguage(identity.Language, wanted.Language) {
			continue
		}
		name := componentPathName(identity.Name)
		prefix := 0
		for prefix < len(name) && prefix < len(wantedName) && name[prefix] == wantedName[prefix] {
			prefix++
		}
		suffix := 0
		for suffix < len(name) && suffix < len(wantedName) && name[len(name)-1-suffix] == wantedName[len(wantedName)-1-suffix] {
			suffix++
		}
		matches = append(matches, scored{path: candidate.Path, score: prefix + suffix})
	}
	if len(matches) == 0 {
		return "none with matching architecture/token/version/language"
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].score != matches[j].score {
			return matches[i].score > matches[j].score
		}
		return strings.ToLower(matches[i].path) < strings.ToLower(matches[j].path)
	})
	if len(matches) > 3 {
		matches = matches[:3]
	}
	paths := make([]string, len(matches))
	for index, match := range matches {
		paths[index] = fmt.Sprintf("%q", match.path)
	}
	return strings.Join(paths, ", ")
}
