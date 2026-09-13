package uup

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
)

// StageEffectSummary inventories the portable offline effects declared by the
// selected component manifests. TopLevel counts every root effect family so a
// caller can reject unsupported semantics rather than silently omit them.
type StageEffectSummary struct {
	Files              int
	Links              int
	RegistryKeys       int
	RegistryValues     int
	SelectedPayloads   int
	UnselectedPayloads int
	TopLevel           map[string]int
	DestinationRoots   map[string]int
	RegistryRoots      map[string]int
	RegistryTypes      map[string]int
}

type StageFileEffect struct {
	Architecture     string
	Kind             string
	SourceName       string
	SourceMode       string
	SourceDescriptor *ContentDescriptor
	ExpectedSHA256   *[sha256.Size]byte
	StorePath        string
	Destinations     []string
}

type StageRegistryEffect struct {
	Architecture string
	Value        AssemblyRegistryValue
}

type StageRegistryKeyEffect struct {
	Architecture string
	KeyName      string
}

type StageEffectPlan struct {
	Files          []StageFileEffect
	RegistryKeys   []StageRegistryKeyEffect
	RegistryValues []StageRegistryEffect
	Summary        StageEffectSummary
}

type stageEffectSource struct {
	Name       string
	Mode       string
	Descriptor *ContentDescriptor
}

func AnalyzeStageEffects(stage *CumulativeStage, plan StageAssemblyPlan) (StageEffectSummary, error) {
	effects, err := PlanStageEffects(stage, plan)
	if err != nil {
		return StageEffectSummary{}, err
	}
	return effects.Summary, nil
}

// PlanStageEffects joins the selected CBS package/component closure to the
// stage content graph. Every selected manifest, catalog, and declared file
// must have one exact logical payload; unresolved content is fatal.
func PlanStageEffects(stage *CumulativeStage, plan StageAssemblyPlan) (StageEffectPlan, error) {
	result := StageEffectPlan{Summary: StageEffectSummary{
		TopLevel: make(map[string]int), DestinationRoots: make(map[string]int),
		RegistryRoots: make(map[string]int), RegistryTypes: make(map[string]int),
	}}
	if stage == nil || stage.Graph == nil {
		return StageEffectPlan{}, fmt.Errorf("uup servicing: stage content graph is required")
	}
	payloads := make(map[string]DeltaPayload, len(stage.Graph.Payloads))
	payloadsByHash := make(map[[sha256.Size]byte][]DeltaPayload)
	for _, payload := range stage.Graph.Payloads {
		payloadsByHash[payload.Target.SHA256] = append(payloadsByHash[payload.Target.SHA256], payload)
		for _, key := range stageEffectLookupKeys(payload.Target.Name) {
			if previous, exists := payloads[key]; exists && normalizeCIXName(previous.Target.Name) != normalizeCIXName(payload.Target.Name) {
				return StageEffectPlan{}, fmt.Errorf("uup servicing: content lookup key %q is ambiguous between %q and %q", key, previous.Target.Name, payload.Target.Name)
			}
			payloads[key] = payload
		}
	}
	sources := make(map[string]ContentDescriptor, len(stage.Graph.Carries))
	sourcesByHash := make(map[[sha256.Size]byte][]CarryPayload)
	for _, carry := range stage.Graph.Carries {
		sourcesByHash[carry.Target.SHA256] = append(sourcesByHash[carry.Target.SHA256], carry)
		for _, key := range stageEffectLookupKeys(carry.Target.Name) {
			if previous, exists := sources[key]; exists && (previous.SHA256 != carry.Source.SHA256 || previous.Length != carry.Source.Length) {
				return StageEffectPlan{}, fmt.Errorf("uup servicing: predecessor lookup key %q has conflicting descriptors", key)
			}
			sources[key] = carry.Source
		}
	}
	metadata := make(map[string]string)
	entries, err := stage.metadataEntries()
	if err != nil {
		return StageEffectPlan{}, err
	}
	for _, entry := range entries {
		for _, key := range stageEffectLookupKeys(entry.Path) {
			if previous, exists := metadata[key]; exists && !strings.EqualFold(previous, entry.Path) {
				return StageEffectPlan{}, fmt.Errorf("uup servicing: metadata lookup key %q is ambiguous between %q and %q", key, previous, entry.Path)
			}
			metadata[key] = entry.Path
		}
	}
	selected := make(map[string]struct{})
	addFile := func(kind string, sourceNames []string, expectedHash *[sha256.Size]byte, installedFallback, storePath string, destinations []string) error {
		source, err := resolveStageEffectSource(kind, sourceNames, expectedHash, payloads, payloadsByHash, sources, sourcesByHash, metadata, installedFallback)
		if err != nil {
			return err
		}
		if source.Mode == "payload" {
			key := normalizeCIXName(source.Name)
			if _, exists := selected[key]; exists {
				return fmt.Errorf("uup servicing: content payload %q selected more than once", source.Name)
			}
			selected[key] = struct{}{}
		}
		result.Files = append(result.Files, StageFileEffect{Kind: kind, SourceName: source.Name, SourceMode: source.Mode, SourceDescriptor: source.Descriptor, ExpectedSHA256: expectedHash, StorePath: storePath, Destinations: destinations})
		return nil
	}
	packages := append([]NamedAssemblyManifest(nil), plan.Packages...)
	sort.Slice(packages, func(i, j int) bool { return strings.ToLower(packages[i].Path) < strings.ToLower(packages[j].Path) })
	for _, pack := range packages {
		name := strings.TrimPrefix(strings.ReplaceAll(pack.Path, "\\", "/"), "/")
		base := path.Base(name)
		if err := addFile("package-manifest", []string{name}, nil, "", "/Windows/servicing/Packages/"+base, nil); err != nil {
			return StageEffectPlan{}, err
		}
		catalog := strings.TrimSuffix(name, path.Ext(name)) + ".cat"
		// The CBS package store alone is not a Code Integrity catalog
		// installation. Keep the verified catalog there and link the same
		// bytes into the native catalog store, including for WOW64 packages.
		// FileCrypt's catalog-only signature exercises this during boot.
		catalogDestination := `$(runtime.windows)\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\` + path.Base(catalog)
		if err := addFile("package-catalog", []string{catalog}, nil, "", "/Windows/servicing/Packages/"+path.Base(catalog), []string{catalogDestination}); err != nil {
			return StageEffectPlan{}, err
		}
	}
	components := append([]PlannedComponent(nil), plan.Components...)
	sort.Slice(components, func(i, j int) bool { return components[i].Path < components[j].Path })
	for _, component := range components {
		file, err := stage.openAssemblyFile(component.Path)
		if err != nil {
			return StageEffectPlan{}, fmt.Errorf("uup servicing: open component manifest %q: %w", component.Path, err)
		}
		if file.Size() < 0 || file.Size() > maximumAssemblyManifestSize {
			return StageEffectPlan{}, fmt.Errorf("uup servicing: component manifest %q exceeds %d-byte bound", component.Path, maximumAssemblyManifestSize)
		}
		manifest, err := ParseAssemblyManifest(io.NewSectionReader(file, 0, file.Size()))
		stage.releaseAssemblyFile(component.Path)
		if err != nil {
			return StageEffectPlan{}, fmt.Errorf("uup servicing: parse component manifest %q: %w", component.Path, err)
		}
		if manifest.Identity.ExactKey() != component.Identity.ExactKey() {
			return StageEffectPlan{}, fmt.Errorf("uup servicing: component manifest %q identity does not match package reference", component.Path)
		}
		manifestName := strings.TrimPrefix(strings.ReplaceAll(component.Path, "\\", "/"), "/")
		if err := addFile("component-manifest", []string{manifestName}, nil, "", "/Windows/WinSxS/Manifests/"+path.Base(manifestName), nil); err != nil {
			return StageEffectPlan{}, err
		}
		result.Summary.Files += len(manifest.Files)
		result.Summary.RegistryKeys += len(manifest.RegistryKeys)
		for _, key := range manifest.RegistryKeys {
			result.RegistryKeys = append(result.RegistryKeys, StageRegistryKeyEffect{
				Architecture: manifest.Identity.ProcessorArchitecture,
				KeyName:      key,
			})
		}
		result.Summary.RegistryValues += len(manifest.RegistryValues)
		for _, value := range manifest.RegistryValues {
			result.RegistryValues = append(result.RegistryValues, StageRegistryEffect{
				Architecture: manifest.Identity.ProcessorArchitecture,
				Value:        value,
			})
			result.Summary.RegistryRoots[firstPathPart(value.KeyName)]++
			result.Summary.RegistryTypes[strings.ToUpper(value.ValueType)]++
		}
		for _, file := range manifest.Files {
			relative, err := componentSourcePath(file)
			if err != nil {
				return StageEffectPlan{}, fmt.Errorf("uup servicing: component %q: %w", manifest.Identity.Name, err)
			}
			sourceNames, err := componentPayloadSourceNames(component.Stem, file)
			if err != nil {
				return StageEffectPlan{}, fmt.Errorf("uup servicing: component %q: %w", manifest.Identity.Name, err)
			}
			expectedHash, err := assemblyFileSHA256(file)
			if err != nil {
				return StageEffectPlan{}, fmt.Errorf("uup servicing: component %q file %q: %w", manifest.Identity.Name, file.Name, err)
			}
			destinations := make([]string, 0, 1+len(file.Links))
			if file.DestinationPath != "" {
				destinations = append(destinations, componentDestinationPath(file.DestinationPath, relative))
				result.Summary.DestinationRoots[firstPathPart(file.DestinationPath)]++
			}
			for _, destination := range file.Links {
				destinations = append(destinations, destination)
				result.Summary.DestinationRoots[firstPathPart(destination)]++
				result.Summary.Links++
			}
			storePath := "/Windows/WinSxS/" + component.Stem + "/" + relative
			installedFallback := ""
			if component.PreviousStem != "" {
				installedFallback = component.PreviousStem + `\` + strings.ReplaceAll(relative, "/", `\`)
			}
			if err := addFile("component-file", sourceNames, expectedHash, installedFallback, storePath, destinations); err != nil {
				return StageEffectPlan{}, fmt.Errorf("uup servicing: component %s selected by %s file %q attributes=%v: %w", formatAssemblyIdentity(manifest.Identity), component.SelectedBy, file.Name, file.Attributes, err)
			}
			result.Files[len(result.Files)-1].Architecture = manifest.Identity.ProcessorArchitecture
		}
		for _, name := range manifest.TopLevel {
			result.Summary.TopLevel[name]++
		}
	}
	result.Summary.SelectedPayloads = len(selected)
	result.Summary.UnselectedPayloads = len(stage.Graph.Payloads) - len(selected)
	if result.Summary.UnselectedPayloads < 0 {
		return StageEffectPlan{}, fmt.Errorf("uup servicing: selected content exceeds stage graph")
	}
	sort.Slice(result.Files, func(i, j int) bool {
		return strings.ToLower(result.Files[i].StorePath) < strings.ToLower(result.Files[j].StorePath)
	})
	return result, nil
}

func stageEffectLookupKeys(name string) []string {
	key := normalizeCIXName(name)
	keys := []string{key}
	if strings.HasPrefix(key, "image1\\") {
		keys = append(keys, strings.TrimPrefix(key, "image1\\"))
	}
	return keys
}

func resolveStageEffectSource(kind string, candidates []string, expectedHash *[sha256.Size]byte, payloads map[string]DeltaPayload, payloadsByHash map[[sha256.Size]byte][]DeltaPayload, sources map[string]ContentDescriptor, sourcesByHash map[[sha256.Size]byte][]CarryPayload, metadata map[string]string, installedFallback string) (stageEffectSource, error) {
	// Candidate order is semantic: file.name is the installed logical target;
	// sourceName/sourcePath are build-source fallbacks. Both names can exist as
	// distinct payloads in one component and therefore must not be unioned.
	for _, candidate := range candidates {
		var match *DeltaPayload
		for _, key := range stageEffectLookupKeys(candidate) {
			if payload, ok := payloads[key]; ok {
				copy := payload
				match = &copy
				break
			}
		}
		if match != nil {
			if expectedHash != nil && match.Target.SHA256 != *expectedHash {
				return stageEffectSource{}, fmt.Errorf("uup servicing: selected %s content payload %q does not match its manifest SHA-256", kind, match.Target.Name)
			}
			return stageEffectSource{Name: match.Target.Name, Mode: "payload"}, nil
		}
	}
	for _, candidate := range candidates {
		for _, key := range stageEffectLookupKeys(candidate) {
			if predecessor, found := sources[key]; found {
				if expectedHash != nil && predecessor.SHA256 != *expectedHash {
					return stageEffectSource{}, fmt.Errorf("uup servicing: selected %s predecessor %q does not match its manifest SHA-256", kind, predecessor.Name)
				}
				copy := predecessor
				return stageEffectSource{Name: predecessor.Name, Mode: "predecessor", Descriptor: &copy}, nil
			}
		}
	}
	if expectedHash != nil && len(candidates) != 0 {
		prefix := stageEffectComponentPrefix(candidates[0])
		var payloadMatch string
		for _, payload := range payloadsByHash[*expectedHash] {
			if stageEffectComponentPrefix(payload.Target.Name) != prefix {
				continue
			}
			if payloadMatch != "" && normalizeCIXName(payloadMatch) != normalizeCIXName(payload.Target.Name) {
				return stageEffectSource{}, fmt.Errorf("uup servicing: selected %s SHA-256 is ambiguous within component %q between %q and %q", kind, prefix, payloadMatch, payload.Target.Name)
			}
			payloadMatch = payload.Target.Name
		}
		if payloadMatch != "" {
			return stageEffectSource{Name: payloadMatch, Mode: "payload"}, nil
		}
		var predecessorMatch *ContentDescriptor
		for _, carry := range sourcesByHash[*expectedHash] {
			if stageEffectComponentPrefix(carry.Target.Name) != prefix {
				continue
			}
			source := carry.Source
			if predecessorMatch != nil && (predecessorMatch.SHA256 != source.SHA256 || predecessorMatch.Length != source.Length || normalizeCIXName(predecessorMatch.Name) != normalizeCIXName(source.Name)) {
				return stageEffectSource{}, fmt.Errorf("uup servicing: selected %s SHA-256 is ambiguous within predecessor component %q between %q and %q", kind, prefix, predecessorMatch.Name, source.Name)
			}
			copy := source
			predecessorMatch = &copy
		}
		if predecessorMatch != nil {
			return stageEffectSource{Name: predecessorMatch.Name, Mode: "predecessor", Descriptor: predecessorMatch}, nil
		}
	}
	for _, candidate := range candidates {
		for _, key := range stageEffectLookupKeys(candidate) {
			if metadataName, found := metadata[key]; found {
				return stageEffectSource{Name: metadataName, Mode: "metadata"}, nil
			}
		}
	}
	if installedFallback != "" {
		return stageEffectSource{Name: installedFallback, Mode: "installed"}, nil
	}
	hashDescription := "none"
	if expectedHash != nil {
		hashDescription = fmt.Sprintf("%x", *expectedHash)
	}
	return stageEffectSource{}, fmt.Errorf("uup servicing: selected %s has no metadata or content payload for declared sources %q and SHA-256 %s", kind, candidates, hashDescription)
}

func stageEffectComponentPrefix(name string) string {
	name = normalizeCIXName(name)
	if strings.HasPrefix(name, "image1\\") {
		name = strings.TrimPrefix(name, "image1\\")
	}
	if separator := strings.IndexByte(name, '\\'); separator >= 0 {
		return name[:separator]
	}
	return name
}

func assemblyFileSHA256(file AssemblyFile) (*[sha256.Size]byte, error) {
	if file.Hash == "" || (!strings.EqualFold(file.HashAlgorithm, "sha256") && !strings.EqualFold(file.HashAlgorithm, "sha-256")) {
		return nil, nil
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(file.Hash))
	if err != nil || len(decoded) != sha256.Size {
		return nil, fmt.Errorf("invalid SHA-256 %q", file.Hash)
	}
	var result [sha256.Size]byte
	copy(result[:], decoded)
	return &result, nil
}

// componentDestinationPath keeps the store-relative source directory out of
// the installed filename. destinationPath already names the target directory.
func componentDestinationPath(directory, relative string) string {
	return strings.TrimRight(directory, `\/`) + `\` + path.Base(relative)
}

func componentPayloadSourceNames(stem string, file AssemblyFile) ([]string, error) {
	relative, err := componentSourcePath(file)
	if err != nil {
		return nil, err
	}
	prefix := strings.TrimSuffix(strings.ReplaceAll(stem, "/", "\\"), "\\") + "\\"
	result := []string{prefix + strings.ReplaceAll(relative, "/", "\\")}
	if file.SourceName == "" {
		return result, nil
	}
	sourceName, err := cleanComponentPayloadPart(file.SourceName)
	if err != nil {
		return nil, fmt.Errorf("invalid component source name %q", file.SourceName)
	}
	result = appendUniqueFold(result, prefix+strings.ReplaceAll(sourceName, "/", "\\"))
	if file.SourcePath != "" {
		if path.Clean(strings.ReplaceAll(file.SourcePath, "\\", "/")) == "." {
			return result, nil
		}
		sourcePath, err := cleanComponentPayloadPart(file.SourcePath)
		if err != nil {
			return nil, fmt.Errorf("invalid component source path %q", file.SourcePath)
		}
		result = appendUniqueFold(result, prefix+strings.ReplaceAll(path.Join(sourcePath, sourceName), "/", "\\"))
	}
	return result, nil
}

func cleanComponentPayloadPart(value string) (string, error) {
	cleaned := path.Clean(strings.ReplaceAll(value, "\\", "/"))
	if cleaned == "." || path.IsAbs(cleaned) || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("unsafe path")
	}
	return cleaned, nil
}

func appendUniqueFold(values []string, value string) []string {
	for _, existing := range values {
		if strings.EqualFold(existing, value) {
			return values
		}
	}
	return append(values, value)
}

func componentSourcePath(file AssemblyFile) (string, error) {
	// sourcePath records the build-tree provenance (often an nttree path), not
	// a directory below the component-store identity. sourceName can likewise
	// be a build input name which differs from the installed logical name.
	// The CBS file name is the path relative to the WinSxS component directory.
	value := strings.ReplaceAll(file.Name, "\\", "/")
	cleaned := path.Clean(value)
	if file.Name == "" || cleaned == "." || strings.HasPrefix(cleaned, "../") || path.IsAbs(cleaned) {
		return "", fmt.Errorf("invalid component file name %q", file.Name)
	}
	return cleaned, nil
}

func firstPathPart(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "$(") {
		if end := strings.Index(value, ")"); end >= 0 {
			return strings.ToLower(value[:end+1])
		}
	}
	if index := strings.IndexAny(value, "\\/"); index >= 0 {
		value = value[:index]
	}
	return strings.ToLower(value)
}
