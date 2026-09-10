package uup

import (
	"encoding/base64"
	"fmt"
	"path"
	"sort"
	"strings"

	windowsupdate "github.com/tinyrange/trex/windows/update"
)

// UpdatePayloadSource identifies either a directly offered file or one logical
// member of an offered container. Container remains the signed Windows Update
// download identity; Member is never a host path.
type UpdatePayloadSource struct {
	Container windowsupdate.File
	Member    string
	Name      string
	Size      int64
}

// UpdatePayload is one resolved servicing payload with the role declared by
// its CompDB payload type and logical name.
type UpdatePayload struct {
	PackageID    string
	Role         string
	Source       UpdatePayloadSource
	DigestSHA256 string
	Selected     bool
}

type UpdateStageDependency struct {
	FeatureID string
	Kind      string
}

// UpdateStagePlan is one independently applicable BuildUpdate composition.
// Scope identifies the image the update targets; package applicability inside
// that image is decided later from its installed CBS inventory.
type UpdateStagePlan struct {
	DatabaseSource  string
	DatabaseName    string
	FeatureID       string
	FeatureType     string
	Scope           string
	OSVersion       string
	TargetOSVersion string
	Representation  string
	Dependencies    []UpdateStageDependency
	Payloads        []UpdatePayload
}

// PlanUpdateStages resolves every BuildUpdate feature/package/payload edge.
// It retains setup and recovery updates as distinct scopes so callers cannot
// accidentally apply them to the installed operating-system image.
func PlanUpdateStages(databases []*Database, files []windowsupdate.File, architecture string) ([]UpdateStagePlan, error) {
	sources := make([]UpdatePayloadSource, 0, len(files))
	for _, file := range files {
		sources = append(sources, UpdatePayloadSource{Container: file, Name: file.Name, Size: file.Size})
	}
	return PlanUpdateStagesFromSources(databases, sources, architecture)
}

// PlanUpdateStagesFromSources resolves BuildUpdate payloads against direct
// downloads and explicitly indexed members of update containers such as MSU.
func PlanUpdateStagesFromSources(databases []*Database, sources []UpdatePayloadSource, architecture string) ([]UpdateStagePlan, error) {
	architecture = strings.TrimSpace(architecture)
	byName := make(map[string][]UpdatePayloadSource, len(sources))
	for _, source := range sources {
		if source.Name == "" || source.Size < 0 || source.Container.Name == "" {
			return nil, fmt.Errorf("uup: invalid update payload source for container %q member %q", source.Container.Name, source.Member)
		}
		byName[strings.ToLower(path.Base(strings.ReplaceAll(source.Name, "\\", "/")))] = append(byName[strings.ToLower(path.Base(strings.ReplaceAll(source.Name, "\\", "/")))], source)
	}
	var result []UpdateStagePlan
	for databaseIndex, database := range databases {
		if database == nil {
			return nil, fmt.Errorf("uup: update CompDB catalog entry %d is nil", databaseIndex)
		}
		if !strings.EqualFold(database.Type, "BuildUpdate") || (architecture != "" && !strings.EqualFold(database.Architecture, architecture)) {
			continue
		}
		if len(database.Features) == 0 {
			return nil, fmt.Errorf("uup: BuildUpdate CompDB %q has no features", database.Name)
		}
		definitions := make(map[string][]Package)
		for _, pack := range database.Packages {
			if pack.ID != "" && len(pack.Payload) != 0 {
				key := strings.ToLower(pack.ID)
				definitions[key] = append(definitions[key], pack)
			}
		}
		referencedDefinitions := make(map[string]struct{})
		for featureIndex := range database.Features {
			feature := &database.Features[featureIndex]
			if feature.ID == "" {
				return nil, fmt.Errorf("uup: BuildUpdate CompDB %q has a feature without an ID", database.Name)
			}
			scope, err := updateFeatureScope(feature.Type)
			if err != nil {
				return nil, fmt.Errorf("uup: BuildUpdate feature %q in CompDB %q: %w", feature.ID, database.Name, err)
			}
			stage := UpdateStagePlan{
				DatabaseSource: database.Source, DatabaseName: database.Name, FeatureID: feature.ID, FeatureType: feature.Type,
				Scope: scope, OSVersion: database.OSVersion, TargetOSVersion: database.TargetOSVersion,
			}
			seen := make(map[string]struct{})
			for _, reference := range feature.Packages {
				if reference.ID == "" {
					return nil, fmt.Errorf("uup: BuildUpdate feature %q in CompDB %q has a package reference without an ID", feature.ID, database.Name)
				}
				packageKey := strings.ToLower(reference.ID)
				packages := definitions[packageKey]
				if len(reference.Payload) != 0 {
					if len(packages) != 0 {
						return nil, fmt.Errorf("uup: BuildUpdate feature %q in CompDB %q package %q is defined both inline and globally", feature.ID, database.Name, reference.ID)
					}
					packages = []Package{reference}
				} else {
					referencedDefinitions[packageKey] = struct{}{}
				}
				if len(packages) == 0 {
					return nil, fmt.Errorf("uup: BuildUpdate feature %q in CompDB %q references undefined package %q", feature.ID, database.Name, reference.ID)
				}
				if len(packages) != 1 {
					return nil, fmt.Errorf("uup: BuildUpdate feature %q in CompDB %q package %q has %d payload definitions", feature.ID, database.Name, reference.ID, len(packages))
				}
				for _, payload := range packages[0].Payload {
					source, digest, err := resolveUpdatePayload(payload, byName)
					if err != nil {
						return nil, fmt.Errorf("uup: BuildUpdate package %q in CompDB %q payload %q: %w", reference.ID, database.Name, payload.Path, err)
					}
					if source.Name == "" {
						return nil, fmt.Errorf("uup: BuildUpdate package %q in CompDB %q has unresolved payload %q", reference.ID, database.Name, payload.Path)
					}
					role, err := updatePayloadRole(payload.Type, source.Name)
					if err != nil {
						return nil, fmt.Errorf("uup: BuildUpdate package %q in CompDB %q payload %q: %w", reference.ID, database.Name, payload.Path, err)
					}
					key := role + "\x00" + strings.ToLower(digest) + "\x00" + strings.ToLower(source.Container.DigestSHA256) + "\x00" + strings.ToLower(source.Member)
					if _, exists := seen[key]; exists {
						continue
					}
					seen[key] = struct{}{}
					stage.Payloads = append(stage.Payloads, UpdatePayload{PackageID: reference.ID, Role: role, Source: source, DigestSHA256: digest})
				}
			}
			if len(stage.Payloads) == 0 {
				return nil, fmt.Errorf("uup: BuildUpdate feature %q in CompDB %q has no resolved payloads", feature.ID, database.Name)
			}
			if err := selectUpdateRepresentation(&stage); err != nil {
				return nil, fmt.Errorf("uup: BuildUpdate feature %q in CompDB %q: %w", feature.ID, database.Name, err)
			}
			sort.Slice(stage.Payloads, func(i, j int) bool {
				if stage.Payloads[i].Role != stage.Payloads[j].Role {
					return stage.Payloads[i].Role < stage.Payloads[j].Role
				}
				return strings.ToLower(stage.Payloads[i].Source.Name) < strings.ToLower(stage.Payloads[j].Source.Name)
			})
			result = append(result, stage)
		}
		for packageKey, packages := range definitions {
			if _, referenced := referencedDefinitions[packageKey]; !referenced {
				return nil, fmt.Errorf("uup: BuildUpdate CompDB %q has unreferenced payload package %q", database.Name, packages[0].ID)
			}
		}
	}
	if err := resolveUpdateFeatureDependencies(result, databases, architecture); err != nil {
		return nil, err
	}
	return orderUpdateStages(result)
}

func resolveUpdateFeatureDependencies(stages []UpdateStagePlan, databases []*Database, architecture string) error {
	type owner struct {
		database *Database
		feature  *Feature
	}
	index := make(map[string][]owner)
	for _, database := range databases {
		if database == nil || (architecture != "" && database.Architecture != "" && !strings.EqualFold(database.Architecture, architecture)) {
			continue
		}
		for featureIndex := range database.Features {
			feature := &database.Features[featureIndex]
			index[strings.ToLower(feature.ID)] = append(index[strings.ToLower(feature.ID)], owner{database: database, feature: feature})
		}
	}
	stageByFeature := make(map[string]int)
	for stageIndex := range stages {
		key := strings.ToLower(stages[stageIndex].FeatureID)
		if previous, exists := stageByFeature[key]; exists {
			return fmt.Errorf("uup: BuildUpdate feature ID %q is ambiguous between CompDBs %q and %q", stages[stageIndex].FeatureID, stages[previous].DatabaseName, stages[stageIndex].DatabaseName)
		}
		stageByFeature[key] = stageIndex
	}
	for _, database := range databases {
		if database == nil || !strings.EqualFold(database.Type, "BuildUpdate") || (architecture != "" && !strings.EqualFold(database.Architecture, architecture)) {
			continue
		}
		for featureIndex := range database.Features {
			feature := &database.Features[featureIndex]
			consumer, exists := stageByFeature[strings.ToLower(feature.ID)]
			if !exists {
				return fmt.Errorf("uup: BuildUpdate feature %q has no planned stage", feature.ID)
			}
			for _, dependency := range feature.Dependencies {
				required, err := mediaDependencyRequired(dependency.Type)
				if err != nil {
					return fmt.Errorf("uup: BuildUpdate feature %q dependency %s: %w", feature.ID, featureReferenceString(dependency), err)
				}
				if !required {
					continue
				}
				var matches []owner
				for _, candidate := range index[strings.ToLower(dependency.ID)] {
					if featureReferenceMatches(dependency, candidate.feature) {
						matches = append(matches, candidate)
					}
				}
				if len(matches) != 1 {
					return fmt.Errorf("uup: BuildUpdate feature %q dependency %s resolves to %d features", feature.ID, featureReferenceString(dependency), len(matches))
				}
				if strings.EqualFold(matches[0].database.Type, "BuildUpdate") {
					stages[consumer].Dependencies = append(stages[consumer].Dependencies, UpdateStageDependency{FeatureID: matches[0].feature.ID, Kind: "feature-required"})
				}
			}
		}
	}
	return nil
}

func selectUpdateRepresentation(stage *UpdateStagePlan) error {
	counts := make(map[string]int)
	for _, payload := range stage.Payloads {
		counts[payload.Role]++
	}
	hasExpress := counts["express-metadata"] != 0 || counts["express-psf"] != 0
	if hasExpress {
		if counts["express-metadata"] == 0 || counts["express-psf"] != 1 {
			return fmt.Errorf("incomplete express representation: %d metadata payloads and %d PSFs", counts["express-metadata"], counts["express-psf"])
		}
		stage.Representation = "express"
		for index := range stage.Payloads {
			stage.Payloads[index].Selected = stage.Payloads[index].Role == "express-metadata" || stage.Payloads[index].Role == "express-psf"
		}
		return nil
	}
	canonical := counts["canonical-cab"] + counts["psfx-cab"]
	if canonical != 1 {
		return fmt.Errorf("canonical representation has %d payloads, want exactly one", canonical)
	}
	stage.Representation = "canonical"
	for index := range stage.Payloads {
		stage.Payloads[index].Selected = stage.Payloads[index].Role == "canonical-cab" || stage.Payloads[index].Role == "psfx-cab"
	}
	return nil
}

func orderUpdateStages(stages []UpdateStagePlan) ([]UpdateStagePlan, error) {
	edges := make([]map[int]string, len(stages))
	indegree := make([]int, len(stages))
	addEdge := func(from, to int, kind string) {
		if from == to {
			return
		}
		if edges[from] == nil {
			edges[from] = make(map[int]string)
		}
		if _, exists := edges[from][to]; exists {
			return
		}
		edges[from][to] = kind
		indegree[to]++
		stages[to].Dependencies = append(stages[to].Dependencies, UpdateStageDependency{FeatureID: stages[from].FeatureID, Kind: kind})
	}
	stageByFeature := make(map[string]int)
	for index := range stages {
		key := strings.ToLower(stages[index].FeatureID)
		if previous, exists := stageByFeature[key]; exists {
			return nil, fmt.Errorf("uup: duplicate BuildUpdate feature ID %q at stages %d and %d", stages[index].FeatureID, previous, index)
		}
		stageByFeature[key] = index
	}
	for consumer := range stages {
		declared := append([]UpdateStageDependency(nil), stages[consumer].Dependencies...)
		stages[consumer].Dependencies = nil
		for _, dependency := range declared {
			producer, exists := stageByFeature[strings.ToLower(dependency.FeatureID)]
			if !exists {
				return nil, fmt.Errorf("uup: stage %q has unresolved stage dependency %q", stages[consumer].FeatureID, dependency.FeatureID)
			}
			addEdge(producer, consumer, dependency.Kind)
		}
	}
	for producer := range stages {
		for consumer := range stages {
			if producer == consumer || stages[producer].Scope != stages[consumer].Scope {
				continue
			}
			if stages[producer].TargetOSVersion != "" && strings.EqualFold(stages[producer].TargetOSVersion, stages[consumer].OSVersion) {
				addEdge(producer, consumer, "version-predecessor")
			}
		}
	}
	for first := range stages {
		if !strings.EqualFold(stages[first].FeatureType, "ServicingStackUpdate") {
			continue
		}
		for second := range stages {
			if first == second || strings.EqualFold(stages[second].FeatureType, "ServicingStackUpdate") {
				continue
			}
			if updateStagesShareContainer(stages[first], stages[second]) {
				addEdge(first, second, "container-ssu-before-update")
			}
		}
	}
	less := func(left, right int) bool {
		if rank := updateScopePriority(stages[left].Scope) - updateScopePriority(stages[right].Scope); rank != 0 {
			return rank < 0
		}
		if comparison := compareVersions(stages[left].TargetOSVersion, stages[right].TargetOSVersion); comparison != 0 {
			return comparison < 0
		}
		if priority := updateStagePriority(stages[left]) - updateStagePriority(stages[right]); priority != 0 {
			return priority < 0
		}
		return strings.ToLower(stages[left].FeatureID) < strings.ToLower(stages[right].FeatureID)
	}
	ready := make([]int, 0, len(stages))
	for index, count := range indegree {
		if count == 0 {
			ready = append(ready, index)
		}
	}
	var ordered []UpdateStagePlan
	for len(ready) != 0 {
		sort.Slice(ready, func(i, j int) bool { return less(ready[i], ready[j]) })
		current := ready[0]
		ready = ready[1:]
		sort.Slice(stages[current].Dependencies, func(i, j int) bool {
			return stages[current].Dependencies[i].FeatureID < stages[current].Dependencies[j].FeatureID
		})
		ordered = append(ordered, stages[current])
		for next := range edges[current] {
			indegree[next]--
			if indegree[next] == 0 {
				ready = append(ready, next)
			}
		}
	}
	if len(ordered) != len(stages) {
		return nil, fmt.Errorf("uup: BuildUpdate stage dependency cycle")
	}
	return ordered, nil
}

func updateStagesShareContainer(left, right UpdateStagePlan) bool {
	containers := make(map[string]struct{})
	for _, payload := range left.Payloads {
		if payload.Selected {
			containers[strings.ToLower(payload.Source.Container.DigestSHA256+"\x00"+payload.Source.Container.Name)] = struct{}{}
		}
	}
	for _, payload := range right.Payloads {
		if !payload.Selected {
			continue
		}
		if _, exists := containers[strings.ToLower(payload.Source.Container.DigestSHA256+"\x00"+payload.Source.Container.Name)]; exists {
			return true
		}
	}
	return false
}

func updateScopePriority(scope string) int {
	switch scope {
	case "installed-os":
		return 0
	case "recovery":
		return 1
	case "setup":
		return 2
	default:
		return 3
	}
}

func resolveUpdatePayload(payload PayloadItem, byName map[string][]UpdatePayloadSource) (UpdatePayloadSource, string, error) {
	name := path.Base(strings.ReplaceAll(payload.Path, "\\", "/"))
	var wantedDigest string
	if payload.Hash != "" {
		decoded, err := base64.StdEncoding.DecodeString(payload.Hash)
		if err != nil || len(decoded) != 32 {
			return UpdatePayloadSource{}, "", fmt.Errorf("invalid SHA-256 payload hash")
		}
		wantedDigest = fmt.Sprintf("%x", decoded)
	}
	var matches []UpdatePayloadSource
	for _, source := range byName[strings.ToLower(name)] {
		if payload.Size >= 0 && source.Size != payload.Size {
			continue
		}
		if wantedDigest != "" && source.Member == "" && !strings.EqualFold(source.Container.DigestSHA256, wantedDigest) {
			continue
		}
		matches = append(matches, source)
	}
	if len(matches) == 0 {
		return UpdatePayloadSource{}, wantedDigest, nil
	}
	if len(matches) != 1 {
		locations := make([]string, 0, len(matches))
		for _, match := range matches {
			location := match.Container.Name
			if match.Member != "" {
				location += "!" + match.Member
			}
			locations = append(locations, location)
		}
		sort.Strings(locations)
		return UpdatePayloadSource{}, wantedDigest, fmt.Errorf("payload identity is ambiguous across %s", strings.Join(locations, ", "))
	}
	if wantedDigest == "" && matches[0].Member == "" {
		wantedDigest = matches[0].Container.DigestSHA256
	}
	return matches[0], wantedDigest, nil
}

func updateFeatureScope(featureType string) (string, error) {
	switch strings.ToLower(featureType) {
	case "safeosupdate":
		return "recovery", nil
	case "setupdynamicupdate":
		return "setup", nil
	case "servicingstackupdate", "cumulativeupdate", "gdr":
		return "installed-os", nil
	default:
		return "", fmt.Errorf("unsupported feature type %q", featureType)
	}
}

func updatePayloadRole(payloadType, name string) (string, error) {
	extension := strings.ToLower(path.Ext(name))
	switch strings.ToLower(payloadType) {
	case "canonical":
		if extension != ".cab" {
			return "", fmt.Errorf("Canonical payload has unsupported extension %q", extension)
		}
		return "canonical-cab", nil
	case "psfx":
		if extension != ".cab" {
			return "", fmt.Errorf("PSFX payload has unsupported extension %q", extension)
		}
		return "psfx-cab", nil
	case "expresscab":
		if extension != ".cab" && extension != ".wim" && extension != ".esd" {
			return "", fmt.Errorf("ExpressCab payload has unsupported extension %q", extension)
		}
		return "express-metadata", nil
	case "expresspsf":
		if extension != ".psf" {
			return "", fmt.Errorf("ExpressPSF payload has unsupported extension %q", extension)
		}
		return "express-psf", nil
	default:
		return "", fmt.Errorf("unsupported payload type %q", payloadType)
	}
}

func updateStagePriority(stage UpdateStagePlan) int {
	switch strings.ToLower(stage.FeatureType) {
	case "servicingstackupdate":
		return 0
	case "cumulativeupdate", "gdr":
		return 1
	case "safeosupdate":
		return 2
	case "setupdynamicupdate":
		return 3
	default:
		return 1
	}
}
