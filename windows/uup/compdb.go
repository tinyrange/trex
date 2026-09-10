// Package uup parses Microsoft Unified Update Platform composition metadata
// and plans the immutable payload subset needed for an edition image.
package uup

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"

	windowsupdate "github.com/tinyrange/trex/windows/update"
)

// Database is one Microsoft CompDB document. Only portable composition data is
// represented; unknown schema additions are ignored by encoding/xml.
type Database struct {
	XMLName xml.Name `xml:"CompDB"`
	// Source identifies the member of the aggregated metadata graph that
	// supplied this document. It is planner provenance, not CompDB XML.
	Source          string    `xml:"-"`
	Name            string    `xml:"Name,attr"`
	Type            string    `xml:"Type,attr"`
	BuildInfo       string    `xml:"BuildInfo,attr"`
	OSVersion       string    `xml:"OSVersion,attr"`
	TargetBuildInfo string    `xml:"TargetBuildInfo,attr"`
	TargetOSVersion string    `xml:"TargetOSVersion,attr"`
	Architecture    string    `xml:"BuildArch,attr"`
	Tags            []Tag     `xml:"Tags>Tag"`
	Features        []Feature `xml:"Features>Feature"`
	Packages        []Package `xml:"Packages>Package"`
}

type Tag struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:"Value,attr"`
}

type Feature struct {
	ID           string       `xml:"FeatureID,attr"`
	ManifestID   string       `xml:"FMID,attr"`
	Group        string       `xml:"Group,attr"`
	Type         string       `xml:"Type,attr"`
	Dependencies []FeatureRef `xml:"Dependencies>Feature"`
	Packages     []Package    `xml:"Packages>Package"`
}

type FeatureRef struct {
	ID         string `xml:"FeatureID,attr"`
	ManifestID string `xml:"FMID,attr"`
	Group      string `xml:"Group,attr"`
	Type       string `xml:"Type,attr"`
}

type Package struct {
	ID      string        `xml:"ID,attr"`
	Type    string        `xml:"PackageType,attr"`
	Payload []PayloadItem `xml:"Payload>PayloadItem"`
}

type PayloadItem struct {
	Path    string `xml:"Path,attr"`
	Hash    string `xml:"PayloadHash,attr"`
	Type    string `xml:"PayloadType,attr"`
	Size    int64  `xml:"-"`
	RawSize string `xml:"PayloadSize,attr"`
}

// Parse reads one CompDB XML document.
func Parse(reader io.Reader) (*Database, error) {
	decoder := xml.NewDecoder(reader)
	var database Database
	if err := decoder.Decode(&database); err != nil {
		return nil, fmt.Errorf("uup CompDB: %w", err)
	}
	if database.XMLName.Local != "CompDB" {
		return nil, fmt.Errorf("uup CompDB: root element is %q, want CompDB", database.XMLName.Local)
	}
	for featureIndex := range database.Features {
		for packageIndex := range database.Features[featureIndex].Packages {
			if err := parsePayloadSizes(&database.Features[featureIndex].Packages[packageIndex]); err != nil {
				return nil, err
			}
		}
	}
	for index := range database.Packages {
		if err := parsePayloadSizes(&database.Packages[index]); err != nil {
			return nil, err
		}
	}
	return &database, nil
}

func parsePayloadSizes(pack *Package) error {
	for index := range pack.Payload {
		if pack.Payload[index].RawSize == "" {
			pack.Payload[index].Size = -1
			continue
		}
		size, err := strconv.ParseInt(pack.Payload[index].RawSize, 10, 64)
		if err != nil || size < 0 {
			return fmt.Errorf("uup CompDB: package %q has invalid payload size %q", pack.ID, pack.Payload[index].RawSize)
		}
		pack.Payload[index].Size = size
	}
	return nil
}

// EditionPlan selects the edition metadata ESD and all directly declared
// package ESDs from one target CompDB.
type EditionPlan struct {
	Metadata     windowsupdate.File
	References   []windowsupdate.File
	Cabinets     []windowsupdate.File
	Applications []windowsupdate.File
	TotalSize    int64
}

// PlanEdition plans a self-contained CompDB. Call PlanEditionCatalog when the
// target has feature dependencies on other CompDB documents.
func PlanEdition(database *Database, files []windowsupdate.File, edition, language string) (EditionPlan, error) {
	return PlanEditionCatalog(database, []*Database{database}, files, edition, language)
}

type selectedFeature struct {
	database *Database
	feature  *Feature
}

// PlanEditionCatalog resolves the target feature graph across every supplied
// CompDB before selecting payloads. A missing or ambiguous feature/package
// edge is fatal; producing a partial image is not a valid plan.
func PlanEditionCatalog(database *Database, databases []*Database, files []windowsupdate.File, edition, language string) (EditionPlan, error) {
	if database == nil {
		return EditionPlan{}, fmt.Errorf("uup: target CompDB is required")
	}
	features, err := resolveFeatureClosure(database, databases)
	if err != nil {
		return EditionPlan{}, err
	}
	edition = strings.ToLower(strings.TrimSpace(edition))
	language = strings.ToLower(strings.TrimSpace(language))
	if edition == "" || language == "" {
		return EditionPlan{}, fmt.Errorf("uup: edition and language are required")
	}
	byName := make(map[string][]windowsupdate.File, len(files))
	for _, file := range files {
		key := strings.ToLower(file.Name)
		byName[key] = append(byName[key], file)
	}
	metadataName := edition + "_" + language + ".esd"
	metadata, found, err := uniquePayloadFile(byName[metadataName])
	if err != nil {
		return EditionPlan{}, fmt.Errorf("uup: metadata ESD %q: %w", metadataName, err)
	}
	if !found {
		return EditionPlan{}, fmt.Errorf("uup: metadata ESD %q is not declared by the offer", metadataName)
	}
	plan := EditionPlan{Metadata: metadata, TotalSize: metadata.Size}
	definitions := make(map[*Database]map[string][]Package)
	for _, candidate := range databases {
		if candidate == nil {
			continue
		}
		byID := make(map[string][]Package)
		for _, pack := range candidate.Packages {
			if pack.ID != "" && len(pack.Payload) > 0 {
				key := strings.ToLower(pack.ID)
				byID[key] = append(byID[key], pack)
			}
		}
		for _, feature := range candidate.Features {
			for _, pack := range feature.Packages {
				if pack.ID != "" && len(pack.Payload) > 0 {
					key := strings.ToLower(pack.ID)
					byID[key] = append(byID[key], pack)
				}
			}
		}
		definitions[candidate] = byID
	}
	seenPayload := map[string]bool{strings.ToLower(metadata.DigestSHA256 + "\x00" + metadata.Name): true}
	for _, selected := range features {
		for _, featurePackage := range selected.feature.Packages {
			id := featurePackage.ID
			if id == "" {
				continue
			}
			packageKey := strings.ToLower(id)
			packages := definitions[selected.database][packageKey]
			if len(packages) == 0 {
				return EditionPlan{}, fmt.Errorf("uup: feature %q in CompDB %q references undefined package %q", selected.feature.ID, selected.database.Name, id)
			}
			resolved := false
			for _, pack := range packages {
				for _, payload := range pack.Payload {
					if !strings.EqualFold(payload.Type, "Canonical") {
						continue
					}
					file, exists, err := resolvePayload(payload, byName)
					if err != nil {
						return EditionPlan{}, fmt.Errorf("uup: required package %q payload %q: %w", id, payload.Path, err)
					}
					if !exists {
						continue
					}
					resolved = true
					payloadKey := strings.ToLower(file.DigestSHA256 + "\x00" + file.Name)
					if seenPayload[payloadKey] {
						continue
					}
					seenPayload[payloadKey] = true
					switch strings.ToLower(path.Ext(file.Name)) {
					case ".esd", ".wim":
						if !strings.EqualFold(file.Name, metadata.Name) {
							plan.References = append(plan.References, file)
						}
					case ".cab":
						plan.Cabinets = append(plan.Cabinets, file)
					case ".appx", ".appxbundle", ".msix", ".msixbundle":
						plan.Applications = append(plan.Applications, file)
					default:
						return EditionPlan{}, fmt.Errorf("uup: required package %q has unsupported canonical payload %q", id, payload.Path)
					}
					plan.TotalSize += file.Size
				}
			}
			if !resolved {
				return EditionPlan{}, fmt.Errorf("uup: required package %q in CompDB %q has no resolved canonical payload", id, selected.database.Name)
			}
		}
	}
	sort.Slice(plan.References, func(i, j int) bool {
		return strings.ToLower(plan.References[i].Name) < strings.ToLower(plan.References[j].Name)
	})
	sort.Slice(plan.Cabinets, func(i, j int) bool {
		return strings.ToLower(plan.Cabinets[i].Name) < strings.ToLower(plan.Cabinets[j].Name)
	})
	sort.Slice(plan.Applications, func(i, j int) bool {
		return strings.ToLower(plan.Applications[i].Name) < strings.ToLower(plan.Applications[j].Name)
	})
	return plan, nil
}

func resolveFeatureClosure(root *Database, databases []*Database) ([]selectedFeature, error) {
	if len(databases) == 0 {
		return nil, fmt.Errorf("uup: CompDB catalog is empty")
	}
	index := make(map[string][]selectedFeature)
	for databaseIndex, database := range databases {
		if database == nil {
			return nil, fmt.Errorf("uup: CompDB catalog entry %d is nil", databaseIndex)
		}
		for featureIndex := range database.Features {
			feature := &database.Features[featureIndex]
			if feature.ID == "" {
				return nil, fmt.Errorf("uup: CompDB %q contains a feature without an ID", database.Name)
			}
			key := strings.ToLower(feature.ID)
			index[key] = append(index[key], selectedFeature{database: database, feature: feature})
		}
	}
	state := make(map[string]uint8)
	var result []selectedFeature
	var visit func(selectedFeature) error
	visit = func(selected selectedFeature) error {
		key := strings.ToLower(selected.database.Name) + "\x00" + featureIdentityKey(FeatureRef{ID: selected.feature.ID, ManifestID: selected.feature.ManifestID, Group: selected.feature.Group, Type: selected.feature.Type})
		switch state[key] {
		case 1:
			return fmt.Errorf("uup: feature dependency cycle at %q", selected.feature.ID)
		case 2:
			return nil
		}
		state[key] = 1
		for _, dependency := range selected.feature.Dependencies {
			required, err := mediaDependencyRequired(dependency.Type)
			if err != nil {
				return fmt.Errorf("uup: feature %q in CompDB %q dependency %s: %w", selected.feature.ID, selected.database.Name, featureReferenceString(dependency), err)
			}
			if !required {
				continue
			}
			var candidates []selectedFeature
			sameID := index[strings.ToLower(dependency.ID)]
			for _, candidate := range sameID {
				if featureReferenceMatches(dependency, candidate.feature) {
					candidates = append(candidates, candidate)
				}
			}
			if len(candidates) == 0 {
				available := make([]string, 0, len(sameID))
				for _, candidate := range sameID {
					available = append(available, candidate.database.Name+":"+featureReferenceString(FeatureRef{ID: candidate.feature.ID, ManifestID: candidate.feature.ManifestID, Group: candidate.feature.Group, Type: candidate.feature.Type}))
				}
				sort.Strings(available)
				if len(available) == 0 {
					available = append(available, "none")
				}
				return fmt.Errorf("uup: feature %q in CompDB %q has unresolved dependency %s; same-ID definitions: %s", selected.feature.ID, selected.database.Name, featureReferenceString(dependency), strings.Join(available, ", "))
			}
			if len(candidates) != 1 {
				names := make([]string, 0, len(candidates))
				for _, candidate := range candidates {
					names = append(names, candidate.database.Name+":"+featureReferenceString(FeatureRef{ID: candidate.feature.ID, ManifestID: candidate.feature.ManifestID, Group: candidate.feature.Group, Type: candidate.feature.Type}))
				}
				sort.Strings(names)
				return fmt.Errorf("uup: feature %q in CompDB %q dependency %s is ambiguous across %s", selected.feature.ID, selected.database.Name, featureReferenceString(dependency), strings.Join(names, ", "))
			}
			if err := visit(candidates[0]); err != nil {
				return err
			}
		}
		state[key] = 2
		result = append(result, selected)
		return nil
	}
	for featureIndex := range root.Features {
		if err := visit(selectedFeature{database: root, feature: &root.Features[featureIndex]}); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func featureIdentityKey(feature FeatureRef) string {
	return strings.ToLower(strings.Join([]string{feature.ID, feature.ManifestID, feature.Group, feature.Type}, "\x00"))
}

func featureReferenceMatches(reference FeatureRef, feature *Feature) bool {
	return feature != nil && strings.EqualFold(reference.ID, feature.ID) &&
		(reference.ManifestID == "" || strings.EqualFold(reference.ManifestID, feature.ManifestID)) &&
		(reference.Group == "" || strings.EqualFold(reference.Group, feature.Group))
}

func mediaDependencyRequired(dependencyType string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(dependencyType)) {
	case "", "required", "mediacreationrequired":
		return true, nil
	case "optional":
		return false, nil
	default:
		return false, fmt.Errorf("unknown dependency type %q", dependencyType)
	}
}

func featureReferenceString(reference FeatureRef) string {
	parts := []string{fmt.Sprintf("%q", reference.ID)}
	if reference.ManifestID != "" {
		parts = append(parts, "FMID="+reference.ManifestID)
	}
	if reference.Group != "" {
		parts = append(parts, "Group="+reference.Group)
	}
	if reference.Type != "" {
		parts = append(parts, "Type="+reference.Type)
	}
	return strings.Join(parts, " ")
}

func uniquePayloadFile(files []windowsupdate.File) (windowsupdate.File, bool, error) {
	if len(files) == 0 {
		return windowsupdate.File{}, false, nil
	}
	identities := make(map[string]windowsupdate.File)
	var keys []string
	for _, file := range files[1:] {
		key := strings.ToLower(file.DigestSHA256) + "\x00" + strconv.FormatInt(file.Size, 10) + "\x00" + strings.ToLower(file.Name)
		if _, exists := identities[key]; !exists {
			identities[key] = file
			keys = append(keys, key)
		}
	}
	first := files[0]
	firstKey := strings.ToLower(first.DigestSHA256) + "\x00" + strconv.FormatInt(first.Size, 10) + "\x00" + strings.ToLower(first.Name)
	if _, exists := identities[firstKey]; !exists {
		identities[firstKey] = first
		keys = append(keys, firstKey)
	}
	if len(identities) != 1 {
		sort.Strings(keys)
		return windowsupdate.File{}, false, fmt.Errorf("ambiguous across %d content identities", len(identities))
	}
	return identities[keys[0]], true, nil
}

func resolvePayload(payload PayloadItem, byName map[string][]windowsupdate.File) (windowsupdate.File, bool, error) {
	name := path.Base(strings.ReplaceAll(payload.Path, "\\", "/"))
	candidates := byName[strings.ToLower(name)]
	var wantedDigest string
	if payload.Hash != "" {
		decoded, err := base64.StdEncoding.DecodeString(payload.Hash)
		if err != nil || len(decoded) != 32 {
			return windowsupdate.File{}, false, fmt.Errorf("invalid SHA-256 payload hash")
		}
		wantedDigest = fmt.Sprintf("%x", decoded)
	}
	var matches []windowsupdate.File
	for _, file := range candidates {
		if payload.Size >= 0 && file.Size != payload.Size {
			continue
		}
		if wantedDigest != "" && !strings.EqualFold(file.DigestSHA256, wantedDigest) {
			continue
		}
		matches = append(matches, file)
	}
	return uniquePayloadFile(matches)
}
