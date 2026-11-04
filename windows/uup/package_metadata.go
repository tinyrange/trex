package uup

import (
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/tinyrange/trex/storage"
)

// PackageMetadataEntry identifies available package metadata, not an admitted
// package or a selected payload. Aggregate is the transport's update.mum root.
type PackageMetadataEntry struct {
	Package   string
	Path      string
	Aggregate bool
}

// PackageMetadataIndex keeps the metadata namespace separate from preliminary
// payload selection and from logical CIX targets. In particular, contained=false
// and currently inapplicable packages must remain resolvable here. Availability
// is not permission to install: CBS admission is a separate operation.
type PackageMetadataIndex struct {
	entries  []PackageMetadataEntry
	byName   map[string]PackageMetadataEntry
	catalogs map[string]string
	open     func(string) (storage.Reader, error)
	release  func(string)
}

// NewPackageMetadataIndex indexes raw and express MUMs without evaluating parent
// applicability or loading every manifest. Construct after the stage's content
// resolvers have been bound; those resolvers are also used for express MUMs.
func NewPackageMetadataIndex(stage *CumulativeStage) (*PackageMetadataIndex, error) {
	if stage == nil {
		return nil, fmt.Errorf("package metadata requires a stage")
	}
	entries, err := stage.assemblyEntries()
	if err != nil {
		return nil, err
	}
	return newPackageMetadataIndex(entries, stage.openAssemblyFile, stage.releaseAssemblyFile)
}

func newPackageMetadataIndex(entries []stageMetadataEntry, open func(string) (storage.Reader, error), release func(string)) (*PackageMetadataIndex, error) {
	result := &PackageMetadataIndex{byName: map[string]PackageMetadataEntry{}, catalogs: map[string]string{}, open: open, release: release}
	for _, entry := range entries {
		if !strings.EqualFold(path.Ext(entry.Name), ".cat") {
			continue
		}
		key := assemblyEntryKey(entry.Path)
		if previous, exists := result.catalogs[key]; exists && previous != entry.Path {
			return nil, fmt.Errorf("ambiguous catalog metadata %q and %q", previous, entry.Path)
		}
		if len(result.catalogs) >= 1<<20 {
			return nil, fmt.Errorf("catalog metadata index exceeds bound")
		}
		result.catalogs[key] = entry.Path
	}
	for _, entry := range entries {
		if !strings.EqualFold(path.Ext(entry.Name), ".mum") {
			continue
		}
		if len(result.entries) >= 1<<20 {
			return nil, fmt.Errorf("package metadata index exceeds bound")
		}
		aggregate := strings.EqualFold(entry.Name, "update.mum")
		id, err := ParsePackageManifestName(entry.Name)
		if aggregate {
			manifest, _, readErr := result.readManifest(entry.Path)
			if readErr != nil {
				return nil, readErr
			}
			id, err = manifest.Identity, nil
		}
		if err != nil {
			return nil, fmt.Errorf("package metadata %q: %w", entry.Path, err)
		}
		name, err := cbsPackageName(id)
		if err != nil {
			return nil, err
		}
		key := strings.ToLower(name)
		if previous, exists := result.byName[key]; exists {
			if previous.Path == entry.Path && previous.Aggregate == aggregate {
				continue
			}
			return nil, fmt.Errorf("ambiguous package metadata %q in %q and %q", name, previous.Path, entry.Path)
		}
		value := PackageMetadataEntry{Package: name, Path: entry.Path, Aggregate: aggregate}
		result.byName[key] = value
		result.entries = append(result.entries, value)
	}
	slices.SortFunc(result.entries, func(a, b PackageMetadataEntry) int {
		return strings.Compare(strings.ToLower(a.Package), strings.ToLower(b.Package))
	})
	return result, nil
}

// Entries returns deterministic metadata inventory, including packages excluded
// by preliminary parent/payload selection. The returned slice is independent.
func (index *PackageMetadataIndex) Entries() []PackageMetadataEntry {
	return slices.Clone(index.entries)
}

func (index *PackageMetadataIndex) readManifest(name string) (*AssemblyManifest, storage.Reader, error) {
	file, err := index.open(name)
	if err != nil {
		return nil, nil, err
	}
	if index.release != nil {
		defer index.release(name)
	}
	if file.Size() < 0 || file.Size() > maximumAssemblyManifestSize {
		return nil, nil, fmt.Errorf("package metadata %q exceeds manifest size bound", name)
	}
	parsed, err := parseAssemblyFile(file)
	if err != nil {
		return nil, nil, fmt.Errorf("package metadata %q: %w", name, err)
	}
	manifest := parsed.Manifest()
	if manifest.Package == nil {
		return nil, nil, fmt.Errorf("package metadata %q has no package declaration", name)
	}
	return manifest, parsed, nil
}

// Open resolves an exact canonical package name, never a basename fallback or
// an arbitrary transport path. It verifies the manifest identity before exposing
// its bytes. Missing metadata and malformed metadata are both errors; callers
// can use Entries to distinguish absence before attempting a read.
func (index *PackageMetadataIndex) Open(name string) (storage.Reader, error) {
	entry, ok := index.byName[strings.ToLower(name)]
	if !ok {
		return nil, fmt.Errorf("package metadata %q is unavailable", name)
	}
	manifest, file, err := index.readManifest(entry.Path)
	if err != nil {
		return nil, err
	}
	actual, err := cbsPackageName(manifest.Identity)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(actual, entry.Package) {
		return nil, fmt.Errorf("package metadata %q declares identity %q", entry.Package, actual)
	}
	snapshot := file.(*ParsedAssemblyFile)
	snapshot.packageIndex = index
	snapshot.packageName = strings.ToLower(entry.Package)
	return snapshot, nil
}

// OpenCatalog resolves only the exact companion of an identity-validated MUM.
// This exposes catalog bytes, not membership, signature integrity or trust.
func (index *PackageMetadataIndex) OpenCatalog(name string) (storage.Reader, error) {
	return index.OpenCatalogWithManifest(name, nil)
}

// OpenCatalogWithManifest may reuse only a snapshot resolved by this index for
// the same exact package. This is identity binding, not catalog trust proof.
func (index *PackageMetadataIndex) OpenCatalogWithManifest(name string, manifest *ParsedAssemblyFile) (storage.Reader, error) {
	if manifest == nil {
		if _, err := index.Open(name); err != nil {
			return nil, err
		}
	} else if manifest.packageIndex != index || manifest.packageName != strings.ToLower(name) {
		return nil, fmt.Errorf("package catalog manifest snapshot identity/index mismatch")
	}
	entry := index.byName[strings.ToLower(name)]
	companion := strings.TrimSuffix(entry.Path, path.Ext(entry.Path)) + ".cat"
	catalog, ok := index.catalogs[assemblyEntryKey(companion)]
	if !ok {
		return nil, fmt.Errorf("package catalog %q is unavailable", name)
	}
	file, err := index.open(catalog)
	if index.release != nil {
		index.release(catalog)
	}
	if err != nil {
		return nil, err
	}
	if file.Size() < 0 || file.Size() > 64<<20 {
		return nil, fmt.Errorf("package catalog %q exceeds 64 MiB", name)
	}
	return file, nil
}
