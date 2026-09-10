package uup

import (
	"crypto/sha256"
	"fmt"
	"io"
	"strings"

	"github.com/tinyrange/trex/archive/wim"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
)

type assemblyArchive interface {
	OpenFile(string) (starfile.File, error)
	List(string) ([]wim.EntryInfo, error)
}

// Only an inferred name may be disambiguated. Keep the architecture, spelling,
// language and relative file fixed. An abbreviated family can contain multiple
// identities and installed versions, so neither the inferred version nor its
// WinSxS identity suffix is authoritative. Every candidate must satisfy both
// the delta's length and SHA-256.
func resolveBaseAssemblyDescriptor(base assemblyArchive, imagePath string, descriptor ContentDescriptor) (storage.Reader, error) {
	name, err := baseAssemblyContentPath(imagePath, descriptor.Name)
	if err != nil {
		return nil, err
	}
	open := func(name string) (storage.Reader, error) {
		file, err := base.OpenFile(name)
		if err != nil {
			return nil, err
		}
		if file.Size() != descriptor.Length {
			return nil, fmt.Errorf("base-image basis %q has size %d, want %d", name, file.Size(), descriptor.Length)
		}
		hash := sha256.New()
		if _, err := io.Copy(hash, io.NewSectionReader(file, 0, file.Size())); err != nil {
			return nil, fmt.Errorf("hash base-image basis %q: %w", name, err)
		}
		if !equalHashBytes(descriptor.SHA256, hash.Sum(nil)) {
			return nil, fmt.Errorf("base-image basis %q has SHA-256 %x, want %x", name, hash.Sum(nil), descriptor.SHA256)
		}
		return file, nil
	}
	file, firstErr := open(name)
	if firstErr == nil || !descriptor.nameHint {
		return file, firstErr
	}
	clean := strings.TrimPrefix(strings.ReplaceAll(descriptor.Name, "\\", "/"), "/")
	component, relative, ok := strings.Cut(clean, "/")
	identity, err := parseComponentStem(component)
	if !ok || err != nil || (!strings.Contains(identity.Identity.Name, "..") && !strings.Contains(identity.Identity.Language, "..")) {
		return nil, firstErr
	}
	root := imagePath + "/Windows/WinSxS"
	entries, err := base.List(root)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !entry.Directory || strings.EqualFold(entry.Name, component) {
			continue
		}
		candidate, err := parseComponentStem(entry.Name)
		if err != nil || candidate.FamilyKey() != identity.FamilyKey() {
			continue
		}
		if file, err := open(root + "/" + entry.Name + "/" + relative); err == nil {
			return file, nil
		}
	}
	return nil, firstErr
}
