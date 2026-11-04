package uup

import (
	"bytes"
	"fmt"
	"io"

	"github.com/tinyrange/trex/storage"
)

// ParsedAssemblyFile owns a decoded manifest snapshot and its parse. Consumers
// must treat Manifest's result as read-only. It has no global cache and never
// follows later changes to the source reader.
type ParsedAssemblyFile struct {
	data     []byte
	manifest *AssemblyManifest
	// A component index seals this binding only after full exact resolution.
	componentIndex    *ComponentMetadataIndex
	componentPath     string
	componentStem     string
	componentIdentity string
	packageIndex      *PackageMetadataIndex
	packageName       string
}

func (f *ParsedAssemblyFile) ReadAt(p []byte, off int64) (int, error) {
	return bytes.NewReader(f.data).ReadAt(p, off)
}
func (f *ParsedAssemblyFile) Size() int64                 { return int64(len(f.data)) }
func (f *ParsedAssemblyFile) Manifest() *AssemblyManifest { return f.manifest }

func parseAssemblyFile(file storage.Reader) (*ParsedAssemblyFile, error) {
	size := file.Size()
	if size < 0 || size > maximumAssemblyManifestSize {
		return nil, fmt.Errorf("assembly manifest size exceeds bound")
	}
	data := make([]byte, int(size))
	if _, err := io.ReadFull(io.NewSectionReader(file, 0, size), data); err != nil {
		return nil, err
	}
	manifest, err := ParseAssemblyManifestBytes(data)
	if err != nil {
		return nil, err
	}
	return &ParsedAssemblyFile{data: data, manifest: manifest}, nil
}

// openPlannedManifest shares only an owned snapshot, never a mutable archive
// reader. Changing the public path invalidates the captured path binding.
func openPlannedManifest(component PlannedComponent, open func(string) (storage.Reader, error), release func(string)) (*ParsedAssemblyFile, error) {
	if component.preparedManifest != nil && component.preparedPath == component.Path {
		return component.preparedManifest, nil
	}
	file, err := open(component.Path)
	if err != nil {
		return nil, err
	}
	if release != nil {
		defer release(component.Path)
	}
	return parseAssemblyFile(file)
}
