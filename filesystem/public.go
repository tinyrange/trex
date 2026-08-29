package filesystem

import starfile "github.com/tinyrange/trex/storage/star"

// ArchiveEntry is a flattened filesystem entry suitable for indexing and web
// frontends. File is nil for directories.
type ArchiveEntry struct {
	Name      string
	Size      int64
	Directory bool
	File      starfile.File
}

// ExtentSpec describes an allocated range in a generated sparse image. An
// extent may be backed by Data, by File at Offset, or by implicit zeroes.
type ExtentSpec struct {
	Start, Size, Offset int64
	Data                []byte
	File                starfile.File
}

// NewGeneratedImage returns a read-only sparse file composed from specs.
func NewGeneratedImage(name string, size int64, specs []ExtentSpec) starfile.File {
	extents := make([]imageExtent, len(specs))
	for index, spec := range specs {
		extents[index] = imageExtent{start: spec.Start, size: spec.Size, off: spec.Offset, data: spec.Data, file: spec.File}
	}
	return &generatedImageFile{name: name, size: size, extents: extents}
}
