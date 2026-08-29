package udf

import (
	filesystemapi "github.com/tinyrange/trex/filesystem"
	starfile "github.com/tinyrange/trex/storage/star"
)

// Entries parses file and metadata entries from a UDF volume.
func Entries(file starfile.File) ([]filesystemapi.ArchiveEntry, error) {
	image, err := newUDFImage(file)
	if err != nil {
		return nil, err
	}
	entries := []filesystemapi.ArchiveEntry{{Name: "/$metadata", Directory: true}}
	for _, entry := range image.virtualEntries() {
		entries = append(entries, filesystemapi.ArchiveEntry{Name: entry.name, Size: entry.size, File: &udfRegionFile{image: image, name: entry.name, offset: entry.offset, size: entry.size}})
	}
	var walk func(udfFileEntry) error
	walk = func(dir udfFileEntry) error {
		children, err := image.readDir(dir)
		if err != nil {
			return err
		}
		for _, child := range children {
			if child.isDir() {
				entries = append(entries, filesystemapi.ArchiveEntry{Name: child.path, Directory: true})
				if err := walk(child); err != nil {
					return err
				}
				continue
			}
			child := child
			entries = append(entries, filesystemapi.ArchiveEntry{Name: child.path, Size: child.size, File: &udfFile{image: image, entry: child}})
		}
		return nil
	}
	return entries, walk(image.root)
}
