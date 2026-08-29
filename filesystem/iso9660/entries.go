package iso9660

import (
	"path"
	"strings"

	filesystemapi "github.com/tinyrange/trex/filesystem"
	starfile "github.com/tinyrange/trex/storage/star"
)

// Entries parses file and metadata entries from an ISO 9660 volume.
func Entries(file starfile.File) ([]filesystemapi.ArchiveEntry, error) {
	image, err := newISOImage(file)
	if err != nil {
		return nil, err
	}
	var entries []filesystemapi.ArchiveEntry
	if len(image.virtualEntries()) != 0 {
		entries = append(entries, filesystemapi.ArchiveEntry{Name: "/$metadata", Directory: true})
	}
	for _, entry := range image.virtualEntries() {
		entries = append(entries, filesystemapi.ArchiveEntry{Name: entry.name, Size: entry.size, File: &isoRegionFile{image: image, name: entry.name, offset: entry.offset, size: entry.size}})
	}
	var walk func(isoDirRecord, string) error
	walk = func(record isoDirRecord, base string) error {
		children, err := image.readDir(record)
		if err != nil {
			return err
		}
		for _, child := range children {
			name := path.Join(base, strings.TrimPrefix(child.name, "/"))
			if child.isDir() {
				entries = append(entries, filesystemapi.ArchiveEntry{Name: name, Directory: true})
				if err := walk(child, name); err != nil {
					return err
				}
				continue
			}
			entries = append(entries, filesystemapi.ArchiveEntry{Name: name, Size: int64(child.size), File: &isoFile{image: image, record: child, name: name}})
		}
		return nil
	}
	return entries, walk(image.root, "/")
}
