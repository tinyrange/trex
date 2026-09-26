package iso9660

import (
	"fmt"
	"maps"
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
	active := make(map[uint32]bool)
	var walk func(isoDirRecord, string) error
	walk = func(record isoDirRecord, base string) error {
		if active[record.extent] || len(active) >= 256 {
			return fmt.Errorf("iso: cyclic or excessively deep directory tree")
		}
		active[record.extent] = true
		defer delete(active, record.extent)
		children, err := image.readDir(record)
		if err != nil {
			return err
		}
		for _, child := range children {
			name := path.Join(base, strings.TrimPrefix(child.name, "/"))
			entry := filesystemapi.ArchiveEntry{Name: name, Kind: child.kind(), Directory: child.isDir()}
			if child.rr != nil {
				entry.Attributes = maps.Clone(child.rr.attributes)
				entry.Link = child.rr.link
			}
			if child.isDir() {
				entries = append(entries, entry)
				if err := walk(child, name); err != nil {
					return err
				}
				continue
			}
			file := &isoFile{image: image, record: child, name: name}
			entry.Size = file.Size()
			if child.kind() == "file" {
				entry.File = file
			}
			entries = append(entries, entry)
		}
		return nil
	}
	return entries, walk(image.root, "/")
}
