package cab

import (
	"bytes"
	"fmt"
	"path"
	"strings"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
	"github.com/tinyrange/trex/storage"
	bytecache "github.com/tinyrange/trex/storage/cache"
)

func init() {
	auto.Register("cab", 10, func(prefix []byte, source storage.Reader, options auto.Options) (auto.View, error) {
		if !bytes.HasPrefix(prefix, []byte("MSCF")) {
			return nil, auto.ErrNoMatch
		}
		store := bytecache.New(min(bytecache.DefaultBytes, options.MaxExpandedBytes))
		value, err := OpenWithCache(source, true, store, 1)
		if err != nil {
			return nil, err
		}
		if err := validateContinuationNames(value); err != nil {
			return nil, err
		}
		if value.flags&3 != 0 {
			set, err := discoverSet(value, options, store)
			if err != nil {
				return nil, err
			}
			return adapter.Parsed(set, options)
		}
		return adapter.Parsed(value, options)
	})
}

func validateContinuationNames(archive *Archive) error {
	if archive.flags&1 != 0 && archive.previous == "" || archive.flags&2 != 0 && archive.next == "" {
		return fmt.Errorf("cab: empty companion cabinet name")
	}
	for _, file := range archive.files {
		if (file.folder == cabFolderContinuedFromPrevious || file.folder == cabFolderContinuedBoth) && archive.flags&1 == 0 {
			return fmt.Errorf("cab: file %q continues a missing previous cabinet", file.name)
		}
		if (file.folder == cabFolderContinuedToNext || file.folder == cabFolderContinuedBoth) && archive.flags&2 == 0 {
			return fmt.Errorf("cab: file %q continues a missing next cabinet", file.name)
		}
	}
	return nil
}

// cabinetPath interprets Windows separators in a cabinet's declared neighbor
// name, while retaining the explicitly supplied portable source-tree boundary.
func cabinetPath(current, name string) (string, error) {
	valid := func(value string) bool {
		if value == "" || strings.ContainsAny(value, ":\x00") {
			return false
		}
		for _, part := range strings.Split(value, "/") {
			if part == "" || part == "." || part == ".." {
				return false
			}
		}
		return true
	}
	name = strings.ReplaceAll(name, "\\", "/")
	if strings.Contains(current, "\\") || !valid(current) || !valid(name) {
		return "", fmt.Errorf("cab: invalid companion path %q from %q", name, current)
	}
	return path.Join(path.Dir(current), name), nil
}

func discoverSet(initial *Archive, options auto.Options, store *bytecache.Cache) (*Set, error) {
	context := options.Source
	if context == nil || context.Tree == nil {
		return nil, fmt.Errorf("cab: cabinet set requires a companion source tree")
	}
	if _, err := cabinetPath(context.Path, path.Base(context.Path)); err != nil {
		return nil, err
	}
	seen := map[string]bool{strings.ToLower(context.Path): true}
	totalEntries := len(initial.files)
	totalFolders := len(initial.folders)
	if totalEntries > options.MaxEntries || totalFolders > options.MaxEntries {
		return nil, auto.ErrLimit
	}
	load := func(current *Archive, currentPath, name string, direction int) (*Archive, string, error) {
		name, err := cabinetPath(currentPath, name)
		if err != nil {
			return nil, "", err
		}
		key := strings.ToLower(name)
		if seen[key] {
			return nil, "", fmt.Errorf("cab: companion cycle at %q", name)
		}
		if len(seen) >= min(options.MaxEntries, 65536) {
			return nil, "", auto.ErrLimit
		}
		entry, err := context.Lookup(name, options)
		if err != nil {
			return nil, "", fmt.Errorf("cab: companion %q: %w", name, err)
		}
		if entry.Kind != "file" || entry.Reader == nil {
			return nil, "", fmt.Errorf("cab: companion %q is not a regular file", name)
		}
		archive, err := OpenWithCache(entry.Reader, false, store, uint64(len(seen)+1))
		if err != nil {
			return nil, "", fmt.Errorf("cab: companion %q: %w", name, err)
		}
		if archive.setID != initial.setID {
			return nil, "", fmt.Errorf("cab: companion %q has set ID %d, want %d", name, archive.setID, initial.setID)
		}
		want := int(current.cabinet) + direction
		if want < 0 || want > 65535 || int(archive.cabinet) != want {
			return nil, "", fmt.Errorf("cab: companion %q has sequence %d, want %d", name, archive.cabinet, want)
		}
		if err := validateContinuationNames(archive); err != nil {
			return nil, "", fmt.Errorf("cab: companion %q: %w", name, err)
		}
		back := archive.previous
		if direction < 0 {
			back = archive.next
		}
		backPath, err := cabinetPath(name, back)
		if err != nil || !strings.EqualFold(backPath, currentPath) {
			return nil, "", fmt.Errorf("cab: companion %q does not link back to %q", name, currentPath)
		}
		totalEntries += len(archive.files)
		totalFolders += len(archive.folders)
		if totalEntries > options.MaxEntries || totalFolders > options.MaxEntries {
			return nil, "", auto.ErrLimit
		}
		seen[key] = true
		return archive, name, nil
	}
	var before, after []*Archive
	for _, direction := range []int{-1, 1} {
		current, currentPath := initial, context.Path
		for {
			name := current.next
			if direction < 0 {
				name = current.previous
			}
			if name == "" {
				break
			}
			var err error
			current, currentPath, err = load(current, currentPath, name, direction)
			if err != nil {
				return nil, err
			}
			if direction < 0 {
				before = append(before, current)
			} else {
				after = append(after, current)
			}
		}
	}
	archives := make([]*Archive, 0, len(seen))
	for index := len(before) - 1; index >= 0; index-- {
		archives = append(archives, before[index])
	}
	archives = append(archives, initial)
	archives = append(archives, after...)
	if archives[0].cabinet != 0 {
		return nil, fmt.Errorf("cab: cabinet set starts at sequence %d, want 0", archives[0].cabinet)
	}
	return OpenSetWithCache(archives, true, store, uint64(len(seen)+1))
}
