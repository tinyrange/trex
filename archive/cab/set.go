package cab

import (
	"bytes"
	"fmt"
	"io"
	"path"
	"strings"
	"sync"

	"github.com/tinyrange/trex/compression/lzx"
	bytecache "github.com/tinyrange/trex/storage/cache"
	starfile "github.com/tinyrange/trex/storage/star"

	"go.starlark.net/starlark"
)

const (
	cabFolderContinuedFromPrevious = uint16(0xfffd)
	cabFolderContinuedToNext       = uint16(0xfffe)
	cabFolderContinuedBoth         = uint16(0xffff)
)

type cabSetFolderFragment struct {
	archive *Archive
	folder  folder
}

type cabSetFolder struct {
	compression uint16
	fragments   []cabSetFolderFragment
}

type cabSetFile struct {
	name              string
	size              uint32
	folder            int
	uncompressedStart uint32
}

type Set struct {
	files       []cabSetFile
	fileIndex   map[string]int
	folders     []cabSetFolder
	cache       bool
	cacheStore  *bytecache.Cache
	cacheSource uint64
}

func SetBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	cache := true
	if err := starlark.UnpackArgs("cab_set", args, kwargs, "files", &value, "cache?", &cache); err != nil {
		return nil, err
	}
	iterable, ok := value.(starlark.Iterable)
	if !ok {
		return nil, fmt.Errorf("cab_set: files must be iterable")
	}
	store := bytecache.New(bytecache.DefaultBytes)
	iterator := iterable.Iterate()
	defer iterator.Done()
	archives := make([]*Archive, 0)
	var item starlark.Value
	for iterator.Next(&item) {
		file, ok := item.(starfile.File)
		if !ok {
			return nil, fmt.Errorf("cab_set: item %d is %s, want file", len(archives), item.Type())
		}
		archive, err := OpenWithCache(file, false, store, uint64(len(archives)+1))
		if err != nil {
			return nil, fmt.Errorf("cab_set: cabinet %d: %w", len(archives), err)
		}
		archives = append(archives, archive)
	}
	if len(archives) == 0 {
		return nil, fmt.Errorf("cab_set: files must not be empty")
	}
	return OpenSetWithCache(archives, cache, store, uint64(len(archives)+1))
}

func OpenSetWithCache(archives []*Archive, cache bool, store *bytecache.Cache, source uint64) (*Set, error) {
	setID := archives[0].setID
	firstCabinet := archives[0].cabinet
	for index, archive := range archives {
		if archive.setID != setID {
			return nil, fmt.Errorf("cab_set: cabinet %d has set ID %d, want %d", index, archive.setID, setID)
		}
		if archive.cabinet != firstCabinet+uint16(index) {
			return nil, fmt.Errorf("cab_set: cabinet %d has sequence %d, want %d", index, archive.cabinet, firstCabinet+uint16(index))
		}
	}

	result := &Set{
		fileIndex: make(map[string]int), cache: cache, cacheStore: store, cacheSource: source,
	}
	previousLastFolder := -1
	for cabinetIndex, archive := range archives {
		if len(archive.folders) == 0 {
			if len(archive.files) != 0 {
				return nil, fmt.Errorf("cab_set: cabinet %d has files but no folders", cabinetIndex)
			}
			continue
		}
		continuesPrevious := false
		for _, file := range archive.files {
			if file.folder == cabFolderContinuedFromPrevious || file.folder == cabFolderContinuedBoth {
				continuesPrevious = true
				break
			}
		}
		localFolders := make([]int, len(archive.folders))
		for localIndex, folder := range archive.folders {
			globalIndex := -1
			if localIndex == 0 && continuesPrevious {
				if previousLastFolder < 0 {
					return nil, fmt.Errorf("cab_set: cabinet %d continues a missing previous folder", cabinetIndex)
				}
				globalIndex = previousLastFolder
				if result.folders[globalIndex].compression != folder.compression {
					return nil, fmt.Errorf("cab_set: cabinet %d changes compression in a continued folder", cabinetIndex)
				}
			} else {
				globalIndex = len(result.folders)
				result.folders = append(result.folders, cabSetFolder{compression: folder.compression})
			}
			result.folders[globalIndex].fragments = append(result.folders[globalIndex].fragments, cabSetFolderFragment{archive: archive, folder: folder})
			localFolders[localIndex] = globalIndex
		}
		previousLastFolder = localFolders[len(localFolders)-1]

		for _, file := range archive.files {
			localFolder := int(file.folder)
			switch file.folder {
			case cabFolderContinuedFromPrevious:
				localFolder = 0
			case cabFolderContinuedToNext:
				localFolder = len(localFolders) - 1
			case cabFolderContinuedBoth:
				if len(localFolders) != 1 {
					return nil, fmt.Errorf("cab_set: cabinet %d has a through-continuation with %d folders", cabinetIndex, len(localFolders))
				}
				localFolder = 0
			}
			if localFolder < 0 || localFolder >= len(localFolders) {
				return nil, fmt.Errorf("cab_set: cabinet %d file %q has invalid folder %d", cabinetIndex, file.name, file.folder)
			}
			member := cabSetFile{name: file.name, size: file.size, folder: localFolders[localFolder], uncompressedStart: file.uncompressedStart}
			key := strings.ToLower(normalizeCABPath(file.name))
			if _, exists := result.fileIndex[key]; exists {
				// A FROM_PREV record is the redundant tail catalogue for a file
				// whose logical entry was already published by an earlier cabinet.
				// Keep that first entry. Ordinary duplicate names are independent
				// extraction operations, however, and FDI exposes them in cabinet
				// order; the later extraction overwrites the earlier destination.
				// Append it below and update the lookup index to the last occurrence.
				if file.folder == cabFolderContinuedFromPrevious || file.folder == cabFolderContinuedBoth {
					continue
				}
			}
			result.fileIndex[key] = len(result.files)
			result.fileIndex[strings.ToLower(strings.TrimPrefix(key, "/"))] = len(result.files)
			result.files = append(result.files, member)
		}
	}
	return result, nil
}

func (c *Set) String() string       { return "<cab.set>" }
func (c *Set) Type() string         { return "cab" }
func (c *Set) Freeze()              {}
func (c *Set) Truth() starlark.Bool { return starlark.True }
func (c *Set) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", c.Type())
}
func (c *Set) Get(key starlark.Value) (starlark.Value, bool, error) {
	name, ok := starlark.AsString(key)
	if !ok {
		return nil, false, nil
	}
	cleaned := path.Clean("/" + strings.TrimPrefix(name, "/"))
	if cleaned == "/" {
		return c.list(), true, nil
	}
	file, err := c.lookup(cleaned)
	if err != nil {
		return nil, false, err
	}
	return file, true, nil
}
func (c *Set) Attr(name string) (starlark.Value, error) {
	switch name {
	case "files":
		return c.list(), nil
	case "find":
		return starlark.NewBuiltin("find", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var name string
			if err := starlark.UnpackArgs("find", args, kwargs, "path", &name); err != nil {
				return nil, err
			}
			value, err := c.lookup(name)
			if err != nil {
				return starlark.None, nil
			}
			return value, nil
		}), nil
	}
	return nil, nil
}
func (c *Set) AttrNames() []string { return []string{"files", "find"} }
func (c *Set) list() *starlark.List {
	values := make([]starlark.Value, len(c.files))
	for index, file := range c.files {
		values[index] = starlark.String(file.name)
	}
	return starlark.NewList(values)
}
func (c *Set) lookup(name string) (starlark.Value, error) {
	cleaned := normalizeCABPath(name)
	index, ok := c.fileIndex[strings.ToLower(cleaned)]
	if !ok {
		index, ok = c.fileIndex[strings.ToLower(strings.TrimPrefix(cleaned, "/"))]
	}
	if !ok {
		return nil, fmt.Errorf("cab_set: path %q not found", name)
	}
	return &SetEntry{archive: c, file: c.files[index]}, nil
}

func (c *Set) folderData(index int) ([]byte, error) {
	if !c.cache {
		return c.readFolderData(index)
	}
	return c.cacheStore.Get(bytecache.Key{Source: c.cacheSource, Kind: 2, Index: index}, func() ([]byte, error) {
		return c.readFolderData(index)
	})
}

func (c *Set) readFolderData(index int) ([]byte, error) {
	folder := c.folders[index]
	blocks := make([]dataBlock, 0)
	for _, fragment := range folder.fragments {
		fragmentBlocks, err := fragment.archive.readFolderDataBlocks(fragment.folder)
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, fragmentBlocks...)
	}
	switch folder.compression & 0x000f {
	case 0:
		return decodeCABBlocks(blocks, false)
	case 1:
		return decodeCABBlocks(blocks, true)
	case 2:
		return quantumDecompressCAB(blocks, int(folder.compression>>8)&0x1f)
	case 3:
		payload, expected := cabinetBlocksPayload(blocks)
		return lzx.Decompress(payload, int(folder.compression>>8), expected)
	default:
		return nil, fmt.Errorf("cab_set: unsupported compression type 0x%x", folder.compression)
	}
}

type SetEntry struct {
	archive      *Set
	file         cabSetFile
	uncachedOnce sync.Once
	uncachedData []byte
	uncachedErr  error
}

func (f *SetEntry) data() ([]byte, error) {
	read := func() ([]byte, error) {
		folder, err := f.archive.folderData(f.file.folder)
		if err != nil {
			return nil, err
		}
		start := int(f.file.uncompressedStart)
		end := start + int(f.file.size)
		if start < 0 || end < start || end > len(folder) {
			return nil, fmt.Errorf("cab_set: file %q extends past folder data", f.file.name)
		}
		return folder[start:end], nil
	}
	if f.archive.cache {
		return read()
	}
	f.uncachedOnce.Do(func() {
		data, err := read()
		if err == nil {
			data = bytes.Clone(data)
		}
		f.uncachedData, f.uncachedErr = data, err
	})
	return f.uncachedData, f.uncachedErr
}
func (f *SetEntry) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset")
	}
	if off >= f.Size() {
		return 0, io.EOF
	}
	data, err := f.data()
	if err != nil {
		return 0, fmt.Errorf("cab set entry %q: %w", f.file.name, err)
	}
	n := copy(p, data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
func (f *SetEntry) WriteAt(_ []byte, _ int64) (int, error) {
	return 0, fmt.Errorf("cab set entry %q is read-only", f.file.name)
}
func (f *SetEntry) Size() int64 { return int64(f.file.size) }
func (f *SetEntry) String() string {
	return fmt.Sprintf("<cab.set.file %q size=%d>", f.file.name, f.Size())
}
func (f *SetEntry) Type() string         { return "file" }
func (f *SetEntry) Freeze()              {}
func (f *SetEntry) Truth() starlark.Bool { return starlark.True }
func (f *SetEntry) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", f.Type())
}
func (f *SetEntry) Attr(name string) (starlark.Value, error) {
	return starfile.Attr(f, name), nil
}
func (f *SetEntry) AttrNames() []string { return starfile.AttrNames() }
