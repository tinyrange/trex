package wim

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf16"

	"github.com/tinyrange/trex/compression/lzms"
	"github.com/tinyrange/trex/compression/lzx"
	"github.com/tinyrange/trex/compression/xpress"
	virtualfs "github.com/tinyrange/trex/filesystem"
	"github.com/tinyrange/trex/storage"
	bytecache "github.com/tinyrange/trex/storage/cache"
	starfile "github.com/tinyrange/trex/storage/star"

	"go.starlark.net/starlark"
)

const (
	wimHeaderSize           = 208
	wimResourceMetadata     = 0x02
	wimResourceCompressed   = 0x04
	wimResourceSolid        = 0x10
	wimLookupEntrySize      = 50
	wimMetadataEntryBaseLen = 102
	wimSolidResourceMagic   = int64(0x100000000)
	wimFlagXPRESS           = 0x00020000
	wimFlagLZX              = 0x00040000
	wimFlagLZMS             = 0x00080000
)

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	referenceValue := starlark.Value(starlark.None)
	if err := starlark.UnpackArgs("wim", args, kwargs, "file", &value, "references?", &referenceValue); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("wim: got %s, want file", value.Type())
	}
	var references []storage.Reader
	if referenceValue != starlark.None {
		iterable, ok := referenceValue.(starlark.Iterable)
		if !ok {
			return nil, fmt.Errorf("wim: references got %s, want iterable", referenceValue.Type())
		}
		iterator := iterable.Iterate()
		defer iterator.Done()
		var item starlark.Value
		for iterator.Next(&item) {
			reference, ok := item.(starfile.File)
			if !ok {
				return nil, fmt.Errorf("wim: references[%d] got %s, want file", len(references), item.Type())
			}
			references = append(references, reference)
		}
	}
	return OpenWithReferences(file, references)
}

type Archive struct {
	file            storage.Reader
	flags           uint32
	chunkSize       int
	partNumber      uint16
	totalParts      uint16
	imageCount      int
	lookup          []wimLookupEntry
	byHash          map[string]wimResourceLocation
	locationsByHash map[string][]wimResourceLocation
	xml             wimResource
	boot            wimResource
	images          []image
	cacheStore      *bytecache.Cache
	cacheSource     uint64
}

type image struct {
	index    int
	resource wimResource
	metadata []byte
	security [][]byte
	root     entry
	dirs     map[string][]entry
	byPath   map[string]entry
}

type wimResource struct {
	size         int64
	flags        byte
	offset       int64
	originalSize int64
	chunkSize    int
	compression  uint32
}

type wimResourceLocation struct {
	archive    *Archive
	external   storage.Reader
	resource   wimResource
	blobOffset int64
	blobSize   int64
	lookupPart uint16
	refCount   uint32
}

type wimLookupEntry struct {
	resource wimResource
	part     uint16
	refCount uint32
	hash     [20]byte
}

type entry struct {
	name           string
	path           string
	shortName      string
	size           int64
	attrs          uint32
	securityID     uint32
	creationTime   uint64
	lastAccessTime uint64
	lastWriteTime  uint64
	reparseTag     uint32
	hardLink       uint64
	streamCount    uint16
	hash           [20]byte
	isDir          bool
	subdirOff      uint64
}

// EntryInfo describes one image path without exposing WIM metadata internals.
type EntryInfo struct {
	Name           string
	Path           string
	Size           int64
	Directory      bool
	Attributes     uint32
	HardLinkID     uint64
	SHA1           [20]byte
	CreationTime   uint64
	LastAccessTime uint64
	LastWriteTime  uint64
}

// FileReadOrder identifies the physical resource and logical blob position
// used to read a file. It is intended only for locality-preserving ordering;
// callers must not interpret it as a persistent file identity.
type FileReadOrder struct {
	Source         uint64
	ResourceOffset int64
	BlobOffset     int64
}

// ReadOrder returns a locality key for one image file without reading its
// content.
func (w *Archive) ReadOrder(name string) (FileReadOrder, error) {
	entry, err := w.lookupPath(name)
	if err != nil {
		return FileReadOrder{}, err
	}
	if entry.isDir {
		return FileReadOrder{}, fmt.Errorf("wim: path %q is a directory", name)
	}
	location, ok := w.byHash[string(entry.hash[:])]
	if !ok || location.external != nil || location.archive == nil {
		return FileReadOrder{}, fmt.Errorf("wim: path %q has no ordered WIM resource", name)
	}
	return FileReadOrder{Source: location.archive.cacheSource, ResourceOffset: location.resource.offset, BlobOffset: location.blobOffset}, nil
}

// NamedFile is a synthetic metadata file exposed by a WIM container.
type NamedFile struct {
	Name string
	File starfile.File
}

// ExternalResource is content from a non-WIM package, addressed by the same
// SHA-1 stored in WIM image metadata. UUP canonical cabinets use this form for
// files which participate in a composed image without being stored in a
// reference ESD.
type ExternalResource struct {
	SHA1 [20]byte
	File storage.Reader
}

func Open(file storage.Reader) (*Archive, error) {
	return OpenWithCache(file, bytecache.New(bytecache.DefaultBytes), 1)
}

// OpenWithReferences opens a metadata WIM/ESD and adds resource-only WIM/ESD
// containers to its content-addressed resource lookup. The inputs remain
// random-access readers and are never extracted or joined into a host file.
func OpenWithReferences(file storage.Reader, references []storage.Reader) (*Archive, error) {
	return OpenWithReferencesCache(file, references, bytecache.DefaultBytes)
}

// OpenWithReferencesCache opens a referenced WIM set with an explicit bounded
// in-memory decompressed-chunk cache. The cache is never persisted.
func OpenWithReferencesCache(file storage.Reader, references []storage.Reader, maximumCacheBytes int64) (*Archive, error) {
	if maximumCacheBytes < 0 {
		return nil, fmt.Errorf("wim: negative cache bound %d", maximumCacheBytes)
	}
	store := bytecache.New(maximumCacheBytes)
	archive, err := OpenWithCache(file, store, 1)
	if err != nil {
		return nil, err
	}
	if err := archive.addReferenceIndexes(store, references); err != nil {
		return nil, err
	}
	return archive, nil
}

// OpenResourceIndexWithReferences opens only the content-addressed resource
// indexes. It intentionally does not decode image metadata or payloads, making
// it suitable for format inspection and reference-set validation.
func OpenResourceIndexWithReferences(file storage.Reader, references []storage.Reader) (*Archive, error) {
	store := bytecache.New(bytecache.DefaultBytes)
	archive, err := openWithCache(file, store, 1, false)
	if err != nil {
		return nil, err
	}
	if err := archive.addReferenceIndexes(store, references); err != nil {
		return nil, err
	}
	return archive, nil
}

func (w *Archive) addReferenceIndexes(store *bytecache.Cache, references []storage.Reader) error {
	type result struct {
		archive *Archive
		err     error
	}
	results := make([]result, len(references))
	workers := min(len(references), 4)
	jobs := make(chan int, len(references))
	var group sync.WaitGroup
	group.Add(workers)
	for range workers {
		go func() {
			defer group.Done()
			for index := range jobs {
				reference, err := openWithCache(references[index], store, uint64(index+2), false)
				results[index] = result{archive: reference, err: err}
			}
		}()
	}
	for index := range references {
		jobs <- index
	}
	close(jobs)
	group.Wait()
	for index, result := range results {
		if result.err != nil {
			return fmt.Errorf("wim: reference %d: %w", index, result.err)
		}
		reference := result.archive
		for hash, locations := range reference.locationsByHash {
			for _, location := range locations {
				if location.blobSize == 0 {
					continue
				}
				w.byHash[hash] = location
				w.locationsByHash[hash] = append(w.locationsByHash[hash], location)
			}
		}
	}
	return nil
}

// MissingResourceHashes returns the distinct nonzero metadata hashes which
// are not currently backed by the metadata WIM or any reference WIM.
func (w *Archive) MissingResourceHashes() ([][20]byte, error) {
	missing := make(map[[20]byte]struct{})
	for imageIndex := range w.images {
		image := &w.images[imageIndex]
		pending := []entry{image.root}
		for len(pending) > 0 {
			current := pending[len(pending)-1]
			pending = pending[:len(pending)-1]
			children, err := w.readWIMDir(image, current)
			if err != nil {
				return nil, err
			}
			for _, child := range children {
				if child.isDir {
					pending = append(pending, child)
					continue
				}
				if child.hash == ([20]byte{}) {
					continue
				}
				if _, found := w.byHash[string(child.hash[:])]; !found {
					missing[child.hash] = struct{}{}
				}
			}
		}
	}
	result := make([][20]byte, 0, len(missing))
	for digest := range missing {
		result = append(result, digest)
	}
	sort.Slice(result, func(i, j int) bool {
		return bytes.Compare(result[i][:], result[j][:]) < 0
	})
	return result, nil
}

// AddExternalResources adds content-addressed files from canonical package
// containers and refreshes any metadata entries already visited by an
// inspection pass.
func (w *Archive) AddExternalResources(resources []ExternalResource) error {
	for index, resource := range resources {
		if resource.File == nil || resource.File.Size() < 0 {
			return fmt.Errorf("wim: external resource %d has no valid file", index)
		}
		location := wimResourceLocation{external: resource.File, blobSize: resource.File.Size()}
		key := string(resource.SHA1[:])
		w.byHash[key] = location
		w.locationsByHash[key] = append(w.locationsByHash[key], location)
	}
	for imageIndex := range w.images {
		image := &w.images[imageIndex]
		for directory, entries := range image.dirs {
			for index := range entries {
				if location, found := w.byHash[string(entries[index].hash[:])]; found {
					entries[index].size = location.blobSize
				}
			}
			image.dirs[directory] = entries
		}
		for name, entry := range image.byPath {
			if location, found := w.byHash[string(entry.hash[:])]; found {
				entry.size = location.blobSize
				image.byPath[name] = entry
			}
		}
	}
	return nil
}

func OpenWithCache(file storage.Reader, store *bytecache.Cache, source uint64) (*Archive, error) {
	return openWithCache(file, store, source, true)
}

func openWithCache(file storage.Reader, store *bytecache.Cache, source uint64, readImages bool) (*Archive, error) {
	header := make([]byte, wimHeaderSize)
	if _, err := file.ReadAt(header, 0); err != nil {
		return nil, err
	}
	if !bytes.Equal(header[0:8], []byte{'M', 'S', 'W', 'I', 'M', 0, 0, 0}) {
		return nil, fmt.Errorf("wim: invalid MSWIM signature")
	}
	headerSize := binary.LittleEndian.Uint32(header[8:12])
	if headerSize < wimHeaderSize {
		return nil, fmt.Errorf("wim: unsupported header size %d", headerSize)
	}
	w := &Archive{
		file:            file,
		flags:           binary.LittleEndian.Uint32(header[16:20]),
		chunkSize:       int(binary.LittleEndian.Uint32(header[20:24])),
		partNumber:      binary.LittleEndian.Uint16(header[40:42]),
		totalParts:      binary.LittleEndian.Uint16(header[42:44]),
		imageCount:      int(binary.LittleEndian.Uint32(header[44:48])),
		byHash:          make(map[string]wimResourceLocation),
		locationsByHash: make(map[string][]wimResourceLocation),
		xml:             parseWIMResource(header[72:96]),
		boot:            parseWIMResource(header[96:120]),
		cacheStore:      store, cacheSource: source,
	}
	compressionFlags := w.flags & (wimFlagXPRESS | wimFlagLZX | wimFlagLZMS)
	if w.chunkSize == 0 {
		if compressionFlags != 0 {
			return nil, fmt.Errorf("wim: compressed archive has zero chunk size")
		}
	} else if w.chunkSize&(w.chunkSize-1) != 0 {
		return nil, fmt.Errorf("wim: invalid chunk size %d", w.chunkSize)
	}
	lookupResource := parseWIMResource(header[48:72])
	lookupData, err := w.readResource(lookupResource)
	if err != nil {
		return nil, fmt.Errorf("lookup table: %w", err)
	}
	if len(lookupData)%wimLookupEntrySize != 0 {
		return nil, fmt.Errorf("wim: invalid lookup table size")
	}
	for off := 0; off+wimLookupEntrySize <= len(lookupData); off += wimLookupEntrySize {
		entry := wimLookupEntry{
			resource: parseWIMResource(lookupData[off : off+24]),
			part:     binary.LittleEndian.Uint16(lookupData[off+24 : off+26]),
			refCount: binary.LittleEndian.Uint32(lookupData[off+26 : off+30]),
		}
		copy(entry.hash[:], lookupData[off+30:off+50])
		w.lookup = append(w.lookup, entry)
	}
	if err := w.indexLookupResources(); err != nil {
		return nil, err
	}
	if readImages {
		if err := w.readImages(); err != nil {
			return nil, err
		}
	}
	return w, nil
}

func (w *Archive) indexLookupResources() error {
	for index := 0; index < len(w.lookup); {
		if w.lookup[index].resource.flags&wimResourceSolid == 0 {
			entry := w.lookup[index]
			w.byHash[string(entry.hash[:])] = wimResourceLocation{
				archive: w, resource: entry.resource, blobSize: entry.resource.originalSize,
				lookupPart: entry.part, refCount: entry.refCount,
			}
			w.locationsByHash[string(entry.hash[:])] = append(w.locationsByHash[string(entry.hash[:])], w.byHash[string(entry.hash[:])])
			index++
			continue
		}
		end := index + 1
		for end < len(w.lookup) && w.lookup[end].resource.flags&wimResourceSolid != 0 {
			end++
		}
		if err := w.indexSolidRun(w.lookup[index:end]); err != nil {
			return err
		}
		index = end
	}
	return nil
}

func (w *Archive) indexSolidRun(entries []wimLookupEntry) error {
	type solidResource struct {
		base     int64
		resource wimResource
	}
	var resources []solidResource
	var logicalSize int64
	for _, entry := range entries {
		if entry.resource.originalSize != wimSolidResourceMagic {
			continue
		}
		resource, err := w.loadSolidResource(entry.resource)
		if err != nil {
			return fmt.Errorf("wim: solid resource at %#x: %w", entry.resource.offset, err)
		}
		resources = append(resources, solidResource{base: logicalSize, resource: resource})
		logicalSize += resource.originalSize
	}
	if len(resources) == 0 {
		return fmt.Errorf("wim: solid lookup run has no resource descriptor")
	}
	for _, entry := range entries {
		if entry.resource.originalSize == wimSolidResourceMagic {
			continue
		}
		blobOffset := entry.resource.offset
		blobSize := entry.resource.size
		located := false
		for _, resource := range resources {
			if blobOffset >= resource.base && blobOffset+blobSize >= blobOffset && blobOffset+blobSize <= resource.base+resource.resource.originalSize {
				location := wimResourceLocation{
					archive: w, resource: resource.resource,
					blobOffset: blobOffset - resource.base, blobSize: blobSize,
					lookupPart: entry.part, refCount: entry.refCount,
				}
				w.byHash[string(entry.hash[:])] = location
				w.locationsByHash[string(entry.hash[:])] = append(w.locationsByHash[string(entry.hash[:])], location)
				located = true
				break
			}
		}
		if !located {
			return fmt.Errorf("wim: solid blob offset %#x size %#x exceeds resources", blobOffset, blobSize)
		}
	}
	return nil
}

func (w *Archive) loadSolidResource(resource wimResource) (wimResource, error) {
	if resource.size < 16 {
		return resource, fmt.Errorf("resource is smaller than its header")
	}
	header := make([]byte, 16)
	if _, err := w.file.ReadAt(header, resource.offset); err != nil {
		return resource, err
	}
	resource.originalSize = int64(binary.LittleEndian.Uint64(header[0:8]))
	resource.chunkSize = int(binary.LittleEndian.Uint32(header[8:12]))
	resource.compression = binary.LittleEndian.Uint32(header[12:16])
	if resource.originalSize <= 0 || resource.chunkSize <= 0 || resource.chunkSize&(resource.chunkSize-1) != 0 {
		return resource, fmt.Errorf("invalid uncompressed size or chunk size")
	}
	if resource.compression > 3 {
		return resource, fmt.Errorf("unknown compression format %d", resource.compression)
	}
	return resource, nil
}

// List returns the direct children of a WIM path. The root contains one
// directory per image.
func (w *Archive) List(name string) ([]EntryInfo, error) {
	entries, err := w.dirEntries(name)
	if err != nil {
		return nil, err
	}
	result := make([]EntryInfo, len(entries))
	for i, entry := range entries {
		result[i] = entry.info()
	}
	return result, nil
}

func (entry entry) info() EntryInfo {
	return EntryInfo{
		Name: entry.name, Path: entry.path, Size: entry.size, Directory: entry.isDir,
		Attributes: entry.attrs, HardLinkID: entry.hardLink, SHA1: entry.hash,
		CreationTime: entry.creationTime, LastAccessTime: entry.lastAccessTime, LastWriteTime: entry.lastWriteTime,
	}
}

// Stat returns portable metadata for one image path.
func (w *Archive) Stat(name string) (EntryInfo, error) {
	entry, err := w.lookupPath(name)
	if err != nil {
		return EntryInfo{}, err
	}
	return entry.info(), nil
}

// Walk visits descendants of a WIM path without materializing a path list.
// Directory entries are visited before their children; returning an error
// stops traversal immediately.
func (w *Archive) Walk(name string, visit func(EntryInfo) error) error {
	if visit == nil {
		return fmt.Errorf("wim: nil walk visitor")
	}
	entries, err := w.dirEntries(name)
	if err != nil {
		return err
	}
	pending := make([]entry, len(entries))
	for index := range entries {
		pending[len(entries)-1-index] = entries[index]
	}
	for len(pending) != 0 {
		current := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if err := visit(current.info()); err != nil {
			return err
		}
		if !current.isDir {
			continue
		}
		children, err := w.dirEntries(current.path)
		if err != nil {
			return err
		}
		for index := len(children) - 1; index >= 0; index-- {
			pending = append(pending, children[index])
		}
	}
	return nil
}

// OpenFile returns a random-access view of a file in an image.
func (w *Archive) OpenFile(name string) (starfile.File, error) {
	entry, err := w.lookupPath(name)
	if err != nil {
		return nil, err
	}
	if entry.isDir {
		return nil, fmt.Errorf("wim: path %q is a directory", name)
	}
	return w.newFile(entry), nil
}

// MetadataFiles returns the XML and per-image metadata resources.
func (w *Archive) MetadataFiles() []NamedFile {
	var result []NamedFile
	if file := w.virtualFile("/$metadata/xml.xml"); file != nil {
		result = append(result, NamedFile{Name: "/$metadata/xml.xml", File: file})
	}
	for _, image := range w.images {
		name := fmt.Sprintf("/$metadata/image%d_metadata.bin", image.index)
		if file := w.virtualFile(name); file != nil {
			result = append(result, NamedFile{Name: name, File: file})
		}
	}
	return result
}

func (w *Archive) String() string       { return "<wim>" }
func (w *Archive) Type() string         { return "wim" }
func (w *Archive) Freeze()              {}
func (w *Archive) Truth() starlark.Bool { return starlark.True }
func (w *Archive) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", w.Type())
}
func (w *Archive) Get(key starlark.Value) (starlark.Value, bool, error) {
	name, ok := starlark.AsString(key)
	if !ok {
		return nil, false, nil
	}
	cleaned := storage.CleanPath(name)
	if cleaned == "/" {
		return &wimDirectory{archive: w, name: "/"}, true, nil
	}
	if cleaned == "/$metadata" {
		return &wimMetadataDirectory{archive: w}, true, nil
	}
	if file := w.virtualFile(cleaned); file != nil {
		return file, true, nil
	}
	entry, err := w.lookupPath(cleaned)
	if err != nil {
		return nil, false, err
	}
	if entry.isDir {
		return &wimDirectory{archive: w, name: cleaned}, true, nil
	}
	return w.newFile(entry), true, nil
}
func (w *Archive) Attr(name string) (starlark.Value, error) {
	switch name {
	case "apply":
		return starlark.NewBuiltin("apply", w.applyBuiltin), nil
	case "entry":
		return starlark.NewBuiltin("entry", w.entryBuiltin), nil
	case "resource_locations":
		return starlark.NewBuiltin("resource_locations", w.resourceLocationsBuiltin), nil
	case "resource_entries":
		return starlark.NewBuiltin("resource_entries", w.resourceEntriesBuiltin), nil
	case "missing_resources":
		return starlark.NewBuiltin("missing_resources", w.missingResourcesBuiltin), nil
	case "cache_stats":
		stats := w.cacheStore.Stats()
		return starfile.NewRecord(starlark.StringDict{
			"bytes":        starlark.MakeInt64(stats.Bytes),
			"entries":      starlark.MakeInt(stats.Entries),
			"evictions":    starlark.MakeUint64(stats.Evictions),
			"hits":         starlark.MakeUint64(stats.Hits),
			"loaded_bytes": starlark.MakeUint64(stats.LoadedBytes),
			"loads":        starlark.MakeUint64(stats.Loads),
			"misses":       starlark.MakeUint64(stats.Misses),
			"peak_bytes":   starlark.MakeInt64(stats.PeakBytes),
		}), nil
	case "files":
		values := []starlark.Value{starlark.String("/$metadata")}
		for _, image := range w.images {
			values = append(values, starlark.String(fmt.Sprintf("/image%d", image.index)))
		}
		return starlark.NewList(values), nil
	}
	return nil, nil
}
func (w *Archive) AttrNames() []string {
	return []string{"apply", "cache_stats", "entry", "files", "missing_resources", "resource_entries", "resource_locations"}
}

func (w *Archive) missingResourcesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	imageIndex := 1
	limit := 100
	if err := starlark.UnpackArgs("missing_resources", args, kwargs, "image?", &imageIndex, "limit?", &limit); err != nil {
		return nil, err
	}
	if imageIndex < 1 || limit < 0 {
		return nil, fmt.Errorf("missing_resources: image must be positive and limit non-negative")
	}
	if limit == 0 {
		return starlark.NewList(nil), nil
	}
	var selected *image
	for index := range w.images {
		if w.images[index].index == imageIndex {
			selected = &w.images[index]
			break
		}
	}
	if selected == nil {
		return nil, fmt.Errorf("missing_resources: image %d not found", imageIndex)
	}
	values := make([]starlark.Value, 0, min(limit, 100))
	pending := []entry{selected.root}
	for len(pending) > 0 {
		directory := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		children, err := w.readWIMDir(selected, directory)
		if err != nil {
			return nil, err
		}
		for _, child := range children {
			if child.isDir {
				pending = append(pending, child)
				continue
			}
			if child.hash == ([20]byte{}) {
				continue
			}
			if _, ok := w.byHash[string(child.hash[:])]; ok {
				continue
			}
			values = append(values, starfile.NewRecord(starlark.StringDict{
				"hard_link_id": starlark.MakeUint64(child.hardLink),
				"path":         starlark.String(child.path),
				"sha1":         starlark.String(hex.EncodeToString(child.hash[:])),
			}))
			if len(values) >= limit {
				return starlark.NewList(values), nil
			}
		}
	}
	return starlark.NewList(values), nil
}

func (w *Archive) resourceEntriesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source, chunk int
	limit := 100
	if err := starlark.UnpackArgs("resource_entries", args, kwargs, "source", &source, "chunk", &chunk, "limit?", &limit); err != nil {
		return nil, err
	}
	if source < 0 || chunk < 0 || limit < 0 {
		return nil, fmt.Errorf("resource_entries: source, chunk, and limit must be non-negative")
	}
	if limit == 0 {
		return starlark.NewList(nil), nil
	}
	values := make([]starlark.Value, 0, min(limit, 100))
	for imageIndex := range w.images {
		image := &w.images[imageIndex]
		pending := []entry{image.root}
		for len(pending) > 0 {
			directory := pending[len(pending)-1]
			pending = pending[:len(pending)-1]
			children, err := w.readWIMDir(image, directory)
			if err != nil {
				return nil, err
			}
			for _, child := range children {
				if child.isDir {
					pending = append(pending, child)
					continue
				}
				location, ok := w.byHash[string(child.hash[:])]
				if !ok || int(location.archive.cacheSource) != source || location.resource.chunkSize <= 0 || location.blobSize <= 0 {
					continue
				}
				first := int(location.blobOffset / int64(location.resource.chunkSize))
				last := int((location.blobOffset + location.blobSize - 1) / int64(location.resource.chunkSize))
				if chunk < first || chunk > last {
					continue
				}
				values = append(values, starfile.NewRecord(starlark.StringDict{
					"blob_offset": starlark.MakeInt64(location.blobOffset),
					"path":        starlark.String(child.path),
					"sha1":        starlark.String(hex.EncodeToString(child.hash[:])),
					"size":        starlark.MakeInt64(location.blobSize),
				}))
				if len(values) >= limit {
					return starlark.NewList(values), nil
				}
			}
		}
	}
	return starlark.NewList(values), nil
}

func (w *Archive) resourceLocationsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var digest string
	if err := starlark.UnpackArgs("resource_locations", args, kwargs, "sha1", &digest); err != nil {
		return nil, err
	}
	decoded, err := hex.DecodeString(digest)
	if err != nil || len(decoded) != 20 {
		return nil, fmt.Errorf("resource_locations: sha1 must be 40 hexadecimal characters")
	}
	locations := w.locationsByHash[string(decoded)]
	values := make([]starlark.Value, 0, len(locations))
	for _, location := range locations {
		values = append(values, wimResourceLocationRecord(location))
	}
	return starlark.NewList(values), nil
}

func (w *Archive) entryBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs("entry", args, kwargs, "path", &name); err != nil {
		return nil, err
	}
	entry, err := w.lookupPath(name)
	if err != nil {
		return nil, err
	}
	data := starlark.Value(starlark.None)
	if entry.hash != ([20]byte{}) {
		data = w.newFile(entry)
	}
	return starfile.NewRecord(starlark.StringDict{
		"creation_time":    starlark.MakeUint64(entry.creationTime),
		"data":             data,
		"directory":        starlark.Bool(entry.isDir),
		"file_attributes":  starlark.MakeUint(uint(entry.attrs)),
		"hard_link_id":     starlark.MakeUint64(entry.hardLink),
		"last_access_time": starlark.MakeUint64(entry.lastAccessTime),
		"last_write_time":  starlark.MakeUint64(entry.lastWriteTime),
		"name":             starlark.String(entry.name),
		"path":             starlark.String(entry.path),
		"reparse_tag":      starlark.MakeUint(uint(entry.reparseTag)),
		"security_id":      starlark.MakeUint(uint(entry.securityID)),
		"sha1":             starlark.Bytes(entry.hash[:]),
		"short_name":       starlark.String(entry.shortName),
		"stream_count":     starlark.MakeUint(uint(entry.streamCount)),
	}), nil
}

func parseWIMResource(data []byte) wimResource {
	size := int64(0)
	for i := 6; i >= 0; i-- {
		size = (size << 8) | int64(data[i])
	}
	return wimResource{
		size:         size,
		flags:        data[7],
		offset:       int64(binary.LittleEndian.Uint64(data[8:16])),
		originalSize: int64(binary.LittleEndian.Uint64(data[16:24])),
	}
}

func (w *Archive) readImages() error {
	metadata := make([]wimResource, 0, w.imageCount)
	for _, entry := range w.lookup {
		if entry.resource.flags&wimResourceMetadata == 0 || entry.resource.originalSize == 0 {
			continue
		}
		if entry.resource.originalSize > 0 && entry.resource.originalSize < 128*1024*1024 {
			data, err := w.readResource(entry.resource)
			if err != nil {
				continue
			}
			if len(data) >= 120 && plausibleWIMMetadata(data) {
				metadata = append(metadata, entry.resource)
				if len(metadata) >= w.imageCount {
					break
				}
			}
		}
	}
	if len(metadata) == 0 && w.boot.originalSize > 0 {
		metadata = append(metadata, w.boot)
	}
	for idx, resource := range metadata {
		data, err := w.readResource(resource)
		if err != nil {
			return err
		}
		root, err := parseWIMRoot(data, idx+1)
		if err != nil {
			return err
		}
		security, err := parseWIMSecurity(data)
		if err != nil {
			return fmt.Errorf("wim image %d security: %w", idx+1, err)
		}
		w.images = append(w.images, image{
			index:    idx + 1,
			resource: resource,
			metadata: data,
			security: security,
			root:     root,
			dirs:     make(map[string][]entry),
			byPath:   map[string]entry{wimPathKey(root.path): root},
		})
	}
	return nil
}

func parseWIMSecurity(data []byte) ([][]byte, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("truncated security block")
	}
	size := int(binary.LittleEndian.Uint32(data[0:4]))
	count := int(binary.LittleEndian.Uint32(data[4:8]))
	if size < 8 || size > len(data) || count > (size-8)/8 {
		return nil, fmt.Errorf("invalid security block size or descriptor count")
	}
	offset := 8 + count*8
	descriptors := make([][]byte, 0, count)
	for index := 0; index < count; index++ {
		length64 := binary.LittleEndian.Uint64(data[8+index*8 : 16+index*8])
		if length64 > uint64(size-offset) {
			return nil, fmt.Errorf("descriptor %d exceeds security block", index)
		}
		length := int(length64)
		descriptors = append(descriptors, data[offset:offset+length])
		offset += length
	}
	if padding := size - offset; padding < 0 || padding > 7 || !bytes.Equal(data[offset:size], make([]byte, padding)) {
		return nil, fmt.Errorf("security descriptors end at %#x, block ends at %#x", offset, size)
	}
	return descriptors, nil
}

func plausibleWIMMetadata(data []byte) bool {
	if len(data) < 120 {
		return false
	}
	securitySize := int(binary.LittleEndian.Uint32(data[0:4]))
	if securitySize < 8 || securitySize >= len(data) {
		return false
	}
	off := align8(securitySize)
	if off+wimMetadataEntryBaseLen > len(data) {
		return false
	}
	nameLen := int(binary.LittleEndian.Uint16(data[off+100 : off+102]))
	return nameLen <= 520 && off+wimMetadataEntryBaseLen+nameLen <= len(data)
}

func parseWIMRoot(data []byte, imageIndex int) (entry, error) {
	securitySize := int(binary.LittleEndian.Uint32(data[0:4]))
	if securitySize < 8 || securitySize >= len(data) {
		return entry{}, fmt.Errorf("wim: invalid security block")
	}
	rootOff := align8(securitySize)
	root, err := parseWIMEntry(data, rootOff, fmt.Sprintf("/image%d", imageIndex))
	if err != nil {
		return entry{}, err
	}
	root.name = fmt.Sprintf("image%d", imageIndex)
	root.path = fmt.Sprintf("/image%d", imageIndex)
	root.isDir = true
	return root, nil
}

func parseWIMEntry(data []byte, off int, base string) (entry, error) {
	length := int(binary.LittleEndian.Uint64(data[off : off+8]))
	if length == 0 {
		return entry{}, nil
	}
	if off+length > len(data) || length < wimMetadataEntryBaseLen {
		return entry{}, fmt.Errorf("wim: invalid directory entry length %#x at metadata offset %#x", length, off)
	}
	shortLen := int(binary.LittleEndian.Uint16(data[off+98 : off+100]))
	nameLen := int(binary.LittleEndian.Uint16(data[off+100 : off+102]))
	nameStart := off + wimMetadataEntryBaseLen
	nameEnd := nameStart + nameLen
	if nameEnd+shortLen > off+length {
		return entry{}, fmt.Errorf("wim: invalid directory entry name")
	}
	name := utf16LEString(data[nameStart:nameEnd])
	attrs := binary.LittleEndian.Uint32(data[off+8 : off+12])
	reparseTag := uint32(0)
	hardLink := uint64(0)
	if attrs&0x400 != 0 {
		reparseTag = binary.LittleEndian.Uint32(data[off+88 : off+92])
	} else {
		hardLink = binary.LittleEndian.Uint64(data[off+88 : off+96])
	}
	entry := entry{
		name:           name,
		path:           path.Join(base, name),
		shortName:      utf16LEString(data[nameEnd : nameEnd+shortLen]),
		attrs:          attrs,
		securityID:     binary.LittleEndian.Uint32(data[off+12 : off+16]),
		subdirOff:      binary.LittleEndian.Uint64(data[off+16 : off+24]),
		creationTime:   binary.LittleEndian.Uint64(data[off+40 : off+48]),
		lastAccessTime: binary.LittleEndian.Uint64(data[off+48 : off+56]),
		lastWriteTime:  binary.LittleEndian.Uint64(data[off+56 : off+64]),
		reparseTag:     reparseTag,
		hardLink:       hardLink,
		streamCount:    binary.LittleEndian.Uint16(data[off+96 : off+98]),
		isDir:          binary.LittleEndian.Uint64(data[off+16:off+24]) != 0 || binary.LittleEndian.Uint32(data[off+8:off+12])&0x10 != 0,
	}
	copy(entry.hash[:], data[off+64:off+84])
	return entry, nil
}

func (w *Archive) applyBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var targetValue starlark.Value
	imageIndex := 1
	source := "/"
	destination := "/"
	preserveHardLinks := true
	preserveReparsePoints := true
	if err := starlark.UnpackArgs("apply", args, kwargs,
		"target", &targetValue,
		"image?", &imageIndex,
		"source?", &source,
		"destination?", &destination,
		"hardlinks?", &preserveHardLinks,
		"reparse_points?", &preserveReparsePoints,
	); err != nil {
		return nil, err
	}
	target, ok := targetValue.(*virtualfs.Directory)
	if !ok {
		return nil, fmt.Errorf("wim.apply: got %s, want directory", targetValue.Type())
	}
	var image *image
	for index := range w.images {
		if w.images[index].index == imageIndex {
			image = &w.images[index]
			break
		}
	}
	if image == nil {
		return nil, fmt.Errorf("wim.apply: image %d not found", imageIndex)
	}
	source = storage.CleanPath(source)
	imageSource := image.root.path
	if source != "/" {
		imageSource = path.Join(image.root.path, strings.TrimPrefix(source, "/"))
	}
	root, err := w.lookupPath(imageSource)
	if err != nil {
		return nil, err
	}
	destination = storage.CleanPath(destination)
	if !root.isDir {
		metadata := image.virtualMetadata(root, preserveHardLinks)
		if root.reparseTag != 0 && preserveReparsePoints {
			metadata.ReparseTag = root.reparseTag
			metadata.ReparseData = w.newFile(root)
			target.PutFile(destination, virtualfs.FileRecord{})
		} else {
			metadata.FileAttributes &^= 0x400
			if root.reparseTag != 0 {
				target.PutFile(destination, virtualfs.FileRecord{})
			} else {
				target.PutFile(destination, virtualfs.FileRecord{File: w.newFile(root), Size: root.size})
			}
		}
		target.SetMetadata(destination, metadata)
		return starlark.None, nil
	}
	target.Mkdir(destination)
	rootMetadata := image.virtualMetadata(root, preserveHardLinks)
	if root.reparseTag != 0 && preserveReparsePoints {
		rootMetadata.ReparseTag = root.reparseTag
		rootMetadata.ReparseData = w.newFile(root)
	} else if root.reparseTag != 0 {
		rootMetadata.FileAttributes &^= 0x400
	}
	target.SetMetadata(destination, rootMetadata)
	type pendingDirectory struct {
		entry       entry
		destination string
	}
	pending := []pendingDirectory{{entry: root, destination: destination}}
	for len(pending) > 0 {
		current := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		children, err := w.dirEntries(current.entry.path)
		if err != nil {
			return nil, err
		}
		for _, child := range children {
			childDestination := path.Join(current.destination, child.name)
			metadata := image.virtualMetadata(child, preserveHardLinks)
			if child.reparseTag != 0 && preserveReparsePoints {
				metadata.ReparseTag = child.reparseTag
				metadata.ReparseData = w.newFile(child)
			} else if child.reparseTag != 0 {
				metadata.FileAttributes &^= 0x400
			}
			if child.isDir {
				target.Mkdir(childDestination)
				pending = append(pending, pendingDirectory{entry: child, destination: childDestination})
			} else if child.reparseTag != 0 {
				target.PutFile(childDestination, virtualfs.FileRecord{})
			} else {
				target.PutFile(childDestination, virtualfs.FileRecord{File: w.newFile(child), Size: child.size})
			}
			target.SetMetadata(childDestination, metadata)
		}
	}
	return starlark.None, nil
}

func (image *image) virtualMetadata(entry entry, preserveHardLinks bool) virtualfs.Metadata {
	metadata := virtualfs.Metadata{
		FileAttributes:    entry.attrs,
		HasFileAttributes: true,
		CreationTime:      entry.creationTime,
		LastAccessTime:    entry.lastAccessTime,
		LastWriteTime:     entry.lastWriteTime,
		HardLink:          entry.hardLink,
		ShortName:         entry.shortName,
	}
	if !preserveHardLinks {
		metadata.HardLink = 0
	}
	if int(entry.securityID) < len(image.security) {
		metadata.SecurityDescriptor = image.security[entry.securityID]
	}
	return metadata
}

// wimPathKey preserves EqualFold equivalence, including non-ASCII simple-fold
// cycles such as S/s/long-s. Lowercasing alone is not an equivalent index key.
func wimPathKey(name string) string {
	return strings.Map(func(r rune) rune {
		if r < unicode.MaxASCII {
			if r >= 'a' && r <= 'z' {
				return r - ('a' - 'A')
			}
			return r
		}
		lowest := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < lowest {
				lowest = next
			}
		}
		return lowest
	}, name)
}

func (w *Archive) lookupPath(name string) (entry, error) {
	cleaned := storage.CleanPath(name)
	key := wimPathKey(cleaned)
	for idx := range w.images {
		image := &w.images[idx]
		if !strings.HasPrefix(key+"/", wimPathKey(image.root.path)+"/") {
			continue
		}
		if found, ok := image.byPath[key]; ok {
			return found, nil
		}
		current := image.root
		parts := strings.Split(cleaned[len(image.root.path):], "/")
		for _, part := range parts {
			if part == "" {
				continue
			}
			_, err := w.readWIMDir(image, current)
			if err != nil {
				return entry{}, err
			}
			child, found := image.byPath[wimPathKey(current.path+"/"+part)]
			if !found {
				return entry{}, fmt.Errorf("wim: path %q not found", name)
			}
			current = child
		}
		return current, nil
	}
	return entry{}, fmt.Errorf("wim: path %q not found", name)
}

func (w *Archive) dirEntries(name string) ([]entry, error) {
	cleaned := storage.CleanPath(name)
	if cleaned == "/" {
		entries := make([]entry, 0, len(w.images))
		for _, image := range w.images {
			entries = append(entries, image.root)
		}
		return entries, nil
	}
	if cleaned == "/$metadata" {
		return nil, nil
	}
	for idx := range w.images {
		image := &w.images[idx]
		if strings.EqualFold(cleaned, image.root.path) {
			return w.readWIMDir(image, image.root)
		}
	}
	entry, err := w.lookupPath(cleaned)
	if err != nil {
		return nil, err
	}
	for idx := range w.images {
		image := &w.images[idx]
		if strings.HasPrefix(strings.ToLower(cleaned)+"/", strings.ToLower(image.root.path)+"/") {
			return w.readWIMDir(image, entry)
		}
	}
	return nil, nil
}

func (w *Archive) readWIMDir(image *image, dir entry) ([]entry, error) {
	if !dir.isDir || dir.subdirOff == 0 {
		return nil, nil
	}
	key := strings.ToLower(dir.path)
	if entries, ok := image.dirs[key]; ok {
		return entries, nil
	}
	data := image.metadata
	var entries []entry
	for off := int(dir.subdirOff); ; {
		if off+8 > len(data) || binary.LittleEndian.Uint64(data[off:off+8]) == 0 {
			break
		}
		length := int(binary.LittleEndian.Uint64(data[off : off+8]))
		if length < wimMetadataEntryBaseLen || off+length > len(data) {
			break
		}
		entry, err := parseWIMEntry(data, off, dir.path)
		if err != nil {
			return nil, fmt.Errorf("entry at %#x under %s: %w", off, dir.path, err)
		}
		if entry.name == "" {
			break
		}
		if !validWIMName(entry.name) {
			break
		}
		if location, ok := w.byHash[string(entry.hash[:])]; ok {
			entry.size = location.blobSize
		}
		entries = append(entries, entry)
		off += length
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].isDir != entries[j].isDir {
			return entries[i].isDir
		}
		return strings.ToLower(entries[i].name) < strings.ToLower(entries[j].name)
	})
	for _, child := range entries {
		key := wimPathKey(child.path)
		if _, exists := image.byPath[key]; !exists {
			image.byPath[key] = child
		}
	}
	image.dirs[key] = entries
	return entries, nil
}

func validWIMName(name string) bool {
	if name == "" || strings.ContainsAny(name, `/\`) {
		return false
	}
	for _, r := range name {
		if r < 0x20 || r == '\ufffd' {
			return false
		}
	}
	return true
}

func (w *Archive) readResource(resource wimResource) ([]byte, error) {
	if resource.originalSize < 0 || resource.size < 0 {
		return nil, fmt.Errorf("wim: invalid resource size")
	}
	if resource.flags&wimResourceCompressed == 0 {
		data := make([]byte, resource.size)
		if _, err := w.file.ReadAt(data, resource.offset); err != nil && err != io.EOF {
			return nil, err
		}
		return data, nil
	}
	out := make([]byte, 0, resource.originalSize)
	chunks, err := w.resourceChunks(resource)
	if err != nil {
		return nil, err
	}
	for _, chunk := range chunks {
		data, err := w.readResourceChunk(resource, chunk.index)
		if err != nil {
			return nil, err
		}
		out = append(out, data...)
	}
	if int64(len(out)) > resource.originalSize {
		out = out[:resource.originalSize]
	}
	return out, nil
}

type wimChunk struct {
	index      int
	inOffset   int64
	inSize     int64
	outputSize int
}

func (w *Archive) resourceChunks(resource wimResource) ([]wimChunk, error) {
	if resource.originalSize == 0 {
		return nil, nil
	}
	chunkSize := w.chunkSize
	if resource.flags&wimResourceSolid != 0 {
		chunkSize = resource.chunkSize
	}
	if chunkSize <= 0 {
		return nil, fmt.Errorf("wim: compressed resource has invalid chunk size %d", chunkSize)
	}
	chunks := int((resource.originalSize + int64(chunkSize) - 1) / int64(chunkSize))
	if chunks == 0 {
		return nil, nil
	}
	if resource.flags&(wimResourceCompressed|wimResourceSolid) == 0 {
		return []wimChunk{{index: 0, inOffset: 0, inSize: resource.size, outputSize: int(resource.originalSize)}}, nil
	}
	if resource.flags&wimResourceSolid != 0 {
		tableSize := int64(chunks * 4)
		table := make([]byte, tableSize)
		if n, err := w.file.ReadAt(table, resource.offset+16); n != len(table) {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			return nil, fmt.Errorf("wim: read solid chunk table: %w", err)
		}
		dataOffset := int64(16) + tableSize
		out := make([]wimChunk, 0, chunks)
		for index := 0; index < chunks; index++ {
			compressedSize := int64(binary.LittleEndian.Uint32(table[index*4 : index*4+4]))
			outputSize := chunkSize
			if index == chunks-1 {
				outputSize = int(resource.originalSize - int64(index*chunkSize))
			}
			out = append(out, wimChunk{index: index, inOffset: dataOffset, inSize: compressedSize, outputSize: outputSize})
			dataOffset += compressedSize
		}
		return out, nil
	}
	entrySize := int64(4)
	if resource.size >= 1<<32 {
		entrySize = 8
	}
	tableSize := int64(chunks-1) * entrySize
	table := make([]byte, tableSize)
	if tableSize > 0 {
		if n, err := w.file.ReadAt(table, resource.offset); n != len(table) {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			return nil, fmt.Errorf("wim: read chunk table: %w", err)
		}
	}
	offsetAt := func(idx int) int64 {
		if idx < 0 {
			return tableSize
		}
		off := int64(idx) * entrySize
		if entrySize == 8 {
			return tableSize + int64(binary.LittleEndian.Uint64(table[off:off+8]))
		}
		return tableSize + int64(binary.LittleEndian.Uint32(table[off:off+4]))
	}
	out := make([]wimChunk, 0, chunks)
	for idx := 0; idx < chunks; idx++ {
		start := offsetAt(idx - 1)
		end := resource.size
		if idx < chunks-1 {
			end = offsetAt(idx)
		}
		outputSize := chunkSize
		if idx == chunks-1 {
			outputSize = int(resource.originalSize - int64(idx*chunkSize))
		}
		out = append(out, wimChunk{index: idx, inOffset: start, inSize: end - start, outputSize: outputSize})
	}
	return out, nil
}

func (w *Archive) readResourceChunk(resource wimResource, index int) ([]byte, error) {
	chunks, err := w.resourceChunks(resource)
	if err != nil {
		return nil, err
	}
	if index < 0 || index >= len(chunks) {
		return nil, fmt.Errorf("wim: invalid chunk index")
	}
	return w.readChunk(resource, chunks[index])
}

func (w *Archive) readChunk(resource wimResource, chunk wimChunk) ([]byte, error) {
	data := make([]byte, chunk.inSize)
	if _, err := w.file.ReadAt(data, resource.offset+chunk.inOffset); err != nil && err != io.EOF {
		return nil, err
	}
	if resource.flags&(wimResourceCompressed|wimResourceSolid) == 0 || len(data) == chunk.outputSize {
		if len(data) > chunk.outputSize {
			data = data[:chunk.outputSize]
		}
		return data, nil
	}
	var out []byte
	var err error
	switch {
	case resource.flags&wimResourceSolid != 0 && resource.compression == 0:
		if len(data) != chunk.outputSize {
			err = fmt.Errorf("uncompressed solid chunk has size %d, want %d", len(data), chunk.outputSize)
		} else {
			out = data
		}
	case resource.flags&wimResourceSolid != 0 && resource.compression == 1:
		out, err = xpress.HuffmanDecompress(data, chunk.outputSize)
	case resource.flags&wimResourceSolid != 0 && resource.compression == 2:
		out, err = lzx.DecompressWIMChunk(data, 15, chunk.outputSize)
	case resource.flags&wimResourceSolid != 0 && resource.compression == 3:
		out, err = lzms.Decompress(data, chunk.outputSize)
	case w.flags&wimFlagLZMS != 0:
		out, err = lzms.Decompress(data, chunk.outputSize)
	case w.flags&wimFlagLZX != 0:
		out, err = lzx.DecompressWIMChunk(data, 15, chunk.outputSize)
	case w.flags&wimFlagXPRESS != 0:
		out, err = xpress.HuffmanDecompress(data, chunk.outputSize)
	default:
		err = fmt.Errorf("unknown compression flags %#x", w.flags)
	}
	if err != nil {
		return nil, fmt.Errorf("chunk %d offset %#x size %#x out %d: %w", chunk.index, resource.offset+chunk.inOffset, chunk.inSize, chunk.outputSize, err)
	}
	return out, nil
}

func (w *Archive) cachedResourceChunk(resource wimResource, chunk wimChunk) ([]byte, error) {
	key := bytecache.Key{
		Source:       w.cacheSource,
		Kind:         2,
		Offset:       resource.offset,
		Size:         resource.size,
		OriginalSize: resource.originalSize,
		Index:        chunk.index,
	}
	return w.cacheStore.Get(key, func() ([]byte, error) {
		return w.readChunk(resource, chunk)
	})
}

func (w *Archive) virtualFile(name string) starfile.File {
	switch strings.ToLower(name) {
	case "/$metadata/xml.xml":
		return newResourceFile(name, w, w.xml)
	}
	for _, image := range w.images {
		if strings.EqualFold(name, fmt.Sprintf("/$metadata/image%d_metadata.bin", image.index)) {
			return newResourceFile(name, w, image.resource)
		}
	}
	return nil
}

func align8(value int) int { return (value + 7) &^ 7 }

func utf16LEString(data []byte) string {
	values := make([]uint16, 0, len(data)/2)
	for off := 0; off+1 < len(data); off += 2 {
		v := binary.LittleEndian.Uint16(data[off : off+2])
		if v == 0 {
			continue
		}
		values = append(values, v)
	}
	return string(utf16.Decode(values))
}

type wimDirectory struct {
	archive *Archive
	name    string
}

func (d *wimDirectory) String() string {
	files, err := d.files()
	if err != nil {
		return fmt.Sprintf("<wim.dir %q read error: %v>", d.name, err)
	}
	return files.String()
}
func (d *wimDirectory) Type() string         { return "directory" }
func (d *wimDirectory) Freeze()              {}
func (d *wimDirectory) Truth() starlark.Bool { return starlark.True }
func (d *wimDirectory) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", d.Type())
}
func (d *wimDirectory) Attr(name string) (starlark.Value, error) {
	if name == "files" {
		return d.files()
	}
	return nil, nil
}
func (d *wimDirectory) AttrNames() []string { return []string{"files"} }
func (d *wimDirectory) files() (*starlark.List, error) {
	if d.name == "/$metadata" {
		return d.archive.metadataFiles(), nil
	}
	entries, err := d.archive.dirEntries(d.name)
	if err != nil {
		return nil, err
	}
	values := make([]starlark.Value, 0, len(entries)+1)
	if d.name == "/" {
		values = append(values, starlark.String("/$metadata"))
	}
	for _, entry := range entries {
		values = append(values, starlark.String(entry.path))
	}
	return starlark.NewList(values), nil
}

type wimMetadataDirectory struct {
	archive *Archive
}

func (d *wimMetadataDirectory) String() string {
	return d.archive.metadataFiles().String()
}
func (d *wimMetadataDirectory) Type() string         { return "directory" }
func (d *wimMetadataDirectory) Freeze()              {}
func (d *wimMetadataDirectory) Truth() starlark.Bool { return starlark.True }
func (d *wimMetadataDirectory) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", d.Type())
}
func (d *wimMetadataDirectory) Attr(name string) (starlark.Value, error) {
	if name == "files" {
		return d.archive.metadataFiles(), nil
	}
	return nil, nil
}
func (d *wimMetadataDirectory) AttrNames() []string { return []string{"files"} }

func (w *Archive) metadataFiles() *starlark.List {
	values := []starlark.Value{starlark.String("/$metadata/xml.xml")}
	for _, image := range w.images {
		values = append(values, starlark.String(fmt.Sprintf("/$metadata/image%d_metadata.bin", image.index)))
	}
	return starlark.NewList(values)
}

type File struct {
	archive  *Archive
	entry    entry
	reader   storage.Reader
	location *wimResourceLocation
}

func (w *Archive) newFile(entry entry) *File {
	location, ok := w.byHash[string(entry.hash[:])]
	if !ok {
		return &File{archive: w, entry: entry}
	}
	entry.size = location.blobSize
	return &File{
		archive:  w,
		entry:    entry,
		reader:   readerForLocation(entry.path, location),
		location: &location,
	}
}

func readerForLocation(name string, location wimResourceLocation) storage.Reader {
	if location.external != nil {
		return location.external
	}
	return newResourceFileRange(name, location.archive, location.resource, location.blobOffset, location.blobSize)
}

func (f *File) ReadAt(p []byte, off int64) (int, error) {
	if f.reader == nil {
		return 0, fmt.Errorf("wim: resource for %q not found", f.entry.path)
	}
	return f.reader.ReadAt(p, off)
}
func (f *File) WriteAt(_ []byte, _ int64) (int, error) {
	return 0, fmt.Errorf("wim entry %q is read-only", f.entry.path)
}
func (f *File) Size() int64 { return f.entry.size }
func (f *File) String() string {
	return fmt.Sprintf("<wim.file %q size=%d>", f.entry.path, f.Size())
}
func (f *File) Type() string         { return "file" }
func (f *File) Freeze()              {}
func (f *File) Truth() starlark.Bool { return starlark.True }
func (f *File) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", f.Type())
}
func (f *File) Attr(name string) (starlark.Value, error) {
	switch name {
	case "metadata":
		return starfile.NewRecord(starlark.StringDict{
			"creation_time":    starlark.MakeUint64(f.entry.creationTime),
			"file_attributes":  starlark.MakeUint(uint(f.entry.attrs)),
			"hard_link_id":     starlark.MakeUint64(f.entry.hardLink),
			"last_access_time": starlark.MakeUint64(f.entry.lastAccessTime),
			"last_write_time":  starlark.MakeUint64(f.entry.lastWriteTime),
			"name":             starlark.String(f.entry.name),
			"path":             starlark.String(f.entry.path),
			"reparse_tag":      starlark.MakeUint(uint(f.entry.reparseTag)),
			"security_id":      starlark.MakeUint(uint(f.entry.securityID)),
			"sha1":             starlark.Bytes(f.entry.hash[:]),
			"short_name":       starlark.String(f.entry.shortName),
			"stream_count":     starlark.MakeUint(uint(f.entry.streamCount)),
		}), nil
	case "resource":
		if f.location == nil {
			return starlark.None, nil
		}
		return wimResourceLocationRecord(*f.location), nil
	case "verify":
		return starlark.NewBuiltin("verify", f.verifyBuiltin), nil
	case "verify_locations":
		return starlark.NewBuiltin("verify_locations", f.verifyLocationsBuiltin), nil
	}
	return starfile.Attr(f, name), nil
}

func (f *File) verifyBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("verify", args, kwargs); err != nil {
		return nil, err
	}
	hash := sha1.New()
	if _, err := io.Copy(hash, io.NewSectionReader(f, 0, f.Size())); err != nil {
		return nil, fmt.Errorf("wim: verify %q: %w", f.entry.path, err)
	}
	actual := hash.Sum(nil)
	expected := f.entry.hash[:]
	return starfile.NewRecord(starlark.StringDict{
		"actual_sha1":   starlark.String(hex.EncodeToString(actual)),
		"expected_sha1": starlark.String(hex.EncodeToString(expected)),
		"size":          starlark.MakeInt64(f.Size()),
		"valid":         starlark.Bool(bytes.Equal(actual, expected)),
	}), nil
}

func (f *File) verifyLocationsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("verify_locations", args, kwargs); err != nil {
		return nil, err
	}
	locations := f.archive.locationsByHash[string(f.entry.hash[:])]
	values := make([]starlark.Value, 0, len(locations))
	for _, location := range locations {
		reader := readerForLocation(f.entry.path, location)
		hash := sha1.New()
		if _, err := io.Copy(hash, io.NewSectionReader(reader, 0, location.blobSize)); err != nil {
			return nil, fmt.Errorf("wim: verify location for %q: %w", f.entry.path, err)
		}
		actual := hash.Sum(nil)
		chunk := -1
		if location.external == nil && location.resource.chunkSize > 0 {
			chunk = int(location.blobOffset / int64(location.resource.chunkSize))
		}
		source := uint64(0)
		if location.archive != nil {
			source = location.archive.cacheSource
		}
		values = append(values, starfile.NewRecord(starlark.StringDict{
			"actual_sha1": starlark.String(hex.EncodeToString(actual)),
			"blob_offset": starlark.MakeInt64(location.blobOffset),
			"chunk":       starlark.MakeInt(chunk),
			"source":      starlark.MakeUint64(source),
			"valid":       starlark.Bool(bytes.Equal(actual, f.entry.hash[:])),
		}))
	}
	return starlark.NewList(values), nil
}

func wimResourceLocationRecord(location wimResourceLocation) starlark.Value {
	resource := location.resource
	firstChunk, lastChunk := -1, -1
	if resource.chunkSize > 0 && location.blobSize > 0 {
		firstChunk = int(location.blobOffset / int64(resource.chunkSize))
		lastChunk = int((location.blobOffset + location.blobSize - 1) / int64(resource.chunkSize))
	}
	archivePart, totalParts := uint(0), uint(0)
	source := uint64(0)
	compression := "external"
	if location.archive != nil {
		archivePart = uint(location.archive.partNumber)
		totalParts = uint(location.archive.totalParts)
		source = location.archive.cacheSource
		compression = wimCompressionName(location.archive, resource)
	}
	return starfile.NewRecord(starlark.StringDict{
		"blob_offset":     starlark.MakeInt64(location.blobOffset),
		"blob_size":       starlark.MakeInt64(location.blobSize),
		"archive_part":    starlark.MakeUint(archivePart),
		"total_parts":     starlark.MakeUint(totalParts),
		"lookup_part":     starlark.MakeUint(uint(location.lookupPart)),
		"reference_count": starlark.MakeUint(uint(location.refCount)),
		"chunk_size":      starlark.MakeInt(resource.chunkSize),
		"compression":     starlark.String(compression),
		"compressed_size": starlark.MakeInt64(resource.size),
		"first_chunk":     starlark.MakeInt(firstChunk),
		"flags":           starlark.MakeUint(uint(resource.flags)),
		"last_chunk":      starlark.MakeInt(lastChunk),
		"original_size":   starlark.MakeInt64(resource.originalSize),
		"physical_offset": starlark.MakeInt64(resource.offset),
		"source":          starlark.MakeUint64(source),
	})
}
func (f *File) AttrNames() []string {
	return append(starfile.AttrNames(), "metadata", "resource", "verify", "verify_locations")
}

func wimCompressionName(archive *Archive, resource wimResource) string {
	if resource.flags&wimResourceSolid != 0 {
		switch resource.compression {
		case 0:
			return "none"
		case 1:
			return "xpress"
		case 2:
			return "lzx"
		case 3:
			return "lzms"
		default:
			return "unknown"
		}
	}
	if resource.flags&wimResourceCompressed == 0 {
		return "none"
	}
	switch {
	case archive.flags&wimFlagLZMS != 0:
		return "lzms"
	case archive.flags&wimFlagLZX != 0:
		return "lzx"
	case archive.flags&wimFlagXPRESS != 0:
		return "xpress"
	default:
		return "unknown"
	}
}

type ResourceFile struct {
	name        string
	archive     *Archive
	resource    wimResource
	offset      int64
	size        int64
	mu          sync.Mutex
	chunks      []wimChunk
	chunksErr   error
	chunksReady bool
}

func newResourceFile(name string, archive *Archive, resource wimResource) *ResourceFile {
	size := resource.originalSize
	if size == 0 {
		size = resource.size
	}
	return newResourceFileRange(name, archive, resource, 0, size)
}

func newResourceFileRange(name string, archive *Archive, resource wimResource, offset, size int64) *ResourceFile {
	return &ResourceFile{name: name, archive: archive, resource: resource, offset: offset, size: size}
}

func (f *ResourceFile) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset")
	}
	if off >= f.Size() {
		return 0, io.EOF
	}
	requested := len(p)
	if remaining := f.Size() - off; int64(len(p)) > remaining {
		p = p[:remaining]
	}
	if f.resource.flags&(wimResourceCompressed|wimResourceSolid) == 0 {
		n, err := f.archive.file.ReadAt(p, f.resource.offset+f.offset+off)
		if n < requested && err == nil {
			err = io.EOF
		}
		return n, err
	}
	chunks, err := f.resourceChunks()
	if err != nil {
		return 0, fmt.Errorf("wim resource %q: %w", f.name, err)
	}
	n := 0
	absoluteOffset := f.offset + off
	chunkSize := f.archive.chunkSize
	if f.resource.flags&wimResourceSolid != 0 {
		chunkSize = f.resource.chunkSize
	}
	for len(p) > 0 {
		index := int(absoluteOffset / int64(chunkSize))
		if index < 0 || index >= len(chunks) {
			break
		}
		chunk, err := f.archive.cachedResourceChunk(f.resource, chunks[index])
		if err != nil {
			return n, fmt.Errorf("wim resource %q: %w", f.name, err)
		}
		chunkOffset := int(absoluteOffset % int64(chunkSize))
		copied := copy(p, chunk[chunkOffset:])
		n += copied
		off += int64(copied)
		absoluteOffset += int64(copied)
		p = p[copied:]
	}
	if n < requested {
		return n, io.EOF
	}
	return n, nil
}
func (f *ResourceFile) WriteAt(_ []byte, _ int64) (int, error) {
	return 0, fmt.Errorf("wim resource %q is read-only", f.name)
}
func (f *ResourceFile) Size() int64 {
	return f.size
}
func (f *ResourceFile) String() string {
	return fmt.Sprintf("<wim.resource %q size=%d>", f.name, f.Size())
}
func (f *ResourceFile) Type() string         { return "file" }
func (f *ResourceFile) Freeze()              {}
func (f *ResourceFile) Truth() starlark.Bool { return starlark.True }
func (f *ResourceFile) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", f.Type())
}
func (f *ResourceFile) Attr(name string) (starlark.Value, error) {
	return starfile.Attr(f, name), nil
}
func (f *ResourceFile) AttrNames() []string { return starfile.AttrNames() }
func (f *ResourceFile) resourceChunks() ([]wimChunk, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.chunksReady {
		f.chunks, f.chunksErr = f.archive.resourceChunks(f.resource)
		f.chunksReady = true
	}
	return f.chunks, f.chunksErr
}
