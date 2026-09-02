package wim

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"sync"
	"unicode/utf16"

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
	wimLookupEntrySize      = 50
	wimMetadataEntryBaseLen = 102
)

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("wim", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("wim: got %s, want file", value.Type())
	}
	return Open(file)
}

type Archive struct {
	file        storage.Reader
	flags       uint32
	chunkSize   int
	imageCount  int
	lookup      []wimLookupEntry
	byHash      map[string]wimResource
	xml         wimResource
	boot        wimResource
	images      []image
	cacheStore  *bytecache.Cache
	cacheSource uint64
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
	Name      string
	Path      string
	Size      int64
	Directory bool
}

// NamedFile is a synthetic metadata file exposed by a WIM container.
type NamedFile struct {
	Name string
	File starfile.File
}

func Open(file storage.Reader) (*Archive, error) {
	return OpenWithCache(file, bytecache.New(bytecache.DefaultBytes), 1)
}

func OpenWithCache(file storage.Reader, store *bytecache.Cache, source uint64) (*Archive, error) {
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
		file:       file,
		flags:      binary.LittleEndian.Uint32(header[16:20]),
		chunkSize:  int(binary.LittleEndian.Uint32(header[20:24])),
		imageCount: int(binary.LittleEndian.Uint32(header[44:48])),
		byHash:     make(map[string]wimResource),
		xml:        parseWIMResource(header[72:96]),
		boot:       parseWIMResource(header[96:120]),
		cacheStore: store, cacheSource: source,
	}
	if w.chunkSize <= 0 {
		return nil, fmt.Errorf("wim: invalid chunk size")
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
		w.byHash[string(entry.hash[:])] = entry.resource
	}
	if err := w.readImages(); err != nil {
		return nil, err
	}
	return w, nil
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
		result[i] = EntryInfo{Name: entry.name, Path: entry.path, Size: entry.size, Directory: entry.isDir}
	}
	return result, nil
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
	case "files":
		values := []starlark.Value{starlark.String("/$metadata")}
		for _, image := range w.images {
			values = append(values, starlark.String(fmt.Sprintf("/image%d", image.index)))
		}
		return starlark.NewList(values), nil
	}
	return nil, nil
}
func (w *Archive) AttrNames() []string { return []string{"apply", "entry", "files"} }

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
			byPath:   map[string]entry{strings.ToLower(root.path): root},
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

func (w *Archive) lookupPath(name string) (entry, error) {
	cleaned := storage.CleanPath(name)
	for idx := range w.images {
		image := &w.images[idx]
		if strings.EqualFold(name, image.root.path) {
			return image.root, nil
		}
		if !strings.HasPrefix(strings.ToLower(cleaned)+"/", strings.ToLower(image.root.path)+"/") {
			continue
		}
		current := image.root
		parts := strings.Split(strings.TrimPrefix(strings.TrimPrefix(cleaned, image.root.path), "/"), "/")
		for _, part := range parts {
			if part == "" {
				continue
			}
			children, err := w.readWIMDir(image, current)
			if err != nil {
				return entry{}, err
			}
			found := false
			for _, child := range children {
				if strings.EqualFold(child.name, part) {
					current = child
					found = true
					break
				}
			}
			if !found {
				return entry{}, fmt.Errorf("wim: path %q not found", name)
			}
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
		if resource, ok := w.byHash[string(entry.hash[:])]; ok {
			entry.size = resource.originalSize
		}
		entries = append(entries, entry)
		image.byPath[strings.ToLower(entry.path)] = entry
		off += length
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].isDir != entries[j].isDir {
			return entries[i].isDir
		}
		return strings.ToLower(entries[i].name) < strings.ToLower(entries[j].name)
	})
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
	for _, chunk := range w.resourceChunks(resource) {
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

func (w *Archive) resourceChunks(resource wimResource) []wimChunk {
	if resource.originalSize == 0 {
		return nil
	}
	chunks := int((resource.originalSize + int64(w.chunkSize) - 1) / int64(w.chunkSize))
	if chunks == 0 {
		return nil
	}
	if resource.flags&wimResourceCompressed == 0 {
		return []wimChunk{{index: 0, inOffset: 0, inSize: resource.size, outputSize: int(resource.originalSize)}}
	}
	entrySize := int64(4)
	if resource.size >= 1<<32 {
		entrySize = 8
	}
	tableSize := int64(chunks-1) * entrySize
	table := make([]byte, tableSize)
	if tableSize > 0 {
		_, _ = w.file.ReadAt(table, resource.offset)
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
		outputSize := w.chunkSize
		if idx == chunks-1 {
			outputSize = int(resource.originalSize - int64(idx*w.chunkSize))
		}
		out = append(out, wimChunk{index: idx, inOffset: start, inSize: end - start, outputSize: outputSize})
	}
	return out
}

func (w *Archive) readResourceChunk(resource wimResource, index int) ([]byte, error) {
	chunks := w.resourceChunks(resource)
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
	if resource.flags&wimResourceCompressed == 0 || len(data) == chunk.outputSize {
		if len(data) > chunk.outputSize {
			data = data[:chunk.outputSize]
		}
		return data, nil
	}
	if out, err := xpress.HuffmanDecompress(data, chunk.outputSize); err == nil {
		return out, nil
	}
	out, err := lzx.DecompressWIMChunk(data, 15, chunk.outputSize)
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
	archive *Archive
	entry   entry
	reader  *ResourceFile
}

func (w *Archive) newFile(entry entry) *File {
	resource, ok := w.byHash[string(entry.hash[:])]
	if !ok {
		return &File{archive: w, entry: entry}
	}
	return &File{
		archive: w,
		entry:   entry,
		reader:  newResourceFile(entry.path, w, resource),
	}
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
	if name == "metadata" {
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
	}
	return starfile.Attr(f, name), nil
}
func (f *File) AttrNames() []string { return append(starfile.AttrNames(), "metadata") }

type ResourceFile struct {
	name     string
	archive  *Archive
	resource wimResource
	mu       sync.Mutex
	chunks   []wimChunk
}

func newResourceFile(name string, archive *Archive, resource wimResource) *ResourceFile {
	return &ResourceFile{name: name, archive: archive, resource: resource}
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
	if f.resource.flags&wimResourceCompressed == 0 {
		n, err := f.archive.file.ReadAt(p, f.resource.offset+off)
		if n < requested && err == nil {
			err = io.EOF
		}
		return n, err
	}
	chunks := f.resourceChunks()
	n := 0
	for len(p) > 0 {
		index := int(off / int64(f.archive.chunkSize))
		if index < 0 || index >= len(chunks) {
			break
		}
		chunk, err := f.archive.cachedResourceChunk(f.resource, chunks[index])
		if err != nil {
			return n, fmt.Errorf("wim resource %q: %w", f.name, err)
		}
		chunkOffset := int(off % int64(f.archive.chunkSize))
		copied := copy(p, chunk[chunkOffset:])
		n += copied
		off += int64(copied)
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
	if f.resource.originalSize != 0 {
		return f.resource.originalSize
	}
	return f.resource.size
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
func (f *ResourceFile) resourceChunks() []wimChunk {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.chunks == nil {
		f.chunks = f.archive.resourceChunks(f.resource)
	}
	return f.chunks
}
