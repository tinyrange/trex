package cab

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"path"
	"strings"
	"sync"

	"github.com/tinyrange/trex/compression/lzx"
	mszipcompression "github.com/tinyrange/trex/compression/mszip"
	"github.com/tinyrange/trex/storage"
	bytecache "github.com/tinyrange/trex/storage/cache"
	starfile "github.com/tinyrange/trex/storage/star"

	"go.starlark.net/starlark"
)

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	cache := true
	if err := starlark.UnpackArgs("cab", args, kwargs, "file", &value, "cache?", &cache); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("cab: got %s, want file", value.Type())
	}
	return Open(file, cache)
}

type Archive struct {
	file        storage.Reader
	files       []fileRecord
	fileIndex   map[string]int
	folders     []folder
	dataReserve int
	flags       uint16
	setID       uint16
	cabinet     uint16
	previous    string
	next        string
	cache       bool
	cacheStore  *bytecache.Cache
	cacheSource uint64
}

type folder struct {
	dataOffset  uint32
	blocks      uint16
	compression uint16
}

type fileRecord struct {
	name              string
	size              uint32
	folder            uint16
	uncompressedStart uint32
}

// FileInfo describes a member of a cabinet without materializing it.
type FileInfo struct {
	Name string
	Size int64
}

// ContentResource is one cabinet member selected by its content SHA-1.
// Data owns only the selected member bytes, not the decoded cabinet folder.
type ContentResource struct {
	Name string
	SHA1 [20]byte
	Data []byte
}

// MemoryBudget bounds concurrently decoded cabinet folder bytes. Implementations
// must block Acquire until the requested bytes are available and make Release
// safe to call from another goroutine.
type MemoryBudget interface {
	Acquire(bytes int64) error
	Release(bytes int64)
}

type dataBlock struct {
	compressed   []byte
	uncompressed int
}

func Open(file storage.Reader, cache bool) (*Archive, error) {
	return OpenWithCache(file, cache, bytecache.New(bytecache.DefaultBytes), 1)
}

func OpenWithCache(file storage.Reader, cache bool, store *bytecache.Cache, source uint64) (*Archive, error) {
	header := make([]byte, 36)
	if _, err := file.ReadAt(header, 0); err != nil {
		return nil, err
	}
	if string(header[0:4]) != "MSCF" {
		return nil, fmt.Errorf("cab: invalid MSCF signature")
	}
	coffFiles := binary.LittleEndian.Uint32(header[16:20])
	cFolders := binary.LittleEndian.Uint16(header[26:28])
	cFiles := binary.LittleEndian.Uint16(header[28:30])
	flags := binary.LittleEndian.Uint16(header[30:32])
	setID := binary.LittleEndian.Uint16(header[32:34])
	cabinet := binary.LittleEndian.Uint16(header[34:36])
	setReserve := 0
	folderReserve := 0
	dataReserve := 0

	folderOffset := int64(36)
	if flags&0x0004 != 0 {
		reserve := make([]byte, 4)
		if _, err := file.ReadAt(reserve, folderOffset); err != nil {
			return nil, err
		}
		setReserve = int(binary.LittleEndian.Uint16(reserve[0:2]))
		folderReserve = int(reserve[2])
		dataReserve = int(reserve[3])
		folderOffset += 4 + int64(setReserve)
	}
	previous := ""
	next := ""
	for _, optional := range []struct {
		flag uint16
		name *string
	}{{0x0001, &previous}, {0x0002, &next}} {
		if flags&optional.flag == 0 {
			continue
		}
		name, size, err := readCABString(file, folderOffset)
		if err != nil {
			return nil, err
		}
		*optional.name = name
		folderOffset += int64(size)
		_, size, err = readCABString(file, folderOffset)
		if err != nil {
			return nil, err
		}
		folderOffset += int64(size)
	}

	folders := make([]folder, 0, cFolders)
	offset := folderOffset
	for i := 0; i < int(cFolders); i++ {
		record := make([]byte, 8)
		if _, err := file.ReadAt(record, offset); err != nil {
			return nil, err
		}
		offset += int64(len(record))
		if folderReserve > 0 {
			offset += int64(folderReserve)
		}
		folders = append(folders, folder{
			dataOffset:  binary.LittleEndian.Uint32(record[0:4]),
			blocks:      binary.LittleEndian.Uint16(record[4:6]),
			compression: binary.LittleEndian.Uint16(record[6:8]),
		})
	}

	files := make([]fileRecord, 0, cFiles)
	offset = int64(coffFiles)
	for i := 0; i < int(cFiles); i++ {
		record := make([]byte, 16)
		if _, err := file.ReadAt(record, offset); err != nil {
			return nil, err
		}
		offset += int64(len(record))
		name, n, err := readCABString(file, offset)
		if err != nil {
			return nil, err
		}
		offset += int64(n)
		files = append(files, fileRecord{
			name:              normalizeCABPath(name),
			size:              binary.LittleEndian.Uint32(record[0:4]),
			uncompressedStart: binary.LittleEndian.Uint32(record[4:8]),
			folder:            binary.LittleEndian.Uint16(record[8:10]),
		})
	}
	fileIndex := make(map[string]int, len(files)*2)
	for i, file := range files {
		addCABIndexEntry(fileIndex, file.name, i)
		addCABIndexEntry(fileIndex, strings.TrimPrefix(file.name, "/"), i)
	}
	return &Archive{
		file: file, files: files, fileIndex: fileIndex, folders: folders,
		dataReserve: dataReserve, flags: flags, setID: setID, cabinet: cabinet,
		previous: previous, next: next, cache: cache, cacheStore: store, cacheSource: source,
	}, nil
}

func (c *Archive) String() string       { return "<cab>" }
func (c *Archive) Type() string         { return "cab" }
func (c *Archive) Freeze()              {}
func (c *Archive) Truth() starlark.Bool { return starlark.True }
func (c *Archive) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", c.Type())
}
func (c *Archive) Get(key starlark.Value) (starlark.Value, bool, error) {
	name, ok := starlark.AsString(key)
	if !ok {
		return nil, false, nil
	}
	cleaned := path.Clean("/" + strings.TrimPrefix(name, "/"))
	if cleaned != "/" {
		file, err := c.lookup(cleaned)
		if err != nil {
			return nil, false, err
		}
		return file, true, nil
	}
	return c.list(), true, nil
}
func (c *Archive) Attr(name string) (starlark.Value, error) {
	if name == "files" {
		return c.list(), nil
	}
	if name == "find" {
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
func (c *Archive) AttrNames() []string {
	return []string{"files", "find"}
}
func (c *Archive) list() *starlark.List {
	values := make([]starlark.Value, len(c.files))
	for i, file := range c.files {
		values[i] = starlark.String(file.name)
	}
	return starlark.NewList(values)
}

// Files returns cabinet members in archive order.
func (c *Archive) Files() []FileInfo {
	files := make([]FileInfo, len(c.files))
	for i, file := range c.files {
		files[i] = FileInfo{Name: file.name, Size: int64(file.size)}
	}
	return files
}

// Lookup returns a random-access view of a named cabinet member.
func (c *Archive) Lookup(name string) (*Entry, error) {
	value, err := c.lookup(name)
	if err != nil {
		return nil, err
	}
	return value.(*Entry), nil
}

// ResolveResourcesBySHA1 decodes each relevant cabinet folder once, hashes
// all members in that folder, and retains only requested content. Both the
// largest transient folder and the total retained bytes are explicitly
// bounded; no host files or disk cache are involved.
func (c *Archive) ResolveResourcesBySHA1(wanted map[[20]byte]struct{}, maximumFolderBytes, maximumResourceBytes int64) ([]ContentResource, error) {
	if maximumResourceBytes < 0 {
		return nil, fmt.Errorf("cab: negative resource bound")
	}
	var result []ContentResource
	var retained int64
	err := c.VisitResourcesBySHA1(wanted, maximumFolderBytes, nil, func(name string, digest [20]byte, data []byte) error {
		if retained+int64(len(data)) > maximumResourceBytes {
			return fmt.Errorf("cab: selected resources exceed %d-byte bound", maximumResourceBytes)
		}
		owned := bytes.Clone(data)
		result = append(result, ContentResource{Name: name, SHA1: digest, Data: owned})
		retained += int64(len(owned))
		return nil
	})
	return result, err
}

// VisitResourcesBySHA1 decodes each relevant folder once and visits requested
// members. data is borrowed and remains valid only until visit returns. An
// optional shared budget bounds folder bytes across concurrent archives.
func (c *Archive) VisitResourcesBySHA1(wanted map[[20]byte]struct{}, maximumFolderBytes int64, budget MemoryBudget, visit func(name string, digest [20]byte, data []byte) error) error {
	if maximumFolderBytes < 0 {
		return fmt.Errorf("cab: negative folder bound")
	}
	remaining := make(map[[20]byte]struct{}, len(wanted))
	for digest := range wanted {
		remaining[digest] = struct{}{}
	}
	for folderIndex := range c.folders {
		if len(remaining) == 0 {
			break
		}
		folderSize := int64(0)
		for _, file := range c.files {
			if int(file.folder) != folderIndex {
				continue
			}
			end := int64(file.uncompressedStart) + int64(file.size)
			if end > folderSize {
				folderSize = end
			}
		}
		if folderSize == 0 {
			continue
		}
		if folderSize > maximumFolderBytes {
			return fmt.Errorf("cab: folder %d size %d exceeds %d-byte bound", folderIndex, folderSize, maximumFolderBytes)
		}
		if budget != nil {
			if err := budget.Acquire(folderSize); err != nil {
				return fmt.Errorf("cab: folder %d memory: %w", folderIndex, err)
			}
		}
		err := func() error {
			if budget != nil {
				defer budget.Release(folderSize)
			}
			folder, err := c.folderData(folderIndex)
			if err != nil {
				return fmt.Errorf("cab: folder %d: %w", folderIndex, err)
			}
			for _, file := range c.files {
				if int(file.folder) != folderIndex {
					continue
				}
				start := int64(file.uncompressedStart)
				end := start + int64(file.size)
				if start < 0 || end < start || end > int64(len(folder)) {
					return fmt.Errorf("cab: member %q exceeds folder %d", file.name, folderIndex)
				}
				digest := sha1.Sum(folder[start:end])
				if _, found := remaining[digest]; !found {
					continue
				}
				if err := visit(file.name, digest, folder[start:end]); err != nil {
					return err
				}
				delete(remaining, digest)
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

func readCABString(file storage.Reader, offset int64) (string, int, error) {
	var data []byte
	buf := make([]byte, 64)
	for {
		n, err := file.ReadAt(buf, offset+int64(len(data)))
		if err != nil && err != io.EOF {
			return "", 0, err
		}
		if n > 0 {
			chunk := buf[:n]
			if end := bytes.IndexByte(chunk, 0); end >= 0 {
				data = append(data, chunk[:end]...)
				return string(data), len(data) + 1, nil
			}
			data = append(data, chunk...)
		}
		if err == io.EOF {
			return "", 0, fmt.Errorf("cab: unterminated string")
		}
	}
}

func normalizeCABPath(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	return path.Clean("/" + strings.TrimPrefix(name, "/"))
}

func (c *Archive) lookup(name string) (starlark.Value, error) {
	cleaned := normalizeCABPath(name)
	if i, ok := c.fileIndex[strings.ToLower(cleaned)]; ok {
		return &Entry{archive: c, file: c.files[i]}, nil
	}
	if i, ok := c.fileIndex[strings.ToLower(strings.TrimPrefix(cleaned, "/"))]; ok {
		return &Entry{archive: c, file: c.files[i]}, nil
	}
	return nil, fmt.Errorf("cab: path %q not found", name)
}

func addCABIndexEntry(index map[string]int, name string, i int) {
	key := strings.ToLower(name)
	if _, exists := index[key]; !exists {
		index[key] = i
	}
}

type Entry struct {
	archive      *Archive
	file         fileRecord
	uncachedOnce sync.Once
	uncachedData []byte
	uncachedErr  error
}

// Bytes materializes this entry, honoring the archive cache policy.
func (f *Entry) Bytes() ([]byte, error) { return f.data() }

func (f *Entry) data() ([]byte, error) {
	if f.archive.cache {
		return f.archive.fileData(f.file)
	}
	f.uncachedOnce.Do(func() {
		data, err := f.archive.fileData(f.file)
		if err == nil {
			// A file slice otherwise retains the entire decompressed CAB folder.
			// Keep only the entry while this random-access file remains reachable.
			data = bytes.Clone(data)
		}
		f.uncachedData, f.uncachedErr = data, err
	})
	return f.uncachedData, f.uncachedErr
}

func (f *Entry) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset")
	}
	if off >= f.Size() {
		return 0, io.EOF
	}
	data, err := f.data()
	if err != nil {
		return 0, fmt.Errorf("cab entry %q: %w", f.file.name, err)
	}
	n := copy(p, data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
func (f *Entry) WriteTo(w io.Writer) (int64, error) {
	data, err := f.data()
	if err != nil {
		return 0, fmt.Errorf("cab entry %q: %w", f.file.name, err)
	}
	return io.Copy(w, bytes.NewReader(data))
}
func (f *Entry) WriteAt(_ []byte, _ int64) (int, error) {
	return 0, fmt.Errorf("cab entry %q is read-only", f.file.name)
}
func (f *Entry) Size() int64 { return int64(f.file.size) }
func (f *Entry) String() string {
	return fmt.Sprintf("<cab.file %q size=%d>", f.file.name, f.Size())
}
func (f *Entry) Type() string         { return "file" }
func (f *Entry) Freeze()              {}
func (f *Entry) Truth() starlark.Bool { return starlark.True }
func (f *Entry) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", f.Type())
}
func (f *Entry) Attr(name string) (starlark.Value, error) {
	return starfile.Attr(f, name), nil
}
func (f *Entry) AttrNames() []string {
	return starfile.AttrNames()
}

func (c *Archive) fileData(file fileRecord) ([]byte, error) {
	if int(file.folder) >= len(c.folders) {
		return nil, fmt.Errorf("cab: invalid folder index")
	}
	folder, err := c.folderData(int(file.folder))
	if err != nil {
		return nil, err
	}
	start := int(file.uncompressedStart)
	end := start + int(file.size)
	if start < 0 || end > len(folder) {
		return nil, fmt.Errorf("cab: file %q extends past folder data", file.name)
	}
	return folder[start:end], nil
}

func (c *Archive) folderData(index int) ([]byte, error) {
	if !c.cache {
		return c.readFolderData(c.folders[index])
	}
	return c.cacheStore.Get(bytecache.Key{
		Source: c.cacheSource,
		Kind:   1,
		Index:  index,
	}, func() ([]byte, error) {
		return c.readFolderData(c.folders[index])
	})
}

func (c *Archive) readFolderData(folder folder) ([]byte, error) {
	switch folder.compression & 0x000f {
	case 0:
		return c.readFolderBlocks(folder, false)
	case 1:
		return c.readFolderBlocks(folder, true)
	case 2:
		blocks, err := c.readFolderDataBlocks(folder)
		if err != nil {
			return nil, err
		}
		return quantumDecompressCAB(blocks, int(folder.compression>>8)&0x1f)
	case 3:
		return c.readLZXFolderBlocks(folder)
	default:
		return nil, fmt.Errorf("cab: unsupported compression type 0x%x", folder.compression)
	}
}

func (c *Archive) readLZXFolderBlocks(folder folder) ([]byte, error) {
	windowBits := int(folder.compression >> 8)
	decoderInput, totalOutput, err := c.readFolderPayload(folder)
	if err != nil {
		return nil, err
	}
	if totalOutput == 0 {
		for _, file := range c.files {
			if file.folder == 0 {
				totalOutput += int(file.size)
			}
		}
	}
	return lzx.Decompress(decoderInput, windowBits, totalOutput)
}

// readFolderPayload joins an LZX bitstream directly while reading CFDATA.
// Keeping one payload avoids allocating one byte slice per 32 KiB data block
// and then copying the entire compressed folder into a second slice.
func (c *Archive) readFolderPayload(folder folder) ([]byte, int, error) {
	capacity := int(folder.blocks) * (32 << 10)
	if capacity < 0 || int64(capacity) > c.file.Size() {
		capacity = int(min(c.file.Size(), int64(^uint(0)>>1)))
	}
	payload := make([]byte, 0, capacity)
	totalOutput := 0
	offset := int64(folder.dataOffset)
	var header [8]byte
	reserved := make([]byte, c.dataReserve)
	for index := 0; index < int(folder.blocks); index++ {
		if _, err := c.file.ReadAt(header[:], offset); err != nil {
			return nil, 0, err
		}
		offset += int64(len(header))
		if len(reserved) != 0 {
			if _, err := c.file.ReadAt(reserved, offset); err != nil {
				return nil, 0, err
			}
			offset += int64(len(reserved))
		}
		compressedSize := int(binary.LittleEndian.Uint16(header[4:6]))
		uncompressedSize := int(binary.LittleEndian.Uint16(header[6:8]))
		start := len(payload)
		payload = append(payload, make([]byte, compressedSize)...)
		if _, err := c.file.ReadAt(payload[start:], offset); err != nil {
			return nil, 0, err
		}
		offset += int64(compressedSize)
		totalOutput += uncompressedSize
	}
	return payload, totalOutput, nil
}

func (c *Archive) readFolderBlocks(folder folder, mszip bool) ([]byte, error) {
	blocks, err := c.readFolderDataBlocks(folder)
	if err != nil {
		return nil, err
	}
	return decodeCABBlocks(blocks, mszip)
}

func (c *Archive) readFolderDataBlocks(folder folder) ([]dataBlock, error) {
	blocks := make([]dataBlock, 0, folder.blocks)
	offset := int64(folder.dataOffset)
	for i := 0; i < int(folder.blocks); i++ {
		header := make([]byte, 8+c.dataReserve)
		if _, err := c.file.ReadAt(header, offset); err != nil {
			return nil, err
		}
		offset += int64(len(header))
		compressedSize := int(binary.LittleEndian.Uint16(header[4:6]))
		uncompressedSize := int(binary.LittleEndian.Uint16(header[6:8]))
		block := make([]byte, compressedSize)
		if _, err := c.file.ReadAt(block, offset); err != nil {
			return nil, err
		}
		offset += int64(compressedSize)
		blocks = append(blocks, dataBlock{compressed: block, uncompressed: uncompressedSize})
	}
	return blocks, nil
}

func cabinetBlocksPayload(blocks []dataBlock) ([]byte, int) {
	compressedTotal := 0
	totalOutput := 0
	for _, block := range blocks {
		compressedTotal += len(block.compressed)
		totalOutput += block.uncompressed
	}
	payload := make([]byte, 0, compressedTotal)
	for _, block := range blocks {
		payload = append(payload, block.compressed...)
	}
	return payload, totalOutput
}

func decodeCABBlocks(blocks []dataBlock, mszip bool) ([]byte, error) {
	blocks, err := mergeSplitCABDataBlocks(blocks)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if !mszip {
		for _, block := range blocks {
			out.Write(block.compressed)
		}
		return out.Bytes(), nil
	}
	for index := 0; index < len(blocks); {
		if len(blocks[index].compressed) < 2 || string(blocks[index].compressed[:2]) != "CK" {
			return nil, fmt.Errorf("cab: invalid MSZIP block")
		}
		compressed := append([]byte(nil), blocks[index].compressed[2:]...)
		expected := blocks[index].uncompressed
		history := out.Bytes()
		if len(history) > 1<<15 {
			history = history[len(history)-(1<<15):]
		}
		var lastErr error
		for end := index; end < len(blocks); end++ {
			if end > index {
				block := blocks[end]
				if len(block.compressed) < 2 || string(block.compressed[:2]) != "CK" {
					return nil, fmt.Errorf("cab: invalid MSZIP block")
				}
				compressed = append(compressed, block.compressed[2:]...)
				expected += block.uncompressed
			}
			decoded, decodeErr := mszipcompression.Decode(compressed, history, expected)
			if decodeErr == nil {
				out.Write(decoded)
				index = end + 1
				lastErr = nil
				break
			}
			lastErr = decodeErr
		}
		if lastErr != nil {
			return nil, fmt.Errorf("cab: MSZIP block %d: %w", index, lastErr)
		}
	}
	return out.Bytes(), nil
}

func mergeSplitCABDataBlocks(blocks []dataBlock) ([]dataBlock, error) {
	merged := make([]dataBlock, 0, len(blocks))
	var pending []byte
	for _, block := range blocks {
		if len(pending) > 0 {
			pending = append(pending, block.compressed...)
		} else {
			pending = append([]byte(nil), block.compressed...)
		}
		if block.uncompressed == 0 {
			continue
		}
		merged = append(merged, dataBlock{compressed: pending, uncompressed: block.uncompressed})
		pending = nil
	}
	if len(pending) > 0 {
		return nil, fmt.Errorf("cab: unterminated split data block")
	}
	return merged, nil
}
