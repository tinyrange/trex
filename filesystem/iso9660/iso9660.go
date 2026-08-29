package iso9660

import (
	"encoding/binary"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"io"
	"path"
	"strings"
	"sync"
	"unicode/utf16"

	"go.starlark.net/starlark"
)

func ISO9660Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("iso", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("iso: got %s, want file", value.Type())
	}
	return newISOImage(file)
}

type isoImage struct {
	file        starfile.File
	root        isoDirRecord
	bootCatalog int64
	mu          sync.Mutex
	dirCache    map[uint32][]isoDirRecord
	dirIndex    map[uint32]map[string]isoDirRecord
	pathCache   map[string]isoDirRecord
	joliet      bool
}

type isoDirRecord struct {
	name   string
	extent uint32
	size   uint32
	flags  byte
}

func newISOImage(file starfile.File) (*isoImage, error) {
	sector := make([]byte, 2048)
	img := &isoImage{
		file:      file,
		dirCache:  make(map[uint32][]isoDirRecord),
		dirIndex:  make(map[uint32]map[string]isoDirRecord),
		pathCache: make(map[string]isoDirRecord),
	}
	for i := int64(16); ; i++ {
		if _, err := file.ReadAt(sector, i*2048); err != nil {
			return nil, err
		}
		if string(sector[1:6]) != "CD001" {
			return nil, fmt.Errorf("invalid ISO9660 volume descriptor")
		}
		switch sector[0] {
		case 1:
			root, err := parseISODirRecordWithEncoding(sector[156:], false)
			if err != nil {
				return nil, err
			}
			if !img.joliet {
				img.root = root
				img.pathCache["/"] = root
			}
		case 2:
			if !isJolietDescriptor(sector) {
				continue
			}
			root, err := parseISODirRecordWithEncoding(sector[156:], true)
			if err != nil {
				return nil, err
			}
			img.root = root
			img.joliet = true
			img.pathCache["/"] = root
		case 0:
			if strings.TrimRight(string(sector[7:39]), "\x00 ") == "EL TORITO SPECIFICATION" {
				img.bootCatalog = int64(binary.LittleEndian.Uint32(sector[71:75]))
			}
		case 255:
			if img.root.size == 0 {
				return nil, fmt.Errorf("ISO9660 primary volume descriptor not found")
			}
			return img, nil
		}
	}
}

func (i *isoImage) String() string       { return "<iso>" }
func (i *isoImage) Type() string         { return "iso" }
func (i *isoImage) Freeze()              {}
func (i *isoImage) Truth() starlark.Bool { return starlark.True }
func (i *isoImage) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", i.Type())
}
func (i *isoImage) AttrNames() []string { return []string{"find"} }
func (i *isoImage) Attr(name string) (starlark.Value, error) {
	if name != "find" {
		return nil, nil
	}
	return starlark.NewBuiltin("find", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var name string
		if err := starlark.UnpackArgs("find", args, kwargs, "path", &name); err != nil {
			return nil, err
		}
		value, found, err := i.Get(starlark.String(name))
		if err != nil || !found {
			return starlark.None, nil
		}
		return value, nil
	}), nil
}
func (i *isoImage) Get(key starlark.Value) (starlark.Value, bool, error) {
	name, ok := starlark.AsString(key)
	if !ok {
		return nil, false, nil
	}
	cleaned := path.Clean("/" + strings.TrimPrefix(name, "/"))
	if file := i.virtualFile(cleaned); file != nil {
		return file, true, nil
	}
	if cleaned == "/$metadata" && i.bootCatalog > 0 {
		return &isoMetadataDirectory{image: i}, true, nil
	}
	if cleaned == "/" {
		return &isoDirectory{image: i, record: i.root, name: cleaned}, true, nil
	}
	record, err := i.lookup(cleaned)
	if err != nil {
		return nil, false, err
	}
	if record.isDir() {
		return &isoDirectory{image: i, record: record, name: cleaned}, true, nil
	}
	return &isoFile{image: i, record: record, name: cleaned}, true, nil
}

func (i *isoImage) virtualEntries() []isoVirtualEntry {
	if i.bootCatalog <= 0 {
		return nil
	}
	entries := []isoVirtualEntry{{
		name:   "/$metadata/boot_catalog.bin",
		offset: i.bootCatalog * 2048,
		size:   2048,
	}}
	imageOffset, imageSize, err := i.bootImage()
	if err == nil && imageSize > 0 {
		entries = append(entries, isoVirtualEntry{
			name:   "/$metadata/boot_image.bin",
			offset: imageOffset,
			size:   imageSize,
		})
	}
	return entries
}

func (i *isoImage) virtualFile(name string) starfile.File {
	for _, entry := range i.virtualEntries() {
		if strings.EqualFold(entry.name, name) {
			return &isoRegionFile{image: i, name: entry.name, offset: entry.offset, size: entry.size}
		}
	}
	return nil
}

func (i *isoImage) bootImage() (int64, int64, error) {
	catalog := make([]byte, 64)
	if _, err := i.file.ReadAt(catalog, i.bootCatalog*2048); err != nil {
		return 0, 0, err
	}
	entry := catalog[32:64]
	if entry[0] != 0x88 && entry[0] != 0x00 {
		return 0, 0, fmt.Errorf("iso: invalid boot catalog initial entry")
	}
	lba := int64(binary.LittleEndian.Uint32(entry[8:12]))
	size := int64(binary.LittleEndian.Uint16(entry[6:8])) * 512
	switch entry[1] {
	case 1:
		size = 1200 * 1024
	case 2:
		size = 1440 * 1024
	case 3:
		size = 2880 * 1024
	}
	return lba * 2048, size, nil
}

type isoVirtualEntry struct {
	name   string
	offset int64
	size   int64
}

func (i *isoImage) lookup(name string) (isoDirRecord, error) {
	cleaned := path.Clean("/" + strings.TrimPrefix(name, "/"))
	i.mu.Lock()
	if record, ok := i.pathCache[strings.ToLower(cleaned)]; ok {
		i.mu.Unlock()
		return record, nil
	}
	i.mu.Unlock()

	current := i.root
	parts := strings.Split(strings.TrimPrefix(cleaned, "/"), "/")
	for idx, part := range parts {
		if !current.isDir() {
			return isoDirRecord{}, fmt.Errorf("iso: path %q not found", name)
		}
		entry, ok, err := i.findDirEntry(current, part)
		if err != nil {
			return isoDirRecord{}, err
		}
		if !ok {
			return isoDirRecord{}, fmt.Errorf("iso: path %q not found", name)
		}
		current = entry
		if idx == len(parts)-1 {
			i.mu.Lock()
			i.pathCache[strings.ToLower(cleaned)] = current
			i.mu.Unlock()
			return current, nil
		}
	}
	return current, nil
}

func (i *isoImage) findDirEntry(dir isoDirRecord, name string) (isoDirRecord, bool, error) {
	key := dir.extent
	lookup := strings.ToLower(name)
	i.mu.Lock()
	index := i.dirIndex[key]
	if index != nil {
		record, ok := index[lookup]
		i.mu.Unlock()
		return record, ok, nil
	}
	i.mu.Unlock()

	entries, err := i.readDir(dir)
	if err != nil {
		return isoDirRecord{}, false, err
	}
	index = make(map[string]isoDirRecord, len(entries))
	for _, entry := range entries {
		index[strings.ToLower(strings.TrimPrefix(entry.name, "/"))] = entry
	}

	i.mu.Lock()
	if existing := i.dirIndex[key]; existing != nil {
		record, ok := existing[lookup]
		i.mu.Unlock()
		return record, ok, nil
	}
	i.dirIndex[key] = index
	record, ok := index[lookup]
	i.mu.Unlock()
	return record, ok, nil
}

func (i *isoImage) readDir(dir isoDirRecord) ([]isoDirRecord, error) {
	key := dir.extent
	i.mu.Lock()
	if entries := i.dirCache[key]; entries != nil {
		i.mu.Unlock()
		return entries, nil
	}
	i.mu.Unlock()

	data := make([]byte, dir.size)
	if _, err := i.file.ReadAt(data, int64(dir.extent)*2048); err != nil && err != io.EOF {
		return nil, err
	}
	var entries []isoDirRecord
	for offset := 0; offset < len(data); {
		length := int(data[offset])
		if length == 0 {
			offset = ((offset / 2048) + 1) * 2048
			continue
		}
		if offset+length > len(data) {
			return nil, fmt.Errorf("invalid ISO9660 directory record")
		}
		record, err := parseISODirRecordWithEncoding(data[offset:offset+length], i.joliet)
		if err != nil {
			return nil, err
		}
		if record.name != "" {
			entries = append(entries, record)
		}
		offset += length
	}
	i.mu.Lock()
	if cached := i.dirCache[key]; cached != nil {
		i.mu.Unlock()
		return cached, nil
	}
	i.dirCache[key] = entries
	i.mu.Unlock()
	return entries, nil
}

func parseISODirRecord(record []byte) (isoDirRecord, error) {
	return parseISODirRecordWithEncoding(record, false)
}

func parseISODirRecordWithEncoding(record []byte, joliet bool) (isoDirRecord, error) {
	if len(record) < 34 || record[0] == 0 {
		return isoDirRecord{}, fmt.Errorf("invalid ISO9660 directory record")
	}
	nameLength := int(record[32])
	nameStart := 33
	nameEnd := nameStart + nameLength
	if nameEnd > len(record) {
		return isoDirRecord{}, fmt.Errorf("invalid ISO9660 file identifier")
	}
	return isoDirRecord{
		name:   isoName(record[nameStart:nameEnd], joliet),
		extent: uint32(record[2]) | uint32(record[3])<<8 | uint32(record[4])<<16 | uint32(record[5])<<24,
		size:   uint32(record[10]) | uint32(record[11])<<8 | uint32(record[12])<<16 | uint32(record[13])<<24,
		flags:  record[25],
	}, nil
}

func (r isoDirRecord) isDir() bool {
	return r.flags&0x02 != 0
}

func isJolietDescriptor(sector []byte) bool {
	if len(sector) < 91 {
		return false
	}
	escape := string(sector[88:91])
	return escape == "%/@" || escape == "%/C" || escape == "%/E"
}

func isoName(raw []byte, joliet bool) string {
	if len(raw) == 1 && (raw[0] == 0 || raw[0] == 1) {
		return ""
	}
	name := string(raw)
	if joliet {
		units := make([]uint16, 0, len(raw)/2)
		for offset := 0; offset+1 < len(raw); offset += 2 {
			units = append(units, binary.BigEndian.Uint16(raw[offset:offset+2]))
		}
		name = string(utf16.Decode(units))
	}
	name = strings.TrimSuffix(name, ";1")
	return path.Clean("/" + name)
}

type isoDirectory struct {
	image  *isoImage
	record isoDirRecord
	name   string
}

func (d *isoDirectory) String() string {
	files, err := d.files()
	if err != nil {
		return fmt.Sprintf("<iso.dir %q read error: %v>", d.name, err)
	}
	return files.String()
}
func (d *isoDirectory) Type() string         { return "directory" }
func (d *isoDirectory) Freeze()              {}
func (d *isoDirectory) Truth() starlark.Bool { return starlark.True }
func (d *isoDirectory) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", d.Type())
}
func (d *isoDirectory) Attr(name string) (starlark.Value, error) {
	if name == "files" {
		return d.files()
	}
	return nil, nil
}
func (d *isoDirectory) AttrNames() []string {
	return []string{"files"}
}
func (d *isoDirectory) files() (*starlark.List, error) {
	entries, err := d.image.readDir(d.record)
	if err != nil {
		return nil, err
	}
	extra := 0
	if d.name == "/" && len(d.image.virtualEntries()) > 0 {
		extra = 1
	}
	values := make([]starlark.Value, 0, len(entries)+extra)
	if extra > 0 {
		values = append(values, starlark.String("/$metadata"))
	}
	for _, entry := range entries {
		values = append(values, starlark.String(path.Join(d.name, strings.TrimPrefix(entry.name, "/"))))
	}
	return starlark.NewList(values), nil
}

type isoMetadataDirectory struct {
	image *isoImage
}

func (d *isoMetadataDirectory) String() string {
	files, err := d.files()
	if err != nil {
		return fmt.Sprintf("<iso.metadata read error: %v>", err)
	}
	return files.String()
}
func (d *isoMetadataDirectory) Type() string         { return "directory" }
func (d *isoMetadataDirectory) Freeze()              {}
func (d *isoMetadataDirectory) Truth() starlark.Bool { return starlark.True }
func (d *isoMetadataDirectory) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", d.Type())
}
func (d *isoMetadataDirectory) Attr(name string) (starlark.Value, error) {
	if name == "files" {
		return d.files()
	}
	return nil, nil
}
func (d *isoMetadataDirectory) AttrNames() []string {
	return []string{"files"}
}
func (d *isoMetadataDirectory) files() (*starlark.List, error) {
	entries := d.image.virtualEntries()
	values := make([]starlark.Value, len(entries))
	for idx, entry := range entries {
		values[idx] = starlark.String(entry.name)
	}
	return starlark.NewList(values), nil
}

type isoFile struct {
	image  *isoImage
	record isoDirRecord
	name   string
}

func (f *isoFile) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset")
	}
	if off >= f.Size() {
		return 0, io.EOF
	}
	requested := len(p)
	remaining := f.Size() - off
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err := f.image.file.ReadAt(p, int64(f.record.extent)*2048+off)
	if err != nil {
		return n, err
	}
	if n < requested {
		return n, io.EOF
	}
	return n, nil
}
func (f *isoFile) WriteAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset")
	}
	if off+int64(len(p)) > f.Size() {
		return 0, fmt.Errorf("write exceeds ISO file size")
	}
	return f.image.file.WriteAt(p, int64(f.record.extent)*2048+off)
}
func (f *isoFile) Size() int64 { return int64(f.record.size) }
func (f *isoFile) String() string {
	return fmt.Sprintf("<iso.file %q size=%d>", f.name, f.Size())
}
func (f *isoFile) Type() string         { return "file" }
func (f *isoFile) Freeze()              {}
func (f *isoFile) Truth() starlark.Bool { return starlark.True }
func (f *isoFile) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", f.Type())
}
func (f *isoFile) Attr(name string) (starlark.Value, error) {
	return starfile.Attr(f, name), nil
}
func (f *isoFile) AttrNames() []string {
	return starfile.AttrNames()
}

type isoRegionFile struct {
	image  *isoImage
	name   string
	offset int64
	size   int64
}

func (f *isoRegionFile) ReadAt(p []byte, off int64) (int, error) {
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
	n, err := f.image.file.ReadAt(p, f.offset+off)
	if err != nil {
		return n, err
	}
	if n < requested {
		return n, io.EOF
	}
	return n, nil
}
func (f *isoRegionFile) WriteAt(_ []byte, _ int64) (int, error) {
	return 0, fmt.Errorf("iso metadata %q is read-only", f.name)
}
func (f *isoRegionFile) Size() int64 { return f.size }
func (f *isoRegionFile) String() string {
	return fmt.Sprintf("<iso.metadata %q size=%d>", f.name, f.Size())
}
func (f *isoRegionFile) Type() string         { return "file" }
func (f *isoRegionFile) Freeze()              {}
func (f *isoRegionFile) Truth() starlark.Bool { return starlark.True }
func (f *isoRegionFile) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", f.Type())
}
func (f *isoRegionFile) Attr(name string) (starlark.Value, error) {
	return starfile.Attr(f, name), nil
}
func (f *isoRegionFile) AttrNames() []string { return starfile.AttrNames() }
