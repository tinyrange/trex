package fat

import (
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"io"
	"path"
	"sort"
	"strings"
	"unicode/utf16"

	"go.starlark.net/starlark"
)

const (
	fatAttrReadOnly = 0x01
	fatAttrHidden   = 0x02
	fatAttrSystem   = 0x04
	fatAttrVolumeID = 0x08
	fatAttrDir      = 0x10
	fatAttrArchive  = 0x20
	fatAttrLFN      = fatAttrReadOnly | fatAttrHidden | fatAttrSystem | fatAttrVolumeID
)

func FATBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("fat", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("fat: got %s, want file", value.Type())
	}
	return newFATImage(file)
}

type fatImage struct {
	file              starfile.File
	bytesPerSector    int64
	sectorsPerCluster int64
	reservedSectors   int64
	fats              int64
	rootEntries       int64
	totalSectors      int64
	sectorsPerFAT     int64
	rootDirSectors    int64
	fatOffset         int64
	rootDirOffset     int64
	dataOffset        int64
	rootCluster       uint32
	fatType           int
	fat               []byte
}

type fatDirEntry struct {
	name    string
	path    string
	attr    byte
	cluster uint32
	size    int64
}

func newFATImage(file starfile.File) (*fatImage, error) {
	sector := make([]byte, 512)
	if _, err := file.ReadAt(sector, 0); err != nil {
		return nil, err
	}
	if sector[510] != 0x55 || sector[511] != 0xaa {
		return nil, fmt.Errorf("fat: missing boot sector signature")
	}
	bytesPerSector := int64(binary.LittleEndian.Uint16(sector[11:13]))
	sectorsPerCluster := int64(sector[13])
	reservedSectors := int64(binary.LittleEndian.Uint16(sector[14:16]))
	fats := int64(sector[16])
	rootEntries := int64(binary.LittleEndian.Uint16(sector[17:19]))
	totalSectors := int64(binary.LittleEndian.Uint16(sector[19:21]))
	sectorsPerFAT := int64(binary.LittleEndian.Uint16(sector[22:24]))
	if totalSectors == 0 {
		totalSectors = int64(binary.LittleEndian.Uint32(sector[32:36]))
	}
	if sectorsPerFAT == 0 {
		sectorsPerFAT = int64(binary.LittleEndian.Uint32(sector[36:40]))
	}
	rootCluster := binary.LittleEndian.Uint32(sector[44:48])
	if rootCluster == 0 {
		rootCluster = 2
	}
	if bytesPerSector <= 0 || bytesPerSector%512 != 0 || sectorsPerCluster <= 0 || reservedSectors <= 0 || fats <= 0 || totalSectors <= 0 || sectorsPerFAT <= 0 {
		return nil, fmt.Errorf("fat: invalid BIOS parameter block")
	}
	rootDirSectors := ((rootEntries * 32) + (bytesPerSector - 1)) / bytesPerSector
	dataSectors := totalSectors - (reservedSectors + fats*sectorsPerFAT + rootDirSectors)
	if dataSectors <= 0 {
		return nil, fmt.Errorf("fat: invalid data area")
	}
	clusters := dataSectors / sectorsPerCluster
	fatType := 32
	if clusters < 4085 {
		fatType = 12
	} else if clusters < 65525 {
		fatType = 16
	}
	fatOffset := reservedSectors * bytesPerSector
	rootDirOffset := fatOffset + fats*sectorsPerFAT*bytesPerSector
	dataOffset := rootDirOffset + rootDirSectors*bytesPerSector
	fat := make([]byte, sectorsPerFAT*bytesPerSector)
	if _, err := file.ReadAt(fat, fatOffset); err != nil && err != io.EOF {
		return nil, err
	}
	return &fatImage{
		file:              file,
		bytesPerSector:    bytesPerSector,
		sectorsPerCluster: sectorsPerCluster,
		reservedSectors:   reservedSectors,
		fats:              fats,
		rootEntries:       rootEntries,
		totalSectors:      totalSectors,
		sectorsPerFAT:     sectorsPerFAT,
		rootDirSectors:    rootDirSectors,
		fatOffset:         fatOffset,
		rootDirOffset:     rootDirOffset,
		dataOffset:        dataOffset,
		rootCluster:       rootCluster,
		fatType:           fatType,
		fat:               fat,
	}, nil
}

func (i *fatImage) String() string       { return fmt.Sprintf("<fat%d>", i.fatType) }
func (i *fatImage) Type() string         { return "fat" }
func (i *fatImage) Freeze()              {}
func (i *fatImage) Truth() starlark.Bool { return starlark.True }
func (i *fatImage) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", i.Type())
}
func (i *fatImage) Get(key starlark.Value) (starlark.Value, bool, error) {
	name, ok := starlark.AsString(key)
	if !ok {
		return nil, false, nil
	}
	cleaned := storage.CleanPath(name)
	if file := i.virtualFile(cleaned); file != nil {
		return file, true, nil
	}
	if cleaned == "/$metadata" {
		return &fatMetadataDirectory{image: i}, true, nil
	}
	if cleaned == "/" {
		return &fatDirectory{image: i, name: "/", entry: i.rootEntry()}, true, nil
	}
	entry, err := i.lookup(cleaned)
	if err != nil {
		return nil, false, err
	}
	if entry.isDir() {
		return &fatDirectory{image: i, name: cleaned, entry: entry}, true, nil
	}
	return &fatFile{image: i, entry: entry}, true, nil
}

func (i *fatImage) virtualEntries() []fatVirtualEntry {
	entries := []fatVirtualEntry{
		{name: "/$metadata/boot_sector.bin", offset: 0, size: i.bytesPerSector},
	}
	for fat := int64(0); fat < i.fats; fat++ {
		entries = append(entries, fatVirtualEntry{
			name:   fmt.Sprintf("/$metadata/fat%d.bin", fat+1),
			offset: i.fatOffset + fat*i.sectorsPerFAT*i.bytesPerSector,
			size:   i.sectorsPerFAT * i.bytesPerSector,
		})
	}
	if i.fatType != 32 && i.rootDirSectors > 0 {
		entries = append(entries, fatVirtualEntry{
			name:   "/$metadata/root_directory.bin",
			offset: i.rootDirOffset,
			size:   i.rootDirSectors * i.bytesPerSector,
		})
	}
	return entries
}

func (i *fatImage) virtualFile(name string) starfile.File {
	for _, entry := range i.virtualEntries() {
		if strings.EqualFold(entry.name, name) {
			return &fatRegionFile{image: i, name: entry.name, offset: entry.offset, size: entry.size}
		}
	}
	return nil
}

type fatVirtualEntry struct {
	name   string
	offset int64
	size   int64
}

func (i *fatImage) rootEntry() fatDirEntry {
	return fatDirEntry{name: "/", path: "/", attr: fatAttrDir, cluster: i.rootCluster}
}

func (i *fatImage) lookup(name string) (fatDirEntry, error) {
	current := i.rootEntry()
	for _, part := range strings.Split(strings.TrimPrefix(name, "/"), "/") {
		if part == "" {
			continue
		}
		entries, err := i.readDir(current)
		if err != nil {
			return fatDirEntry{}, err
		}
		found := false
		for _, entry := range entries {
			if strings.EqualFold(entry.name, part) {
				current = entry
				found = true
				break
			}
		}
		if !found {
			return fatDirEntry{}, fmt.Errorf("fat: path %q not found", name)
		}
	}
	return current, nil
}

func (i *fatImage) readDir(dir fatDirEntry) ([]fatDirEntry, error) {
	var data []byte
	var err error
	if dir.path == "/" && i.fatType != 32 {
		data = make([]byte, i.rootDirSectors*i.bytesPerSector)
		_, err = i.file.ReadAt(data, i.rootDirOffset)
	} else {
		data, err = i.readClusterChain(dir.cluster, -1)
	}
	if err != nil && err != io.EOF {
		return nil, err
	}
	return parseFATDirectory(data, dir.path, i.fatType), nil
}

func parseFATDirectory(data []byte, base string, fatType int) []fatDirEntry {
	var entries []fatDirEntry
	var lfn []string
	for offset := 0; offset+32 <= len(data); offset += 32 {
		raw := data[offset : offset+32]
		if raw[0] == 0x00 {
			break
		}
		if raw[0] == 0xe5 {
			lfn = nil
			continue
		}
		attr := raw[11]
		if attr == fatAttrLFN {
			part := fatLongNamePart(raw)
			if part != "" {
				lfn = append([]string{part}, lfn...)
			}
			continue
		}
		if attr&fatAttrVolumeID != 0 {
			lfn = nil
			continue
		}
		name := strings.Join(lfn, "")
		lfn = nil
		if name == "" {
			name = fatShortName(raw[0:11])
		}
		if name == "" || name == "." || name == ".." {
			continue
		}
		cluster := uint32(binary.LittleEndian.Uint16(raw[26:28]))
		if fatType == 32 {
			cluster |= uint32(binary.LittleEndian.Uint16(raw[20:22])) << 16
		}
		entry := fatDirEntry{
			name:    name,
			path:    path.Join(base, name),
			attr:    attr,
			cluster: cluster,
			size:    int64(binary.LittleEndian.Uint32(raw[28:32])),
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(a, b int) bool {
		if entries[a].isDir() != entries[b].isDir() {
			return entries[a].isDir()
		}
		return strings.ToLower(entries[a].name) < strings.ToLower(entries[b].name)
	})
	return entries
}

func fatLongNamePart(raw []byte) string {
	codepoints := make([]uint16, 0, 13)
	for _, pair := range [][2]int{{1, 10}, {14, 25}, {28, 31}} {
		for offset := pair[0]; offset+1 <= pair[1]; offset += 2 {
			v := binary.LittleEndian.Uint16(raw[offset : offset+2])
			if v == 0x0000 || v == 0xffff {
				continue
			}
			codepoints = append(codepoints, v)
		}
	}
	return string(utf16.Decode(codepoints))
}

func fatShortName(raw []byte) string {
	name := strings.TrimSpace(string(raw[:8]))
	ext := strings.TrimSpace(string(raw[8:11]))
	if raw[0] == 0x05 {
		name = string([]byte{0xe5}) + name[1:]
	}
	if ext != "" {
		return name + "." + ext
	}
	return name
}

func (e fatDirEntry) isDir() bool {
	return e.attr&fatAttrDir != 0
}

func (i *fatImage) readClusterChain(start uint32, size int64) ([]byte, error) {
	if start < 2 {
		return nil, nil
	}
	clusterSize := i.bytesPerSector * i.sectorsPerCluster
	var out []byte
	for cluster := start; ; {
		offset := i.clusterOffset(cluster)
		buf := make([]byte, clusterSize)
		if _, err := i.file.ReadAt(buf, offset); err != nil && err != io.EOF {
			return nil, err
		}
		out = append(out, buf...)
		if size >= 0 && int64(len(out)) >= size {
			return out[:size], nil
		}
		next, err := i.nextCluster(cluster)
		if err != nil {
			return nil, err
		}
		if i.isEndCluster(next) {
			break
		}
		if next < 2 {
			return nil, fmt.Errorf("fat: invalid cluster chain")
		}
		cluster = next
	}
	if size >= 0 && int64(len(out)) > size {
		out = out[:size]
	}
	return out, nil
}

func (i *fatImage) clusterOffset(cluster uint32) int64 {
	return i.dataOffset + int64(cluster-2)*i.sectorsPerCluster*i.bytesPerSector
}

func (i *fatImage) nextCluster(cluster uint32) (uint32, error) {
	switch i.fatType {
	case 12:
		offset := int(cluster + cluster/2)
		if offset+1 >= len(i.fat) {
			return 0, fmt.Errorf("fat: cluster %d is outside FAT", cluster)
		}
		value := uint32(i.fat[offset]) | uint32(i.fat[offset+1])<<8
		if cluster%2 == 0 {
			return value & 0x0fff, nil
		}
		return value >> 4, nil
	case 16:
		offset := int(cluster) * 2
		if offset+1 >= len(i.fat) {
			return 0, fmt.Errorf("fat: cluster %d is outside FAT", cluster)
		}
		return uint32(binary.LittleEndian.Uint16(i.fat[offset : offset+2])), nil
	case 32:
		offset := int(cluster) * 4
		if offset+3 >= len(i.fat) {
			return 0, fmt.Errorf("fat: cluster %d is outside FAT", cluster)
		}
		return binary.LittleEndian.Uint32(i.fat[offset:offset+4]) & 0x0fffffff, nil
	default:
		return 0, fmt.Errorf("fat: unsupported FAT type")
	}
}

func (i *fatImage) isEndCluster(cluster uint32) bool {
	switch i.fatType {
	case 12:
		return cluster >= 0x0ff8
	case 16:
		return cluster >= 0xfff8
	case 32:
		return cluster >= 0x0ffffff8
	default:
		return true
	}
}

type fatDirectory struct {
	image *fatImage
	name  string
	entry fatDirEntry
}

func (d *fatDirectory) String() string {
	files, err := d.files()
	if err != nil {
		return fmt.Sprintf("<fat.dir %q read error: %v>", d.name, err)
	}
	return files.String()
}
func (d *fatDirectory) Type() string         { return "directory" }
func (d *fatDirectory) Freeze()              {}
func (d *fatDirectory) Truth() starlark.Bool { return starlark.True }
func (d *fatDirectory) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", d.Type())
}
func (d *fatDirectory) Attr(name string) (starlark.Value, error) {
	if name == "files" {
		return d.files()
	}
	return nil, nil
}
func (d *fatDirectory) AttrNames() []string {
	return []string{"files"}
}
func (d *fatDirectory) files() (*starlark.List, error) {
	entries, err := d.image.readDir(d.entry)
	if err != nil {
		return nil, err
	}
	extra := 0
	if d.entry.path == "/" {
		extra = 1
	}
	values := make([]starlark.Value, 0, len(entries)+extra)
	if d.entry.path == "/" {
		values = append(values, starlark.String("/$metadata"))
	}
	for _, entry := range entries {
		values = append(values, starlark.String(entry.path))
	}
	return starlark.NewList(values), nil
}

type fatMetadataDirectory struct {
	image *fatImage
}

func (d *fatMetadataDirectory) String() string {
	files, err := d.files()
	if err != nil {
		return fmt.Sprintf("<fat.metadata read error: %v>", err)
	}
	return files.String()
}
func (d *fatMetadataDirectory) Type() string         { return "directory" }
func (d *fatMetadataDirectory) Freeze()              {}
func (d *fatMetadataDirectory) Truth() starlark.Bool { return starlark.True }
func (d *fatMetadataDirectory) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", d.Type())
}
func (d *fatMetadataDirectory) Attr(name string) (starlark.Value, error) {
	if name == "files" {
		return d.files()
	}
	return nil, nil
}
func (d *fatMetadataDirectory) AttrNames() []string {
	return []string{"files"}
}
func (d *fatMetadataDirectory) files() (*starlark.List, error) {
	entries := d.image.virtualEntries()
	values := make([]starlark.Value, len(entries))
	for idx, entry := range entries {
		values[idx] = starlark.String(entry.name)
	}
	return starlark.NewList(values), nil
}

type fatFile struct {
	image *fatImage
	entry fatDirEntry
}

func (f *fatFile) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset")
	}
	if off >= f.Size() {
		return 0, io.EOF
	}
	data, err := f.image.readClusterChain(f.entry.cluster, f.entry.size)
	if err != nil {
		return 0, err
	}
	n := copy(p, data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
func (f *fatFile) WriteAt(_ []byte, _ int64) (int, error) {
	return 0, fmt.Errorf("fat entry %q is read-only", f.entry.path)
}
func (f *fatFile) Size() int64 { return f.entry.size }
func (f *fatFile) String() string {
	return fmt.Sprintf("<fat.file %q size=%d>", f.entry.path, f.Size())
}
func (f *fatFile) Type() string         { return "file" }
func (f *fatFile) Freeze()              {}
func (f *fatFile) Truth() starlark.Bool { return starlark.True }
func (f *fatFile) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", f.Type())
}
func (f *fatFile) Attr(name string) (starlark.Value, error) {
	return starfile.Attr(f, name), nil
}
func (f *fatFile) AttrNames() []string { return starfile.AttrNames() }

type fatRegionFile struct {
	image  *fatImage
	name   string
	offset int64
	size   int64
}

func (f *fatRegionFile) ReadAt(p []byte, off int64) (int, error) {
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
func (f *fatRegionFile) WriteAt(_ []byte, _ int64) (int, error) {
	return 0, fmt.Errorf("fat metadata %q is read-only", f.name)
}
func (f *fatRegionFile) Size() int64 { return f.size }
func (f *fatRegionFile) String() string {
	return fmt.Sprintf("<fat.metadata %q size=%d>", f.name, f.Size())
}
func (f *fatRegionFile) Type() string         { return "file" }
func (f *fatRegionFile) Freeze()              {}
func (f *fatRegionFile) Truth() starlark.Bool { return starlark.True }
func (f *fatRegionFile) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", f.Type())
}
func (f *fatRegionFile) Attr(name string) (starlark.Value, error) {
	return starfile.Attr(f, name), nil
}
func (f *fatRegionFile) AttrNames() []string { return starfile.AttrNames() }
