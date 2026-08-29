package udf

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
	udfBlockSize             = int64(2048)
	udfTagAnchor             = 2
	udfTagPartition          = 5
	udfTagLogicalVolume      = 6
	udfTagTerminating        = 8
	udfTagFileSet            = 256
	udfTagFileIdentifier     = 257
	udfTagFileEntry          = 261
	udfTagExtendedFileEntry  = 266
	udfFileCharDirectory     = 0x02
	udfFileCharDeleted       = 0x04
	udfFileCharParent        = 0x08
	udfFileTypeDirectory     = 4
	udfFileTypeRegular       = 5
	udfAllocShortDescriptors = 0
	udfAllocLongDescriptors  = 1
	udfAllocEmbedded         = 3
)

func UDFBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("udf", args, kwargs, "file", &value); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("udf: got %s, want file", value.Type())
	}
	return newUDFImage(file)
}

type udfImage struct {
	file          starfile.File
	logicalBlock  int64
	anchorSector  int64
	vdsOffset     int64
	vdsSize       int64
	partitions    map[uint16]udfPartition
	partitionMaps map[uint16]uint16
	root          udfFileEntry
	rootPath      string
}

type udfPartition struct {
	number uint16
	start  uint32
	length uint32
}

type udfExtent struct {
	partition uint16
	block     uint32
	length    uint32
	flags     uint8
}

type udfFileEntry struct {
	name     string
	path     string
	typ      uint8
	size     int64
	embedded []byte
	extents  []udfExtent
}

type udfVirtualEntry struct {
	name   string
	offset int64
	size   int64
}

func newUDFImage(file starfile.File) (*udfImage, error) {
	img := &udfImage{
		file:          file,
		logicalBlock:  udfBlockSize,
		partitions:    make(map[uint16]udfPartition),
		partitionMaps: make(map[uint16]uint16),
	}
	anchor, sector, err := img.readAnchor()
	if err != nil {
		return nil, err
	}
	img.anchorSector = sector
	img.vdsSize = int64(binary.LittleEndian.Uint32(anchor[16:20]))
	img.vdsOffset = int64(binary.LittleEndian.Uint32(anchor[20:24])) * img.logicalBlock
	if img.vdsSize <= 0 {
		return nil, fmt.Errorf("udf: empty volume descriptor sequence")
	}
	fileSet, err := img.readVolumeDescriptors()
	if err != nil {
		return nil, err
	}
	rootICB, err := img.readFileSetDescriptor(fileSet)
	if err != nil {
		return nil, err
	}
	root, err := img.readFileEntry(rootICB, "/")
	if err != nil {
		return nil, err
	}
	root.name = "/"
	root.path = "/"
	img.root = root
	return img, nil
}

func (i *udfImage) String() string       { return "<udf>" }
func (i *udfImage) Type() string         { return "udf" }
func (i *udfImage) Freeze()              {}
func (i *udfImage) Truth() starlark.Bool { return starlark.True }
func (i *udfImage) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", i.Type())
}
func (i *udfImage) Get(key starlark.Value) (starlark.Value, bool, error) {
	name, ok := starlark.AsString(key)
	if !ok {
		return nil, false, nil
	}
	cleaned := storage.CleanPath(name)
	if file := i.virtualFile(cleaned); file != nil {
		return file, true, nil
	}
	if cleaned == "/$metadata" {
		return &udfMetadataDirectory{image: i}, true, nil
	}
	if cleaned == "/" {
		return &udfDirectory{image: i, entry: i.root}, true, nil
	}
	entry, err := i.lookup(cleaned)
	if err != nil {
		return nil, false, err
	}
	if entry.isDir() {
		return &udfDirectory{image: i, entry: entry}, true, nil
	}
	return &udfFile{image: i, entry: entry}, true, nil
}

func (i *udfImage) readAnchor() ([]byte, int64, error) {
	sectors := []int64{256}
	if i.file.Size() > udfBlockSize*512 {
		last := i.file.Size()/udfBlockSize - 1
		sectors = append(sectors, last, last-256)
	}
	for _, sector := range sectors {
		if sector < 0 {
			continue
		}
		block := make([]byte, udfBlockSize)
		if _, err := i.file.ReadAt(block, sector*udfBlockSize); err != nil && err != io.EOF {
			continue
		}
		if udfTagID(block) == udfTagAnchor {
			return block, sector, nil
		}
	}
	return nil, 0, fmt.Errorf("udf: anchor volume descriptor pointer not found")
}

func (i *udfImage) readVolumeDescriptors() (udfExtent, error) {
	data := make([]byte, i.vdsSize)
	if _, err := i.file.ReadAt(data, i.vdsOffset); err != nil && err != io.EOF {
		return udfExtent{}, err
	}
	var fileSet udfExtent
	for off := 0; off+int(i.logicalBlock) <= len(data); off += int(i.logicalBlock) {
		block := data[off : off+int(i.logicalBlock)]
		switch udfTagID(block) {
		case udfTagPartition:
			if len(block) < 196 {
				return udfExtent{}, fmt.Errorf("udf: short partition descriptor")
			}
			number := binary.LittleEndian.Uint16(block[22:24])
			i.partitions[number] = udfPartition{
				number: number,
				start:  binary.LittleEndian.Uint32(block[188:192]),
				length: binary.LittleEndian.Uint32(block[192:196]),
			}
		case udfTagLogicalVolume:
			if len(block) < 440 {
				return udfExtent{}, fmt.Errorf("udf: short logical volume descriptor")
			}
			i.logicalBlock = int64(binary.LittleEndian.Uint32(block[212:216]))
			if i.logicalBlock <= 0 {
				return udfExtent{}, fmt.Errorf("udf: invalid logical block size")
			}
			fileSet = udfLongAD(block[248:264])
			mapLen := int(binary.LittleEndian.Uint32(block[264:268]))
			mapCount := int(binary.LittleEndian.Uint32(block[268:272]))
			maps := block[440:]
			if mapLen > len(maps) {
				return udfExtent{}, fmt.Errorf("udf: partition map table exceeds descriptor")
			}
			if err := i.readPartitionMaps(maps[:mapLen], mapCount); err != nil {
				return udfExtent{}, err
			}
		case udfTagTerminating:
			if fileSet.length == 0 {
				return udfExtent{}, fmt.Errorf("udf: logical volume descriptor not found")
			}
			return fileSet, nil
		}
	}
	if fileSet.length == 0 {
		return udfExtent{}, fmt.Errorf("udf: logical volume descriptor not found")
	}
	return fileSet, nil
}

func (i *udfImage) readPartitionMaps(data []byte, count int) error {
	for idx, off := 0, 0; idx < count && off+2 <= len(data); idx++ {
		mapType := data[off]
		mapLen := int(data[off+1])
		if mapLen <= 0 || off+mapLen > len(data) {
			return fmt.Errorf("udf: invalid partition map")
		}
		if mapType == 1 && mapLen >= 6 {
			num := binary.LittleEndian.Uint16(data[off+4 : off+6])
			i.partitionMaps[uint16(idx)] = num
		}
		off += mapLen
	}
	return nil
}

func (i *udfImage) readFileSetDescriptor(extent udfExtent) (udfExtent, error) {
	data, err := i.readExtent(extent, int64(extent.length))
	if err != nil {
		return udfExtent{}, err
	}
	if len(data) < 416 || udfTagID(data) != udfTagFileSet {
		return udfExtent{}, fmt.Errorf("udf: invalid file set descriptor")
	}
	return udfLongAD(data[400:416]), nil
}

func (i *udfImage) lookup(name string) (udfFileEntry, error) {
	current := i.root
	for _, part := range strings.Split(strings.TrimPrefix(storage.CleanPath(name), "/"), "/") {
		if part == "" {
			continue
		}
		if !current.isDir() {
			return udfFileEntry{}, fmt.Errorf("udf: path %q not found", name)
		}
		children, err := i.readDir(current)
		if err != nil {
			return udfFileEntry{}, err
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
			return udfFileEntry{}, fmt.Errorf("udf: path %q not found", name)
		}
	}
	return current, nil
}

func (i *udfImage) readDir(dir udfFileEntry) ([]udfFileEntry, error) {
	data, err := i.readFileData(dir)
	if err != nil {
		return nil, err
	}
	var entries []udfFileEntry
	for off := 0; off+38 <= len(data); {
		if udfTagID(data[off:]) != udfTagFileIdentifier {
			break
		}
		nameLen := int(data[off+19])
		chars := data[off+18]
		useLen := int(binary.LittleEndian.Uint16(data[off+36 : off+38]))
		size := align4(38 + useLen + nameLen)
		if off+size > len(data) {
			return nil, fmt.Errorf("udf: invalid file identifier descriptor")
		}
		if chars&(udfFileCharDeleted|udfFileCharParent) != 0 {
			off += size
			continue
		}
		name := udfDecodeOSTA(data[off+38+useLen : off+38+useLen+nameLen])
		if name == "" {
			off += size
			continue
		}
		icb := udfLongAD(data[off+20 : off+36])
		childPath := path.Join(dir.path, name)
		entry, err := i.readFileEntry(icb, childPath)
		if err != nil {
			return nil, err
		}
		entry.name = name
		entry.path = childPath
		if chars&udfFileCharDirectory != 0 && !entry.isDir() {
			entry.typ = udfFileTypeDirectory
		}
		entries = append(entries, entry)
		off += size
	}
	sort.Slice(entries, func(a, b int) bool {
		if entries[a].isDir() != entries[b].isDir() {
			return entries[a].isDir()
		}
		return strings.ToLower(entries[a].name) < strings.ToLower(entries[b].name)
	})
	return entries, nil
}

func (i *udfImage) readFileEntry(icb udfExtent, name string) (udfFileEntry, error) {
	data, err := i.readExtent(icb, int64(icb.length))
	if err != nil {
		return udfFileEntry{}, err
	}
	tag := udfTagID(data)
	if tag != udfTagFileEntry && tag != udfTagExtendedFileEntry {
		return udfFileEntry{}, fmt.Errorf("udf: invalid file entry tag %d", tag)
	}
	if len(data) < 176 {
		return udfFileEntry{}, fmt.Errorf("udf: short file entry")
	}
	icbTag := data[16:36]
	typ := icbTag[11]
	flags := binary.LittleEndian.Uint16(icbTag[18:20])
	allocType := int(flags & 0x0007)
	size := int64(binary.LittleEndian.Uint64(data[56:64]))
	var eaOff, adOff int
	var eaLen, adLen uint32
	if tag == udfTagExtendedFileEntry {
		if len(data) < 216 {
			return udfFileEntry{}, fmt.Errorf("udf: short extended file entry")
		}
		eaOff = 216
		eaLen = binary.LittleEndian.Uint32(data[208:212])
		adLen = binary.LittleEndian.Uint32(data[212:216])
	} else {
		eaOff = 176
		eaLen = binary.LittleEndian.Uint32(data[168:172])
		adLen = binary.LittleEndian.Uint32(data[172:176])
	}
	adOff = eaOff + int(eaLen)
	if adOff+int(adLen) > len(data) {
		return udfFileEntry{}, fmt.Errorf("udf: allocation descriptors exceed file entry")
	}
	entry := udfFileEntry{name: path.Base(name), path: storage.CleanPath(name), typ: typ, size: size}
	ads := data[adOff : adOff+int(adLen)]
	switch allocType {
	case udfAllocEmbedded:
		entry.embedded = append([]byte(nil), ads...)
		if int64(len(entry.embedded)) > entry.size {
			entry.embedded = entry.embedded[:entry.size]
		}
	case udfAllocShortDescriptors:
		for off := 0; off+8 <= len(ads); off += 8 {
			ext := udfShortAD(ads[off : off+8])
			if ext.length > 0 {
				entry.extents = append(entry.extents, ext)
			}
		}
	case udfAllocLongDescriptors:
		for off := 0; off+16 <= len(ads); off += 16 {
			ext := udfLongAD(ads[off : off+16])
			if ext.length > 0 {
				entry.extents = append(entry.extents, ext)
			}
		}
	default:
		return udfFileEntry{}, fmt.Errorf("udf: unsupported allocation descriptor type %d", allocType)
	}
	return entry, nil
}

func (i *udfImage) readFileData(entry udfFileEntry) ([]byte, error) {
	if entry.embedded != nil {
		data := append([]byte(nil), entry.embedded...)
		if int64(len(data)) > entry.size {
			data = data[:entry.size]
		}
		return data, nil
	}
	data := make([]byte, 0, entry.size)
	for _, extent := range entry.extents {
		if extent.flags != 0 {
			continue
		}
		chunk, err := i.readExtent(extent, min(int64(extent.length), entry.size-int64(len(data))))
		if err != nil {
			return nil, err
		}
		data = append(data, chunk...)
		if int64(len(data)) >= entry.size {
			break
		}
	}
	if int64(len(data)) > entry.size {
		data = data[:entry.size]
	}
	return data, nil
}

func (i *udfImage) readFileAt(entry udfFileEntry, p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset")
	}
	if off >= entry.size {
		return 0, io.EOF
	}
	requested := len(p)
	if remaining := entry.size - off; int64(len(p)) > remaining {
		p = p[:remaining]
	}
	if entry.embedded != nil {
		n := copy(p, entry.embedded[off:])
		if n < requested {
			return n, io.EOF
		}
		return n, nil
	}
	done := 0
	position := int64(0)
	for _, extent := range entry.extents {
		extentSize := int64(extent.length)
		if off >= position+extentSize {
			position += extentSize
			continue
		}
		if done >= len(p) {
			break
		}
		startInExtent := int64(0)
		if off > position {
			startInExtent = off - position
		}
		toRead := min(extentSize-startInExtent, int64(len(p)-done))
		if toRead <= 0 {
			position += extentSize
			continue
		}
		if extent.flags != 0 {
			clear(p[done : done+int(toRead)])
		} else {
			extentOffset, err := i.extentOffset(extent)
			if err != nil {
				return done, err
			}
			n, err := i.file.ReadAt(p[done:done+int(toRead)], extentOffset+startInExtent)
			done += n
			if err != nil && err != io.EOF {
				return done, err
			}
			if int64(n) < toRead {
				return done, io.EOF
			}
			position += extentSize
			continue
		}
		done += int(toRead)
		position += extentSize
	}
	if done < requested {
		return done, io.EOF
	}
	return done, nil
}

func (i *udfImage) readExtent(extent udfExtent, size int64) ([]byte, error) {
	if size < 0 {
		size = int64(extent.length)
	}
	if size > int64(extent.length) {
		size = int64(extent.length)
	}
	offset, err := i.extentOffset(extent)
	if err != nil {
		return nil, err
	}
	data := make([]byte, size)
	if _, err := i.file.ReadAt(data, offset); err != nil && err != io.EOF {
		return nil, err
	}
	return data, nil
}

func (i *udfImage) extentOffset(extent udfExtent) (int64, error) {
	partNumber, ok := i.partitionMaps[extent.partition]
	if !ok {
		partNumber = extent.partition
	}
	part, ok := i.partitions[partNumber]
	if !ok {
		return 0, fmt.Errorf("udf: partition reference %d not found", extent.partition)
	}
	return int64(part.start+extent.block) * i.logicalBlock, nil
}

func (i *udfImage) virtualEntries() []udfVirtualEntry {
	return []udfVirtualEntry{
		{name: "/$metadata/anchor.bin", offset: i.anchorSector * udfBlockSize, size: udfBlockSize},
		{name: "/$metadata/volume_descriptor_sequence.bin", offset: i.vdsOffset, size: i.vdsSize},
	}
}

func (i *udfImage) virtualFile(name string) starfile.File {
	for _, entry := range i.virtualEntries() {
		if strings.EqualFold(entry.name, name) {
			return &udfRegionFile{image: i, name: entry.name, offset: entry.offset, size: entry.size}
		}
	}
	return nil
}

func (e udfFileEntry) isDir() bool {
	return e.typ == udfFileTypeDirectory
}

func udfTagID(data []byte) uint16 {
	if len(data) < 2 {
		return 0xffff
	}
	return binary.LittleEndian.Uint16(data[0:2])
}

func udfShortAD(data []byte) udfExtent {
	lengthAndFlags := binary.LittleEndian.Uint32(data[0:4])
	return udfExtent{
		length: lengthAndFlags & 0x3fffffff,
		flags:  uint8(lengthAndFlags >> 30),
		block:  binary.LittleEndian.Uint32(data[4:8]),
	}
}

func udfLongAD(data []byte) udfExtent {
	lengthAndFlags := binary.LittleEndian.Uint32(data[0:4])
	return udfExtent{
		length:    lengthAndFlags & 0x3fffffff,
		flags:     uint8(lengthAndFlags >> 30),
		block:     binary.LittleEndian.Uint32(data[4:8]),
		partition: binary.LittleEndian.Uint16(data[8:10]),
	}
}

func udfDecodeOSTA(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	switch data[0] {
	case 8:
		return strings.TrimRight(string(data[1:]), "\x00")
	case 16:
		codepoints := make([]uint16, 0, (len(data)-1)/2)
		for off := 1; off+1 < len(data); off += 2 {
			v := binary.BigEndian.Uint16(data[off : off+2])
			if v == 0 {
				continue
			}
			codepoints = append(codepoints, v)
		}
		return string(utf16.Decode(codepoints))
	default:
		return strings.TrimRight(string(data), "\x00")
	}
}

func align4(n int) int {
	return (n + 3) &^ 3
}

type udfDirectory struct {
	image *udfImage
	entry udfFileEntry
}

func (d *udfDirectory) String() string {
	files, err := d.files()
	if err != nil {
		return fmt.Sprintf("<udf.dir %q read error: %v>", d.entry.path, err)
	}
	return files.String()
}
func (d *udfDirectory) Type() string         { return "directory" }
func (d *udfDirectory) Freeze()              {}
func (d *udfDirectory) Truth() starlark.Bool { return starlark.True }
func (d *udfDirectory) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", d.Type())
}
func (d *udfDirectory) Attr(name string) (starlark.Value, error) {
	if name == "files" {
		return d.files()
	}
	return nil, nil
}
func (d *udfDirectory) AttrNames() []string { return []string{"files"} }
func (d *udfDirectory) files() (*starlark.List, error) {
	children, err := d.image.readDir(d.entry)
	if err != nil {
		return nil, err
	}
	extra := 0
	if d.entry.path == "/" {
		extra = 1
	}
	values := make([]starlark.Value, 0, len(children)+extra)
	if d.entry.path == "/" {
		values = append(values, starlark.String("/$metadata"))
	}
	for _, child := range children {
		values = append(values, starlark.String(child.path))
	}
	return starlark.NewList(values), nil
}

type udfMetadataDirectory struct {
	image *udfImage
}

func (d *udfMetadataDirectory) String() string {
	files, err := d.files()
	if err != nil {
		return fmt.Sprintf("<udf.metadata read error: %v>", err)
	}
	return files.String()
}
func (d *udfMetadataDirectory) Type() string         { return "directory" }
func (d *udfMetadataDirectory) Freeze()              {}
func (d *udfMetadataDirectory) Truth() starlark.Bool { return starlark.True }
func (d *udfMetadataDirectory) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", d.Type())
}
func (d *udfMetadataDirectory) Attr(name string) (starlark.Value, error) {
	if name == "files" {
		return d.files()
	}
	return nil, nil
}
func (d *udfMetadataDirectory) AttrNames() []string { return []string{"files"} }
func (d *udfMetadataDirectory) files() (*starlark.List, error) {
	entries := d.image.virtualEntries()
	values := make([]starlark.Value, len(entries))
	for idx, entry := range entries {
		values[idx] = starlark.String(entry.name)
	}
	return starlark.NewList(values), nil
}

type udfFile struct {
	image *udfImage
	entry udfFileEntry
}

func (f *udfFile) ReadAt(p []byte, off int64) (int, error) {
	return f.image.readFileAt(f.entry, p, off)
}
func (f *udfFile) WriteAt(_ []byte, _ int64) (int, error) {
	return 0, fmt.Errorf("udf entry %q is read-only", f.entry.path)
}
func (f *udfFile) Size() int64 { return f.entry.size }
func (f *udfFile) String() string {
	return fmt.Sprintf("<udf.file %q size=%d>", f.entry.path, f.Size())
}
func (f *udfFile) Type() string         { return "file" }
func (f *udfFile) Freeze()              {}
func (f *udfFile) Truth() starlark.Bool { return starlark.True }
func (f *udfFile) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", f.Type())
}
func (f *udfFile) Attr(name string) (starlark.Value, error) { return starfile.Attr(f, name), nil }
func (f *udfFile) AttrNames() []string                      { return starfile.AttrNames() }

type udfRegionFile struct {
	image  *udfImage
	name   string
	offset int64
	size   int64
}

func (f *udfRegionFile) ReadAt(p []byte, off int64) (int, error) {
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
func (f *udfRegionFile) WriteAt(_ []byte, _ int64) (int, error) {
	return 0, fmt.Errorf("udf metadata %q is read-only", f.name)
}
func (f *udfRegionFile) Size() int64 { return f.size }
func (f *udfRegionFile) String() string {
	return fmt.Sprintf("<udf.metadata %q size=%d>", f.name, f.Size())
}
func (f *udfRegionFile) Type() string         { return "file" }
func (f *udfRegionFile) Freeze()              {}
func (f *udfRegionFile) Truth() starlark.Bool { return starlark.True }
func (f *udfRegionFile) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", f.Type())
}
func (f *udfRegionFile) Attr(name string) (starlark.Value, error) {
	return starfile.Attr(f, name), nil
}
func (f *udfRegionFile) AttrNames() []string { return starfile.AttrNames() }
