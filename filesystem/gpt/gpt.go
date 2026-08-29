package gpt

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"sort"
	"strings"
	"sync"
	"unicode/utf16"

	filesystemapi "github.com/tinyrange/trex/filesystem"
	fsinternal "github.com/tinyrange/trex/filesystem/internal"
	starfile "github.com/tinyrange/trex/storage/star"
	windowsguid "github.com/tinyrange/trex/windows/guid"
	"go.starlark.net/starlark"
)

const (
	gptSectorSize      = int64(512)
	gptEntryCount      = 128
	gptEntrySize       = 128
	gptEntryArrayBytes = gptEntryCount * gptEntrySize
	gptEntryArrayLBAs  = gptEntryArrayBytes / int(gptSectorSize)
	gptFirstUsableLBA  = int64(2 + gptEntryArrayLBAs)
	gptDefaultStartLBA = int64(2048)
)

const gptBasicDataType = "{EBD0A0A2-B9E5-4433-87C0-68B6B72699C7}"

type gptPartition struct {
	file       starfile.File
	typeGUID   [16]byte
	uniqueGUID [16]byte
	startLBA   int64
	endLBA     int64
	attributes uint64
	name       string
}

type gptBuilder struct {
	size       int64
	diskGUID   [16]byte
	partitions []gptPartition

	once  sync.Once
	image starfile.File
	err   error
}

func GPTBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var source starlark.Value
	var diskGUIDText string
	if err := starlark.UnpackArgs("gpt", args, kwargs, "source", &source, "disk_guid?", &diskGUIDText); err != nil {
		return nil, err
	}
	if file, ok := source.(starfile.File); ok {
		if diskGUIDText != "" {
			return nil, fmt.Errorf("gpt: disk_guid is only valid when building an image")
		}
		return newGPTVolume(file)
	}
	var size int64
	if err := starlark.AsInt(source, &size); err != nil {
		return nil, fmt.Errorf("gpt: got %s, want file or integer size", source.Type())
	}
	if size < 2*1024*1024 || size%gptSectorSize != 0 {
		return nil, fmt.Errorf("gpt: size must be a sector-aligned value of at least 2 MiB")
	}
	if diskGUIDText == "" {
		return nil, fmt.Errorf("gpt: disk_guid is required when building an image")
	}
	diskGUID, ok := windowsguid.Parse(diskGUIDText)
	if !ok || fsinternal.ZeroGUID(diskGUID) {
		return nil, fmt.Errorf("gpt: invalid disk_guid %q", diskGUIDText)
	}
	return &gptBuilder{size: size, diskGUID: diskGUID}, nil
}

type gptReadPartition struct {
	typeGUID   [16]byte
	uniqueGUID [16]byte
	startLBA   int64
	endLBA     int64
	attributes uint64
	name       string
	file       starfile.File
}

type gptVolume struct {
	file       starfile.File
	diskGUID   [16]byte
	partitions []gptReadPartition
	paths      map[string]starfile.File
	files      *starlark.List
}

func newGPTVolume(file starfile.File) (*gptVolume, error) {
	if file.Size() < 3*gptSectorSize {
		return nil, fmt.Errorf("gpt: image is too small")
	}
	header, err := fsinternal.ReadBytesAt(file, gptSectorSize, gptSectorSize)
	if err != nil {
		return nil, fmt.Errorf("gpt: read header: %w", err)
	}
	if string(header[0:8]) != "EFI PART" {
		return nil, fmt.Errorf("gpt: invalid header signature")
	}
	headerSize := int(binary.LittleEndian.Uint32(header[12:16]))
	if headerSize < 92 || headerSize > len(header) {
		return nil, fmt.Errorf("gpt: invalid header size %d", headerSize)
	}
	wantHeaderCRC := binary.LittleEndian.Uint32(header[16:20])
	headerCopy := append([]byte(nil), header[:headerSize]...)
	clear(headerCopy[16:20])
	if crc32.ChecksumIEEE(headerCopy) != wantHeaderCRC {
		return nil, fmt.Errorf("gpt: header checksum mismatch")
	}
	currentLBA := binary.LittleEndian.Uint64(header[24:32])
	backupLBA := binary.LittleEndian.Uint64(header[32:40])
	if currentLBA != 1 || backupLBA >= uint64(file.Size()/gptSectorSize) {
		return nil, fmt.Errorf("gpt: invalid header LBA values")
	}
	var diskGUID [16]byte
	copy(diskGUID[:], header[56:72])
	if fsinternal.ZeroGUID(diskGUID) {
		return nil, fmt.Errorf("gpt: zero disk GUID")
	}
	entryLBA := binary.LittleEndian.Uint64(header[72:80])
	entryCount := binary.LittleEndian.Uint32(header[80:84])
	entrySize := binary.LittleEndian.Uint32(header[84:88])
	if entryCount == 0 || entryCount > 4096 || entrySize < 128 || entrySize > 4096 || entrySize%8 != 0 {
		return nil, fmt.Errorf("gpt: invalid partition entry geometry")
	}
	tableSize := int64(entryCount) * int64(entrySize)
	tableOffset := int64(entryLBA) * gptSectorSize
	table, err := fsinternal.ReadBytesAt(file, tableOffset, tableSize)
	if err != nil {
		return nil, fmt.Errorf("gpt: read partition table: %w", err)
	}
	if crc32.ChecksumIEEE(table) != binary.LittleEndian.Uint32(header[88:92]) {
		return nil, fmt.Errorf("gpt: partition table checksum mismatch")
	}
	volume := &gptVolume{file: file, diskGUID: diskGUID, paths: make(map[string]starfile.File)}
	fileNames := make([]starlark.Value, 0)
	for index := uint32(0); index < entryCount; index++ {
		entry := table[int(index*entrySize):int((index+1)*entrySize)]
		var typeGUID [16]byte
		copy(typeGUID[:], entry[0:16])
		if fsinternal.ZeroGUID(typeGUID) {
			continue
		}
		var uniqueGUID [16]byte
		copy(uniqueGUID[:], entry[16:32])
		startLBA := int64(binary.LittleEndian.Uint64(entry[32:40]))
		endLBA := int64(binary.LittleEndian.Uint64(entry[40:48]))
		if fsinternal.ZeroGUID(uniqueGUID) || startLBA < 0 || endLBA < startLBA || endLBA >= file.Size()/gptSectorSize {
			return nil, fmt.Errorf("gpt: invalid partition entry %d", index+1)
		}
		nameUnits := make([]uint16, 0, 36)
		for offset := 56; offset+1 < 128; offset += 2 {
			unit := binary.LittleEndian.Uint16(entry[offset : offset+2])
			if unit == 0 {
				break
			}
			nameUnits = append(nameUnits, unit)
		}
		partitionSize := (endLBA - startLBA + 1) * gptSectorSize
		partitionFile := &starfile.Slice{
			Name: fmt.Sprintf("%s partition %d", file.String(), index+1),
			Base: file, Offset: startLBA * gptSectorSize, Length: partitionSize,
		}
		path := fmt.Sprintf("/partition%d", index+1)
		volume.partitions = append(volume.partitions, gptReadPartition{
			typeGUID: typeGUID, uniqueGUID: uniqueGUID,
			startLBA: startLBA, endLBA: endLBA,
			attributes: binary.LittleEndian.Uint64(entry[48:56]),
			name:       string(utf16.Decode(nameUnits)), file: partitionFile,
		})
		volume.paths[path] = partitionFile
		fileNames = append(fileNames, starlark.String(path))
	}
	volume.files = starlark.NewList(fileNames)
	return volume, nil
}

func (v *gptVolume) String() string        { return fmt.Sprintf("<gpt partitions=%d>", len(v.partitions)) }
func (v *gptVolume) Type() string          { return "gpt" }
func (v *gptVolume) Freeze()               {}
func (v *gptVolume) Truth() starlark.Bool  { return starlark.True }
func (v *gptVolume) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", v.Type()) }
func (v *gptVolume) AttrNames() []string   { return []string{"disk_guid", "files", "partitions"} }
func (v *gptVolume) Attr(name string) (starlark.Value, error) {
	switch name {
	case "disk_guid":
		return starlark.String(windowsguid.Format(v.diskGUID)), nil
	case "files":
		return v.files, nil
	case "partitions":
		items := make([]starlark.Value, 0, len(v.partitions))
		for index, partition := range v.partitions {
			item := starlark.NewDict(8)
			values := map[string]starlark.Value{
				"index": starlark.MakeInt(index + 1), "file": partition.file,
				"type_guid":      starlark.String(windowsguid.Format(partition.typeGUID)),
				"partition_guid": starlark.String(windowsguid.Format(partition.uniqueGUID)),
				"start_lba":      starlark.MakeInt64(partition.startLBA),
				"end_lba":        starlark.MakeInt64(partition.endLBA),
				"attributes":     starlark.MakeUint64(partition.attributes),
				"name":           starlark.String(partition.name),
				"offset":         starlark.MakeInt64(partition.startLBA * gptSectorSize),
				"size":           starlark.MakeInt64((partition.endLBA - partition.startLBA + 1) * gptSectorSize),
			}
			for key, value := range values {
				_ = item.SetKey(starlark.String(key), value)
			}
			items = append(items, item)
		}
		return starlark.NewList(items), nil
	}
	return nil, nil
}
func (v *gptVolume) Get(key starlark.Value) (starlark.Value, bool, error) {
	name, ok := starlark.AsString(key)
	if !ok {
		return nil, false, fmt.Errorf("gpt: key is %s, want string", key.Type())
	}
	name = "/" + strings.Trim(strings.ReplaceAll(name, "\\", "/"), "/")
	if name == "/" {
		return v, true, nil
	}
	file, ok := v.paths[name]
	if !ok {
		return nil, false, nil
	}
	return file, true, nil
}

func (b *gptBuilder) String() string {
	return fmt.Sprintf("<gpt size=%d partitions=%d>", b.size, len(b.partitions))
}
func (b *gptBuilder) Type() string         { return "file" }
func (b *gptBuilder) Freeze()              {}
func (b *gptBuilder) Truth() starlark.Bool { return starlark.True }
func (b *gptBuilder) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", b.Type())
}
func (b *gptBuilder) Attr(name string) (starlark.Value, error) {
	if name == "partition" {
		return starlark.NewBuiltin("partition", b.partitionBuiltin), nil
	}
	return starfile.Attr(b, name), nil
}
func (b *gptBuilder) AttrNames() []string {
	return append(starfile.AttrNames(), "partition")
}

func (b *gptBuilder) partitionBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	typeGUIDText := gptBasicDataType
	var partitionGUIDText string
	name := ""
	startLBA := 0
	attributes := uint64(0)
	if err := starlark.UnpackArgs(
		"partition", args, kwargs,
		"filesystem", &value,
		"partition_guid", &partitionGUIDText,
		"type_guid?", &typeGUIDText,
		"name?", &name,
		"start_lba?", &startLBA,
		"attributes?", &attributes,
	); err != nil {
		return nil, err
	}
	partition, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("partition: got %s, want file", value.Type())
	}
	typeGUID, ok := fsinternal.ParseGUID(typeGUIDText)
	if !ok || fsinternal.ZeroGUID(typeGUID) {
		return nil, fmt.Errorf("partition: invalid type_guid %q", typeGUIDText)
	}
	partitionGUID, ok := fsinternal.ParseGUID(partitionGUIDText)
	if !ok || fsinternal.ZeroGUID(partitionGUID) {
		return nil, fmt.Errorf("partition: invalid partition_guid %q", partitionGUIDText)
	}
	return b.withPartition(partition, typeGUID, partitionGUID, name, int64(startLBA), attributes)
}

func (b *gptBuilder) withPartition(file starfile.File, typeGUID, partitionGUID [16]byte, name string, startLBA int64, attributes uint64) (*gptBuilder, error) {
	if file.Size() <= 0 {
		return nil, fmt.Errorf("partition: filesystem must not be empty")
	}
	if len(utf16.Encode([]rune(name))) > 36 {
		return nil, fmt.Errorf("partition: name exceeds 36 UTF-16 code units")
	}
	if len(b.partitions) >= gptEntryCount {
		return nil, fmt.Errorf("partition: GPT supports at most %d partitions", gptEntryCount)
	}
	for _, existing := range b.partitions {
		if existing.uniqueGUID == partitionGUID {
			return nil, fmt.Errorf("partition: duplicate partition_guid %s", fsinternal.FormatGUID(partitionGUID))
		}
	}
	if startLBA == 0 {
		startLBA = gptDefaultStartLBA
		for _, existing := range b.partitions {
			candidate := fsinternal.Align(existing.endLBA+1, gptDefaultStartLBA)
			if candidate > startLBA {
				startLBA = candidate
			}
		}
	}
	lastUsable := b.size/gptSectorSize - 34
	sectors := fsinternal.CeilDiv(file.Size(), gptSectorSize)
	endLBA := startLBA + sectors - 1
	if startLBA < gptFirstUsableLBA || endLBA > lastUsable || endLBA < startLBA {
		return nil, fmt.Errorf("partition: LBA range %d-%d is outside GPT usable range %d-%d", startLBA, endLBA, gptFirstUsableLBA, lastUsable)
	}
	for _, existing := range b.partitions {
		if startLBA <= existing.endLBA && endLBA >= existing.startLBA {
			return nil, fmt.Errorf("partition: LBA range %d-%d overlaps %d-%d", startLBA, endLBA, existing.startLBA, existing.endLBA)
		}
	}
	clone := &gptBuilder{size: b.size, diskGUID: b.diskGUID}
	clone.partitions = append(clone.partitions, b.partitions...)
	clone.partitions = append(clone.partitions, gptPartition{
		file: file, typeGUID: typeGUID, uniqueGUID: partitionGUID,
		startLBA: startLBA, endLBA: endLBA, attributes: attributes, name: name,
	})
	return clone, nil
}

func (b *gptBuilder) ReadAt(p []byte, off int64) (int, error) {
	image, err := b.generated()
	if err != nil {
		return 0, err
	}
	return image.ReadAt(p, off)
}
func (b *gptBuilder) WriteAt(_ []byte, _ int64) (int, error) {
	return 0, fmt.Errorf("gpt.raw is read-only")
}
func (b *gptBuilder) WriteTo(w io.Writer) (int64, error) {
	image, err := b.generated()
	if err != nil {
		return 0, err
	}
	return io.Copy(w, io.NewSectionReader(image, 0, image.Size()))
}
func (b *gptBuilder) Size() int64 { return b.size }

func (b *gptBuilder) generated() (starfile.File, error) {
	b.once.Do(func() {
		b.image, b.err = b.build()
	})
	return b.image, b.err
}

func (b *gptBuilder) build() (starfile.File, error) {
	if len(b.partitions) == 0 {
		return nil, fmt.Errorf("gpt: disk has no partitions")
	}
	partitions := append([]gptPartition(nil), b.partitions...)
	sort.Slice(partitions, func(i, j int) bool { return partitions[i].startLBA < partitions[j].startLBA })
	entries := make([]byte, gptEntryArrayBytes)
	for index, partition := range partitions {
		entry := entries[index*gptEntrySize : (index+1)*gptEntrySize]
		copy(entry[0:16], partition.typeGUID[:])
		copy(entry[16:32], partition.uniqueGUID[:])
		binary.LittleEndian.PutUint64(entry[32:40], uint64(partition.startLBA))
		binary.LittleEndian.PutUint64(entry[40:48], uint64(partition.endLBA))
		binary.LittleEndian.PutUint64(entry[48:56], partition.attributes)
		for offset, value := range utf16.Encode([]rune(partition.name)) {
			binary.LittleEndian.PutUint16(entry[56+offset*2:], value)
		}
	}
	entryCRC := crc32.ChecksumIEEE(entries)
	totalSectors := b.size / gptSectorSize
	lastLBA := totalSectors - 1
	backupEntriesLBA := lastLBA - int64(gptEntryArrayLBAs)
	primary := b.header(1, lastLBA, 2, entryCRC)
	backup := b.header(lastLBA, 1, backupEntriesLBA, entryCRC)
	extents := []filesystemapi.ExtentSpec{
		{Start: 0, Size: gptSectorSize, Data: protectiveMBR(totalSectors)},
		{Start: gptSectorSize, Size: gptSectorSize, Data: primary},
		{Start: 2 * gptSectorSize, Size: int64(len(entries)), Data: entries},
		{Start: backupEntriesLBA * gptSectorSize, Size: int64(len(entries)), Data: entries},
		{Start: lastLBA * gptSectorSize, Size: gptSectorSize, Data: backup},
	}
	for _, partition := range partitions {
		extents = append(extents, filesystemapi.ExtentSpec{
			Start: partition.startLBA * gptSectorSize,
			Size:  partition.file.Size(),
			File:  partition.file,
		})
	}
	return filesystemapi.NewGeneratedImage("gpt.raw", b.size, extents), nil
}

func (b *gptBuilder) header(currentLBA, backupLBA, entriesLBA int64, entryCRC uint32) []byte {
	header := make([]byte, gptSectorSize)
	copy(header[0:8], "EFI PART")
	binary.LittleEndian.PutUint32(header[8:12], 0x00010000)
	binary.LittleEndian.PutUint32(header[12:16], 92)
	binary.LittleEndian.PutUint64(header[24:32], uint64(currentLBA))
	binary.LittleEndian.PutUint64(header[32:40], uint64(backupLBA))
	binary.LittleEndian.PutUint64(header[40:48], uint64(gptFirstUsableLBA))
	binary.LittleEndian.PutUint64(header[48:56], uint64(b.size/gptSectorSize-34))
	copy(header[56:72], b.diskGUID[:])
	binary.LittleEndian.PutUint64(header[72:80], uint64(entriesLBA))
	binary.LittleEndian.PutUint32(header[80:84], gptEntryCount)
	binary.LittleEndian.PutUint32(header[84:88], gptEntrySize)
	binary.LittleEndian.PutUint32(header[88:92], entryCRC)
	binary.LittleEndian.PutUint32(header[16:20], crc32.ChecksumIEEE(header[:92]))
	return header
}

func protectiveMBR(totalSectors int64) []byte {
	sector := make([]byte, gptSectorSize)
	entry := sector[446:462]
	entry[1], entry[2], entry[3] = 0x00, 0x02, 0x00
	entry[4] = 0xee
	entry[5], entry[6], entry[7] = 0xff, 0xff, 0xff
	binary.LittleEndian.PutUint32(entry[8:12], 1)
	sectors := uint64(totalSectors - 1)
	if sectors > uint64(^uint32(0)) {
		sectors = uint64(^uint32(0))
	}
	binary.LittleEndian.PutUint32(entry[12:16], uint32(sectors))
	sector[510], sector[511] = 0x55, 0xaa
	return sector
}

var _ starfile.File = (*gptBuilder)(nil)
