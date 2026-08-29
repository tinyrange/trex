package fat

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"unicode/utf16"

	filesystemapi "github.com/tinyrange/trex/filesystem"
	fsinternal "github.com/tinyrange/trex/filesystem/internal"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/vmm"
	"go.starlark.net/starlark"
)

const (
	fat16ReservedSectors = int64(1)
	fat16FATs            = int64(2)
	fat16RootEntries     = int64(512)
	fat16FirstCluster    = uint32(2)
	fat16EOC             = uint16(0xffff)
)

func FAT12Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	var size int
	var bootCodeValue starlark.Value = starlark.None
	var chsValue starlark.Value = starlark.None
	var fileOrderValue *starlark.List
	hiddenSectors := 0
	label := "NO NAME"
	directoryLabel := true
	extendedBPB := false
	if err := starlark.UnpackArgs("fat12", args, kwargs, "directory", &value, "size", &size, "boot_code?", &bootCodeValue, "hidden_sectors?", &hiddenSectors, "label?", &label, "file_order?", &fileOrderValue, "directory_label?", &directoryLabel, "extended_bpb?", &extendedBPB, "chs?", &chsValue); err != nil {
		return nil, err
	}
	dir, ok := value.(*filesystemapi.Directory)
	if !ok {
		return nil, fmt.Errorf("fat12: got %s, want directory", value.Type())
	}
	if size <= 0 || size%int(fat32SectorSize) != 0 {
		return nil, fmt.Errorf("fat12: size must be a positive multiple of 512 bytes")
	}
	if hiddenSectors < 0 {
		return nil, fmt.Errorf("fat12: hidden_sectors must be non-negative")
	}
	bootCode, err := fsinternal.BootCodeBytes("fat12", bootCodeValue)
	if err != nil {
		return nil, err
	}
	if len(bootCode) > int(fat32SectorSize) {
		return nil, fmt.Errorf("fat12: boot code must fit in one sector")
	}
	volumeLabel, err := fat32VolumeLabel(label)
	if err != nil {
		return nil, fmt.Errorf("fat12: %w", err)
	}
	fileOrder, err := fsinternal.StringList(fileOrderValue, "file_order")
	if err != nil {
		return nil, fmt.Errorf("fat12: %w", err)
	}
	chs, err := fsinternal.CHSGeometry(chsValue)
	if err != nil {
		return nil, fmt.Errorf("fat12: chs: %w", err)
	}
	return buildFATImageWithOptionsAndGeometryAndBPB(dir, int64(size), bootCode, int64(hiddenSectors), volumeLabel, fileOrder, directoryLabel, extendedBPB, chs, 12)
}

func FAT16Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	var size int
	var bootCodeValue starlark.Value = starlark.None
	var chsValue starlark.Value = starlark.None
	var fileOrderValue *starlark.List
	hiddenSectors := 0
	label := "NO NAME"
	directoryLabel := true
	extendedBPB := true
	if err := starlark.UnpackArgs("fat16", args, kwargs, "directory", &value, "size", &size, "boot_code?", &bootCodeValue, "hidden_sectors?", &hiddenSectors, "label?", &label, "file_order?", &fileOrderValue, "directory_label?", &directoryLabel, "extended_bpb?", &extendedBPB, "chs?", &chsValue); err != nil {
		return nil, err
	}
	dir, ok := value.(*filesystemapi.Directory)
	if !ok {
		return nil, fmt.Errorf("fat16: got %s, want directory", value.Type())
	}
	if size <= 0 || size%int(fat32SectorSize) != 0 {
		return nil, fmt.Errorf("fat16: size must be a positive multiple of 512 bytes")
	}
	if hiddenSectors < 0 {
		return nil, fmt.Errorf("fat16: hidden_sectors must be non-negative")
	}
	bootCode, err := fsinternal.BootCodeBytes("fat16", bootCodeValue)
	if err != nil {
		return nil, err
	}
	if len(bootCode) > int(fat32SectorSize) {
		return nil, fmt.Errorf("fat16: boot code must fit in one sector")
	}
	volumeLabel, err := fat32VolumeLabel(label)
	if err != nil {
		return nil, fmt.Errorf("fat16: %w", err)
	}
	fileOrder, err := fsinternal.StringList(fileOrderValue, "file_order")
	if err != nil {
		return nil, fmt.Errorf("fat16: %w", err)
	}
	chs, err := fsinternal.CHSGeometry(chsValue)
	if err != nil {
		return nil, fmt.Errorf("fat16: chs: %w", err)
	}
	return buildFAT16ImageWithOptionsAndGeometryAndBPB(dir, int64(size), bootCode, int64(hiddenSectors), volumeLabel, fileOrder, directoryLabel, extendedBPB, chs)
}

type fat16Build struct {
	fatBits           int
	size              int64
	totalSectors      int64
	sectorsPerCluster int64
	sectorsPerFAT     int64
	rootDirSectors    int64
	dataOffset        int64
	nextCluster       uint32
	nodes             []*fat32Node
	root              *fat32Node
	bootCode          []byte
	hiddenLBA         int64
	volumeLabel       [11]byte
	directoryLabel    bool
	extendedBPB       bool
	chs               *vmm.CHSGeometry
	fat               []uint16
	dirs              map[*fat32Node][]byte
}

func buildFAT16Image(dir *filesystemapi.Directory, size int64, bootCode []byte, hiddenLBA int64, volumeLabel [11]byte) (starfile.File, error) {
	return buildFAT16ImageWithOptions(dir, size, bootCode, hiddenLBA, volumeLabel, nil, true)
}

func buildFAT16ImageWithOptions(dir *filesystemapi.Directory, size int64, bootCode []byte, hiddenLBA int64, volumeLabel [11]byte, fileOrder []string, directoryLabel bool) (starfile.File, error) {
	return buildFAT16ImageWithOptionsAndGeometry(dir, size, bootCode, hiddenLBA, volumeLabel, fileOrder, directoryLabel, nil)
}

func buildFAT16ImageWithOptionsAndGeometry(dir *filesystemapi.Directory, size int64, bootCode []byte, hiddenLBA int64, volumeLabel [11]byte, fileOrder []string, directoryLabel bool, chs *vmm.CHSGeometry) (starfile.File, error) {
	return buildFAT16ImageWithOptionsAndGeometryAndBPB(dir, size, bootCode, hiddenLBA, volumeLabel, fileOrder, directoryLabel, true, chs)
}

func buildFAT16ImageWithOptionsAndGeometryAndBPB(dir *filesystemapi.Directory, size int64, bootCode []byte, hiddenLBA int64, volumeLabel [11]byte, fileOrder []string, directoryLabel, extendedBPB bool, chs *vmm.CHSGeometry) (starfile.File, error) {
	return buildFATImageWithOptionsAndGeometryAndBPB(dir, size, bootCode, hiddenLBA, volumeLabel, fileOrder, directoryLabel, extendedBPB, chs, 16)
}

func buildFATImageWithOptionsAndGeometryAndBPB(dir *filesystemapi.Directory, size int64, bootCode []byte, hiddenLBA int64, volumeLabel [11]byte, fileOrder []string, directoryLabel, extendedBPB bool, chs *vmm.CHSGeometry, fatBits int) (starfile.File, error) {
	if fatBits != 12 && fatBits != 16 {
		return nil, fmt.Errorf("fat: unsupported allocation width %d", fatBits)
	}
	b := &fat16Build{
		fatBits:        fatBits,
		size:           size,
		totalSectors:   size / fat32SectorSize,
		nextCluster:    fat16FirstCluster,
		bootCode:       bootCode,
		hiddenLBA:      hiddenLBA,
		volumeLabel:    volumeLabel,
		directoryLabel: directoryLabel,
		extendedBPB:    extendedBPB,
		chs:            chs,
	}
	imported := &fat32Build{}
	if err := imported.importDirectory(dir); err != nil {
		return nil, err
	}
	b.nodes = imported.nodes
	b.root = imported.root
	if err := b.applyFileOrder(fileOrder); err != nil {
		return nil, err
	}
	if err := b.layout(); err != nil {
		return nil, err
	}

	extents := []filesystemapi.ExtentSpec{{Start: 0, Size: fat32SectorSize, Data: b.bootSector()}}
	fatData := b.fatBytes()
	for index := int64(0); index < fat16FATs; index++ {
		offset := (fat16ReservedSectors + index*b.sectorsPerFAT) * fat32SectorSize
		extents = append(extents, filesystemapi.ExtentSpec{Start: offset, Size: int64(len(fatData)), Data: fatData})
	}
	rootOffset := (fat16ReservedSectors + fat16FATs*b.sectorsPerFAT) * fat32SectorSize
	extents = append(extents, filesystemapi.ExtentSpec{Start: rootOffset, Size: b.rootDirSectors * fat32SectorSize, Data: b.dirs[b.root]})
	for node, data := range b.dirs {
		if node == b.root {
			continue
		}
		extents = append(extents, filesystemapi.ExtentSpec{Start: b.clusterOffset(node.cluster), Size: int64(len(data)), Data: data})
	}
	for _, node := range b.nodes {
		if node.dir || node.size == 0 {
			continue
		}
		extent := filesystemapi.ExtentSpec{Start: b.clusterOffset(node.cluster), Size: node.size, Data: node.data}
		if node.file != nil {
			extent.File = node.file
			extent.Data = nil
		}
		extents = append(extents, extent)
	}
	sort.Slice(extents, func(i, j int) bool { return extents[i].Start < extents[j].Start })
	return filesystemapi.NewGeneratedImage(fmt.Sprintf("fat%d.raw", fatBits), size, extents), nil
}

func (b *fat16Build) applyFileOrder(paths []string) error {
	if len(paths) == 0 {
		return nil
	}
	byPath := make(map[string]*fat32Node, len(b.nodes))
	for _, node := range b.nodes {
		byPath[strings.ToLower(storage.CleanPath(node.fullPath))] = node
	}
	rank := make(map[*fat32Node]int, len(paths))
	for index, name := range paths {
		cleaned := strings.ToLower(storage.CleanPath(name))
		node := byPath[cleaned]
		if node == nil || node.dir {
			return fmt.Errorf("fat16: file_order path %q is not a file", name)
		}
		if _, exists := rank[node]; exists {
			return fmt.Errorf("fat16: duplicate file_order path %q", name)
		}
		rank[node] = index
	}
	ordered := func(left, right *fat32Node) bool {
		leftRank, leftOrdered := rank[left]
		rightRank, rightOrdered := rank[right]
		if leftOrdered != rightOrdered {
			return leftOrdered
		}
		if leftOrdered {
			return leftRank < rightRank
		}
		return false
	}
	for _, node := range b.nodes {
		sort.SliceStable(node.children, func(left, right int) bool {
			return ordered(node.children[left], node.children[right])
		})
	}
	tail := b.nodes[1:]
	sort.SliceStable(tail, func(left, right int) bool {
		return ordered(tail[left], tail[right])
	})
	return nil
}

func (b *fat16Build) layout() error {
	b.rootDirSectors = fsinternal.CeilDiv(fat16RootEntries*32, fat32SectorSize)
	for _, candidate := range []int64{1, 2, 4, 8, 16, 32, 64, 128} {
		sectorsPerFAT := int64(1)
		for {
			dataSectors := b.totalSectors - fat16ReservedSectors - fat16FATs*sectorsPerFAT - b.rootDirSectors
			if dataSectors <= 0 {
				break
			}
			clusters := dataSectors / candidate
			required := fsinternal.CeilDiv(fsinternal.CeilDiv((clusters+2)*int64(b.fatBits), 8), fat32SectorSize)
			if required <= sectorsPerFAT {
				valid := clusters > 0 && clusters < 4085
				if b.fatBits == 16 {
					valid = clusters >= 4085 && clusters < 65525
				}
				if valid {
					b.sectorsPerCluster = candidate
					b.sectorsPerFAT = sectorsPerFAT
				}
				break
			}
			sectorsPerFAT = required
		}
		if b.sectorsPerCluster != 0 {
			break
		}
	}
	if b.sectorsPerCluster == 0 {
		return fmt.Errorf("fat16: size %d cannot be represented as FAT16", b.size)
	}

	clusterSize := b.sectorsPerCluster * fat32SectorSize
	for _, node := range b.nodes {
		if node == b.root {
			continue
		}
		if node.dir {
			node.clusters = uint32(fsinternal.CeilDiv(b.directorySize(node), clusterSize))
		} else {
			node.clusters = uint32(fsinternal.CeilDiv(node.size, clusterSize))
		}
		if node.clusters > 0 {
			node.cluster = b.allocate(node.clusters)
		}
	}
	dataSectors := b.totalSectors - fat16ReservedSectors - fat16FATs*b.sectorsPerFAT - b.rootDirSectors
	availableClusters := dataSectors / b.sectorsPerCluster
	if int64(b.nextCluster-fat16FirstCluster) > availableClusters {
		return fmt.Errorf("fat16: directory contents need %d clusters, image has %d", b.nextCluster-fat16FirstCluster, availableClusters)
	}
	b.dataOffset = (fat16ReservedSectors + fat16FATs*b.sectorsPerFAT + b.rootDirSectors) * fat32SectorSize
	b.fat = make([]uint16, availableClusters+2)
	if b.fatBits == 12 {
		b.fat[0] = 0x0ff8
		b.fat[1] = 0x0fff
	} else {
		b.fat[0] = 0xfff8
		b.fat[1] = fat16EOC
	}
	for _, node := range b.nodes {
		if node != b.root && node.clusters > 0 {
			b.chain(node.cluster, node.clusters)
		}
	}
	b.dirs = make(map[*fat32Node][]byte)
	for _, node := range b.nodes {
		if node.dir {
			data, err := b.directoryData(node)
			if err != nil {
				return err
			}
			b.dirs[node] = data
		}
	}
	return nil
}

func (b *fat16Build) directorySize(node *fat32Node) int64 {
	entries := 0
	if node == b.root && b.directoryLabel {
		entries++
	}
	if node != b.root {
		entries += 2
	}
	for _, child := range node.children {
		entries++
		if fat32NeedsLFN(child.name, child.short) {
			entries += (len(utf16CodeUnits(child.name)) + 12) / 13
		}
	}
	// Subdirectories need an explicit zero entry after their final child.
	// Account for that terminator before assigning clusters; otherwise a
	// directory whose entries exactly fill a cluster is serialized one cluster
	// larger than its allocation and overlaps the following file extent.
	if node != b.root {
		entries++
	}
	return int64(entries * 32)
}

func utf16CodeUnits(value string) []uint16 {
	return utf16.Encode([]rune(value))
}

func (b *fat16Build) allocate(clusters uint32) uint32 {
	start := b.nextCluster
	b.nextCluster += clusters
	return start
}

func (b *fat16Build) chain(start, clusters uint32) {
	eoc := uint16(fat16EOC)
	if b.fatBits == 12 {
		eoc = 0x0fff
	}
	for index := uint32(0); index < clusters; index++ {
		cluster := start + index
		if index+1 == clusters {
			b.fat[cluster] = eoc
		} else {
			b.fat[cluster] = uint16(cluster + 1)
		}
	}
}

func (b *fat16Build) clusterOffset(cluster uint32) int64 {
	return b.dataOffset + int64(cluster-fat16FirstCluster)*b.sectorsPerCluster*fat32SectorSize
}

func (b *fat16Build) fatBytes() []byte {
	data := make([]byte, b.sectorsPerFAT*fat32SectorSize)
	if b.fatBits == 12 {
		for index, raw := range b.fat {
			value := raw & 0x0fff
			offset := index * 3 / 2
			if offset+1 >= len(data) {
				break
			}
			if index&1 == 0 {
				data[offset] = byte(value)
				data[offset+1] = data[offset+1]&0xf0 | byte(value>>8)&0x0f
			} else {
				data[offset] = data[offset]&0x0f | byte(value<<4)
				data[offset+1] = byte(value >> 4)
			}
		}
		return data
	}
	for index, value := range b.fat {
		offset := index * 2
		if offset+2 > len(data) {
			break
		}
		binary.LittleEndian.PutUint16(data[offset:offset+2], value)
	}
	return data
}

func (b *fat16Build) bootSector() []byte {
	sector := make([]byte, fat32SectorSize)
	if len(b.bootCode) > 0 {
		copy(sector, b.bootCode)
	} else {
		copy(sector[0:3], []byte{0xeb, 0x3c, 0x90})
		copy(sector[3:11], "MSDOS5.0")
	}
	binary.LittleEndian.PutUint16(sector[11:13], uint16(fat32SectorSize))
	sector[13] = byte(b.sectorsPerCluster)
	binary.LittleEndian.PutUint16(sector[14:16], uint16(fat16ReservedSectors))
	sector[16] = byte(fat16FATs)
	binary.LittleEndian.PutUint16(sector[17:19], uint16(fat16RootEntries))
	if b.totalSectors < 65536 {
		binary.LittleEndian.PutUint16(sector[19:21], uint16(b.totalSectors))
		binary.LittleEndian.PutUint32(sector[32:36], 0)
	} else {
		binary.LittleEndian.PutUint16(sector[19:21], 0)
		binary.LittleEndian.PutUint32(sector[32:36], uint32(b.totalSectors))
	}
	sector[21] = 0xf8
	binary.LittleEndian.PutUint16(sector[22:24], uint16(b.sectorsPerFAT))
	heads, sectorsPerTrack := fsinternal.LegacyBIOSGeometry(uint32(b.totalSectors + b.hiddenLBA))
	if b.chs != nil {
		heads, sectorsPerTrack = uint32(b.chs.Heads), uint32(b.chs.Sectors)
	}
	binary.LittleEndian.PutUint16(sector[24:26], uint16(sectorsPerTrack))
	binary.LittleEndian.PutUint16(sector[26:28], uint16(heads))
	binary.LittleEndian.PutUint32(sector[28:32], uint32(b.hiddenLBA))
	if b.extendedBPB {
		sector[36] = 0x80
		sector[38] = 0x29
		binary.LittleEndian.PutUint32(sector[39:43], 0x52584f53)
		copy(sector[43:54], b.volumeLabel[:])
		if b.fatBits == 12 {
			copy(sector[54:62], "FAT12   ")
		} else {
			copy(sector[54:62], "FAT16   ")
		}
	}
	sector[510] = 0x55
	sector[511] = 0xaa
	return sector
}

func (b *fat16Build) directoryData(node *fat32Node) ([]byte, error) {
	var entries []byte
	if node == b.root && b.directoryLabel {
		entries = append(entries, fat32DirEntry("", 0, 0, fatAttrVolumeID, b.volumeLabel)...)
	} else if node != b.root {
		entries = append(entries, fat32DirEntry(".", node.cluster, 0, fatAttrDir, fat32ShortDot())...)
		parentCluster := uint32(0)
		if node.parent != nil && node.parent != b.root {
			parentCluster = node.parent.cluster
		}
		entries = append(entries, fat32DirEntry("..", parentCluster, 0, fatAttrDir, fat32ShortDotDot())...)
	}
	for _, child := range node.children {
		entries = append(entries, fat32LFNEntries(child.name, child.short)...)
		attr := child.attr
		if child.dir {
			attr |= fatAttrDir
		}
		entries = append(entries, fat32DirEntry(child.name, child.cluster, uint32(child.size), attr, child.short)...)
	}
	if node == b.root {
		maximum := int(fat16RootEntries * 32)
		if len(entries)+32 > maximum {
			return nil, fmt.Errorf("fat16: root directory needs %d entries, limit is %d", (len(entries)+31)/32+1, fat16RootEntries)
		}
		data := make([]byte, maximum)
		copy(data, entries)
		return data, nil
	}
	size := fsinternal.Align(int64(len(entries)+32), b.sectorsPerCluster*fat32SectorSize)
	data := make([]byte, size)
	copy(data, entries)
	return data, nil
}
