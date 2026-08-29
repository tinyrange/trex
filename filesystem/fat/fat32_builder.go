package fat

import (
	"encoding/binary"
	"fmt"
	"path"
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
	fat32SectorSize            = int64(512)
	fat32DefaultSectorsPerClus = int64(8)
	fat32ReservedSectors       = int64(32)
	fat32FATs                  = int64(2)
	fat32FSInfoSector          = int64(1)
	fat32BackupBoot            = int64(6)
	fat32BootStageSector       = int64(14)
	fat32RootCluster           = uint32(2)
	fat32EOC                   = uint32(0x0fffffff)
)

func FAT32Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	var size int
	var bootCodeValue starlark.Value = starlark.None
	var chsValue starlark.Value = starlark.None
	var fileOrderValue *starlark.List
	hiddenSectors := 0
	label := "NO NAME"
	directoryLabel := true
	bootStageSector := int(fat32BootStageSector)
	if err := starlark.UnpackArgs("fat32", args, kwargs, "directory", &value, "size", &size, "boot_code?", &bootCodeValue, "hidden_sectors?", &hiddenSectors, "label?", &label, "boot_stage_sector?", &bootStageSector, "file_order?", &fileOrderValue, "directory_label?", &directoryLabel, "chs?", &chsValue); err != nil {
		return nil, err
	}
	dir, ok := value.(*filesystemapi.Directory)
	if !ok {
		return nil, fmt.Errorf("fat32: got %s, want directory", value.Type())
	}
	if size < 64*1024*1024 {
		return nil, fmt.Errorf("fat32: size must be at least 64 MiB")
	}
	if hiddenSectors < 0 {
		return nil, fmt.Errorf("fat32: hidden_sectors must be non-negative")
	}
	if bootStageSector < 2 || bootStageSector >= int(fat32ReservedSectors) {
		return nil, fmt.Errorf("fat32: boot_stage_sector must be between 2 and %d", fat32ReservedSectors-1)
	}
	bootCode, err := fsinternal.BootCodeBytes("fat32", bootCodeValue)
	if err != nil {
		return nil, err
	}
	if err := validateFAT32BootStage(bootCode, int64(bootStageSector)); err != nil {
		return nil, err
	}
	volumeLabel, err := fat32VolumeLabel(label)
	if err != nil {
		return nil, err
	}
	fileOrder, err := fsinternal.StringList(fileOrderValue, "file_order")
	if err != nil {
		return nil, fmt.Errorf("fat32: %w", err)
	}
	chs, err := fsinternal.CHSGeometry(chsValue)
	if err != nil {
		return nil, fmt.Errorf("fat32: chs: %w", err)
	}
	return buildFAT32ImageWithOptionsAndGeometry(dir, int64(size), bootCode, int64(hiddenSectors), volumeLabel, int64(bootStageSector), fileOrder, directoryLabel, chs)
}

type fat32Node struct {
	name       string
	fullPath   string
	parent     *fat32Node
	dir        bool
	size       int64
	file       starfile.File
	data       []byte
	cluster    uint32
	clusters   uint32
	children   []*fat32Node
	short      [11]byte
	attr       byte
	writeOrder uint64
}

type fat32Build struct {
	size              int64
	totalSectors      int64
	sectorsPerFAT     int64
	sectorsPerCluster int64
	dataOffset        int64
	nextCluster       uint32
	nodes             []*fat32Node
	root              *fat32Node
	bootCode          []byte
	hiddenLBA         int64
	volumeLabel       [11]byte
	bootStageLBA      int64
	directoryLabel    bool
	chs               *vmm.CHSGeometry
	fat               []uint32
	dirs              map[*fat32Node][]byte
}

func buildFAT32Image(dir *filesystemapi.Directory, size int64, bootCode []byte, hiddenLBA int64) (starfile.File, error) {
	label, _ := fat32VolumeLabel("NO NAME")
	return buildFAT32ImageWithLabel(dir, size, bootCode, hiddenLBA, label)
}

func buildFAT32ImageWithLabel(dir *filesystemapi.Directory, size int64, bootCode []byte, hiddenLBA int64, volumeLabel [11]byte) (starfile.File, error) {
	return buildFAT32ImageWithOptions(dir, size, bootCode, hiddenLBA, volumeLabel, fat32BootStageSector)
}

func buildFAT32ImageWithOptions(dir *filesystemapi.Directory, size int64, bootCode []byte, hiddenLBA int64, volumeLabel [11]byte, bootStageLBA int64) (starfile.File, error) {
	return buildFAT32ImageWithOptionsAndGeometry(dir, size, bootCode, hiddenLBA, volumeLabel, bootStageLBA, nil, true, nil)
}

func buildFAT32ImageWithOptionsAndGeometry(dir *filesystemapi.Directory, size int64, bootCode []byte, hiddenLBA int64, volumeLabel [11]byte, bootStageLBA int64, fileOrder []string, directoryLabel bool, chs *vmm.CHSGeometry) (starfile.File, error) {
	b := &fat32Build{
		size: size, totalSectors: size / fat32SectorSize,
		sectorsPerCluster: fat32ClusterSectors(size / fat32SectorSize),
		nextCluster:       fat32RootCluster, bootCode: bootCode, hiddenLBA: hiddenLBA,
		volumeLabel: volumeLabel, bootStageLBA: bootStageLBA, directoryLabel: directoryLabel, chs: chs,
	}
	if err := b.importDirectory(dir); err != nil {
		return nil, err
	}
	if err := b.applyFileOrder(fileOrder); err != nil {
		return nil, err
	}
	if err := b.layout(); err != nil {
		return nil, err
	}
	bootData := b.bootData()
	extents := []filesystemapi.ExtentSpec{{Start: 0, Size: int64(len(bootData)), Data: bootData}}
	for i := int64(0); i < fat32FATs; i++ {
		extents = append(extents, filesystemapi.ExtentSpec{Start: (fat32ReservedSectors + i*b.sectorsPerFAT) * fat32SectorSize, Size: int64(len(b.fatBytes())), Data: b.fatBytes()})
	}
	for node, data := range b.dirs {
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
	return filesystemapi.NewGeneratedImage("fat32.raw", size, extents), nil
}

func (b *fat32Build) applyFileOrder(paths []string) error {
	if len(paths) == 0 {
		return nil
	}
	byPath := make(map[string]*fat32Node, len(b.nodes))
	for _, node := range b.nodes {
		byPath[strings.ToLower(storage.CleanPath(node.fullPath))] = node
	}
	rank := make(map[*fat32Node]int, len(paths))
	for index, name := range paths {
		node := byPath[strings.ToLower(storage.CleanPath(name))]
		if node == nil || node.dir {
			return fmt.Errorf("fat32: file_order path %q is not a file", name)
		}
		if _, exists := rank[node]; exists {
			return fmt.Errorf("fat32: duplicate file_order path %q", name)
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
		sort.SliceStable(node.children, func(left, right int) bool { return ordered(node.children[left], node.children[right]) })
	}
	tail := b.nodes[1:]
	sort.SliceStable(tail, func(left, right int) bool { return ordered(tail[left], tail[right]) })
	return nil
}

func (b *fat32Build) importDirectory(dir *filesystemapi.Directory) error {
	snapshot := dir.Snapshot()
	b.root = &fat32Node{name: "/", fullPath: "/", dir: true}
	b.nodes = append(b.nodes, b.root)
	byPath := map[string]*fat32Node{"/": b.root}
	dirs := make([]string, 0, len(snapshot.Directories))
	for _, name := range snapshot.Directories {
		dirs = append(dirs, storage.CleanPath(name))
	}
	sort.Strings(dirs)
	for _, name := range dirs {
		if name != "/" {
			b.ensureDir(byPath, name)
		}
	}
	files := make([]string, 0, len(snapshot.Files))
	for name := range snapshot.Files {
		files = append(files, storage.CleanPath(name))
	}
	sort.Strings(files)
	for _, name := range files {
		parent := b.ensureDir(byPath, path.Dir(name))
		vf := snapshot.Files[name]
		if existing := fat32ChildByName(parent, path.Base(name)); existing != nil {
			if existing.dir || vf.WriteOrder <= existing.writeOrder {
				continue
			}
			existing.name = path.Base(name)
			existing.fullPath = name
			existing.size = vf.Size
			existing.file = vf.File
			existing.data = vf.Data
			existing.attr = fatAttrArchive
			existing.writeOrder = vf.WriteOrder
			continue
		}
		node := &fat32Node{name: path.Base(name), fullPath: name, parent: parent, size: vf.Size, file: vf.File, data: vf.Data, attr: fatAttrArchive, writeOrder: vf.WriteOrder}
		parent.children = append(parent.children, node)
		b.nodes = append(b.nodes, node)
	}
	for name, attributes := range snapshot.Attributes {
		name = storage.CleanPath(name)
		var node *fat32Node
		if candidate := byPath[strings.ToLower(name)]; candidate != nil {
			node = candidate
		} else if parent := byPath[strings.ToLower(path.Dir(name))]; parent != nil {
			node = fat32ChildByName(parent, path.Base(name))
		}
		if node != nil {
			node.attr = fat32Attributes(attributes)
		}
	}
	for _, node := range b.nodes {
		sort.Slice(node.children, func(i, j int) bool {
			return strings.ToLower(node.children[i].name) < strings.ToLower(node.children[j].name)
		})
		assignFAT32ShortNames(node.children)
	}
	return nil
}

func (b *fat32Build) ensureDir(byPath map[string]*fat32Node, name string) *fat32Node {
	name = storage.CleanPath(name)
	key := strings.ToLower(name)
	if node := byPath[key]; node != nil {
		return node
	}
	parent := b.ensureDir(byPath, path.Dir(name))
	if node := fat32ChildByName(parent, path.Base(name)); node != nil && node.dir {
		byPath[key] = node
		return node
	}
	node := &fat32Node{name: path.Base(name), fullPath: name, parent: parent, dir: true, attr: fatAttrDir}
	byPath[key] = node
	parent.children = append(parent.children, node)
	b.nodes = append(b.nodes, node)
	return node
}

func fat32Attributes(attributes filesystemapi.Attributes) byte {
	var attr byte
	if attributes.ReadOnly {
		attr |= fatAttrReadOnly
	}
	if attributes.Hidden {
		attr |= fatAttrHidden
	}
	if attributes.System {
		attr |= fatAttrSystem
	}
	if attributes.Archive {
		attr |= fatAttrArchive
	}
	return attr
}

func fat32ChildByName(parent *fat32Node, name string) *fat32Node {
	for _, child := range parent.children {
		if strings.EqualFold(child.name, name) {
			return child
		}
	}
	return nil
}

func (b *fat32Build) layout() error {
	clusterSize := fat32SectorSize * b.clusterSectors()
	for _, node := range b.nodes {
		if node.dir {
			node.clusters = uint32(fsinternal.CeilDiv(b.directorySize(node), clusterSize))
		} else {
			node.clusters = uint32(fsinternal.CeilDiv(node.size, clusterSize))
		}
		if node.clusters > 0 {
			node.cluster = b.allocate(node.clusters)
		}
	}
	b.sectorsPerFAT = fat32SectorsPerFAT(b.totalSectors, b.clusterSectors())
	if b.sectorsPerFAT == 0 {
		return fmt.Errorf("fat32: image is too small")
	}
	dataSectors := b.totalSectors - fat32ReservedSectors - fat32FATs*b.sectorsPerFAT
	availableClusters := dataSectors / b.clusterSectors()
	if int64(b.nextCluster) > availableClusters+2 {
		return fmt.Errorf("fat32: directory contents need %d clusters, image has %d", int64(b.nextCluster)-int64(fat32RootCluster), availableClusters)
	}
	if availableClusters < 65525 {
		return fmt.Errorf("fat32: image has %d clusters, need at least 65525 for FAT32", availableClusters)
	}
	b.dataOffset = (fat32ReservedSectors + fat32FATs*b.sectorsPerFAT) * fat32SectorSize
	b.fat = make([]uint32, b.totalClusters()+2)
	b.fat[0] = 0x0ffffff8
	b.fat[1] = fat32EOC
	for _, node := range b.nodes {
		if node.clusters > 0 {
			b.chain(node.cluster, node.clusters)
		}
	}
	b.dirs = make(map[*fat32Node][]byte)
	for _, node := range b.nodes {
		if node.dir {
			b.dirs[node] = b.directoryData(node)
		}
	}
	return nil
}

func (b *fat32Build) directorySize(node *fat32Node) int64 {
	entries := 1
	if node != b.root {
		entries += 2
	}
	for _, child := range node.children {
		entries++
		units := len(utf16.Encode([]rune(child.name)))
		if fat32NeedsLFN(child.name, child.short) {
			entries += (units + 12) / 13
		}
	}
	return int64(entries * 32)
}

func (b *fat32Build) allocate(clusters uint32) uint32 {
	start := b.nextCluster
	b.nextCluster += clusters
	return start
}

func (b *fat32Build) chain(start, clusters uint32) {
	for i := uint32(0); i < clusters; i++ {
		cluster := start + i
		if i+1 == clusters {
			b.fat[cluster] = fat32EOC
		} else {
			b.fat[cluster] = cluster + 1
		}
	}
}

func (b *fat32Build) totalClusters() int64 {
	return (b.totalSectors - fat32ReservedSectors - fat32FATs*b.sectorsPerFAT) / b.clusterSectors()
}

func (b *fat32Build) clusterOffset(cluster uint32) int64 {
	return b.dataOffset + int64(cluster-fat32RootCluster)*b.clusterSectors()*fat32SectorSize
}

func (b *fat32Build) fatBytes() []byte {
	data := make([]byte, b.sectorsPerFAT*fat32SectorSize)
	for i, value := range b.fat {
		if i*4+4 > len(data) {
			break
		}
		binary.LittleEndian.PutUint32(data[i*4:i*4+4], value)
	}
	return data
}

func (b *fat32Build) bootSector() []byte {
	sector := make([]byte, fat32SectorSize)
	if len(b.bootCode) > 0 {
		copy(sector, b.bootCode)
	} else {
		copy(sector[0:3], []byte{0xeb, 0x58, 0x90})
	}
	copy(sector[3:11], "MSWIN4.1")
	binary.LittleEndian.PutUint16(sector[11:13], uint16(fat32SectorSize))
	sector[13] = byte(b.clusterSectors())
	binary.LittleEndian.PutUint16(sector[14:16], uint16(fat32ReservedSectors))
	sector[16] = byte(fat32FATs)
	binary.LittleEndian.PutUint16(sector[17:19], 0)
	binary.LittleEndian.PutUint16(sector[19:21], 0)
	sector[21] = 0xf8
	binary.LittleEndian.PutUint16(sector[22:24], 0)
	heads, sectorsPerTrack := fsinternal.LegacyBIOSGeometry(uint32(b.totalSectors + b.hiddenLBA))
	if b.chs != nil {
		heads, sectorsPerTrack = uint32(b.chs.Heads), uint32(b.chs.Sectors)
	}
	binary.LittleEndian.PutUint16(sector[24:26], uint16(sectorsPerTrack))
	binary.LittleEndian.PutUint16(sector[26:28], uint16(heads))
	binary.LittleEndian.PutUint32(sector[28:32], uint32(b.hiddenLBA))
	binary.LittleEndian.PutUint32(sector[32:36], uint32(b.totalSectors))
	binary.LittleEndian.PutUint32(sector[36:40], uint32(b.sectorsPerFAT))
	binary.LittleEndian.PutUint16(sector[40:42], 0)
	binary.LittleEndian.PutUint16(sector[42:44], 0)
	binary.LittleEndian.PutUint32(sector[44:48], fat32RootCluster)
	binary.LittleEndian.PutUint16(sector[48:50], uint16(fat32FSInfoSector))
	binary.LittleEndian.PutUint16(sector[50:52], uint16(fat32BackupBoot))
	sector[64] = 0x80
	sector[66] = 0x29
	binary.LittleEndian.PutUint32(sector[67:71], 0x52584f53)
	copy(sector[71:82], b.volumeLabel[:])
	copy(sector[82:90], []byte("FAT32   "))
	sector[510] = 0x55
	sector[511] = 0xaa
	return sector
}

func fat32VolumeLabel(label string) ([11]byte, error) {
	var out [11]byte
	if label == "" || len(label) > len(out) {
		return out, fmt.Errorf("fat32: label must contain 1 to 11 ASCII characters")
	}
	for i := range out {
		out[i] = ' '
	}
	for i, char := range []byte(strings.ToUpper(label)) {
		if char < 0x20 || char > 0x7e || strings.ContainsRune(`"*+,./:;<=>?[\]|`, rune(char)) {
			return [11]byte{}, fmt.Errorf("fat32: label contains invalid character %q", char)
		}
		out[i] = char
	}
	return out, nil
}

func validateFAT32BootStage(bootCode []byte, stageLBA int64) error {
	if len(bootCode) <= int(fat32SectorSize) {
		return nil
	}
	stageSectors := fsinternal.CeilDiv(int64(len(bootCode))-fat32SectorSize, fat32SectorSize)
	stageEnd := stageLBA + stageSectors
	if stageEnd > fat32ReservedSectors {
		return fmt.Errorf("fat32: secondary boot code extends beyond the reserved sectors")
	}
	for _, metadataLBA := range []int64{fat32FSInfoSector, fat32BackupBoot, fat32BackupBoot + fat32FSInfoSector} {
		if metadataLBA >= stageLBA && metadataLBA < stageEnd {
			return fmt.Errorf("fat32: secondary boot code overlaps reserved metadata sector %d", metadataLBA)
		}
	}
	return nil
}

func (b *fat32Build) bootData() []byte {
	size := fat32SectorSize
	if len(b.bootCode) > 0 {
		size = fsinternal.Align(int64(len(b.bootCode)), fat32SectorSize)
		stageEnd := (b.bootStageLBA + fsinternal.CeilDiv(int64(len(b.bootCode))-fat32SectorSize, fat32SectorSize)) * fat32SectorSize
		if len(b.bootCode) > int(fat32SectorSize) && size < stageEnd {
			size = stageEnd
		}
		if len(b.bootCode) > int(fat32SectorSize) && b.bootStageLBA == 2 {
			backupStageEnd := (fat32BackupBoot + b.bootStageLBA + fsinternal.CeilDiv(int64(len(b.bootCode))-fat32SectorSize, fat32SectorSize)) * fat32SectorSize
			if size < backupStageEnd {
				size = backupStageEnd
			}
		}
	}
	minBootSize := (fat32BackupBoot + fat32FSInfoSector + 1) * fat32SectorSize
	if size < minBootSize {
		size = minBootSize
	}
	data := make([]byte, size)
	if len(b.bootCode) > 0 {
		copy(data, b.bootCode)
		if len(b.bootCode) > int(fat32SectorSize) {
			secondary := b.bootCode[fat32SectorSize:]
			copy(data[b.bootStageLBA*fat32SectorSize:], secondary)
			if b.bootStageLBA == 2 {
				copy(data[(fat32BackupBoot+b.bootStageLBA)*fat32SectorSize:], secondary)
			}
		}
	}
	boot := b.bootSector()
	fsinfo := b.fsInfoSector()
	copy(data, boot)
	copy(data[fat32FSInfoSector*fat32SectorSize:], fsinfo)
	copy(data[fat32BackupBoot*fat32SectorSize:], boot)
	copy(data[(fat32BackupBoot+fat32FSInfoSector)*fat32SectorSize:], fsinfo)
	return data
}

func (b *fat32Build) fsInfoSector() []byte {
	sector := make([]byte, fat32SectorSize)
	binary.LittleEndian.PutUint32(sector[0:4], 0x41615252)
	binary.LittleEndian.PutUint32(sector[484:488], 0x61417272)
	free := uint32(0xffffffff)
	total := b.totalClusters()
	used := int64(b.nextCluster) - int64(fat32RootCluster)
	if total >= used {
		free = uint32(total - used)
	}
	binary.LittleEndian.PutUint32(sector[488:492], free)
	next := uint32(0xffffffff)
	if int64(b.nextCluster)-int64(fat32RootCluster) < total {
		next = b.nextCluster
	}
	binary.LittleEndian.PutUint32(sector[492:496], next)
	binary.LittleEndian.PutUint32(sector[508:512], 0xaa550000)
	return sector
}

func (b *fat32Build) directoryData(node *fat32Node) []byte {
	clusterSize := int(fat32SectorSize * b.clusterSectors())
	var entries []byte
	if node == b.root && b.directoryLabel {
		entries = append(entries, fat32DirEntry("", 0, 0, fatAttrVolumeID, b.volumeLabel)...)
	}
	if node != b.root {
		entries = append(entries, fat32DirEntry(".", node.cluster, 0, fatAttrDir, fat32ShortDot())...)
		parentCluster := uint32(0)
		if node.parent != nil {
			parentCluster = node.parent.cluster
		}
		if node.parent == b.root {
			parentCluster = 0
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
	size := fsinternal.Align(int64(len(entries)+32), int64(clusterSize))
	if size == 0 {
		size = int64(clusterSize)
	}
	data := make([]byte, size)
	copy(data, entries)
	return data
}

func (b *fat32Build) clusterSectors() int64 {
	if b.sectorsPerCluster > 0 {
		return b.sectorsPerCluster
	}
	return fat32DefaultSectorsPerClus
}

func fat32ClusterSectors(totalSectors int64) int64 {
	for _, sectorsPerCluster := range []int64{8, 4, 2, 1} {
		sectorsPerFAT := fat32SectorsPerFAT(totalSectors, sectorsPerCluster)
		if sectorsPerFAT == 0 {
			continue
		}
		clusters := (totalSectors - fat32ReservedSectors - fat32FATs*sectorsPerFAT) / sectorsPerCluster
		if clusters >= 65525 && clusters < int64(fat32EOC-8) {
			return sectorsPerCluster
		}
	}
	return 1
}

func fat32SectorsPerFAT(totalSectors, sectorsPerCluster int64) int64 {
	dataAndFATSectors := totalSectors - fat32ReservedSectors
	if dataAndFATSectors <= 0 || sectorsPerCluster <= 0 {
		return 0
	}
	// This is the canonical FAT32 BPB computation from Microsoft's FAT
	// specification. It intentionally leaves a small amount of FAT slack.
	// Windows 9x recomputes this boundary when locating the second FAT, so a
	// merely self-consistent (or one-sector conservative) size is not enough.
	denominator := (256*sectorsPerCluster + fat32FATs) / 2
	return fsinternal.CeilDiv(dataAndFATSectors, denominator)
}

func assignFAT32ShortNames(nodes []*fat32Node) {
	used := map[string]struct{}{}
	nextSuffix := map[string]int{}
	for _, node := range nodes {
		base, ext := fat32ShortParts(node.name)
		if fat32IsSimple83(node.name, base, ext) {
			candidate := fat32ShortName(base, ext)
			if _, ok := used[string(candidate[:])]; !ok {
				node.short = candidate
				used[string(candidate[:])] = struct{}{}
				continue
			}
		}
		keyBase := base
		key := keyBase + "\x00" + ext
		n := nextSuffix[key]
		if n == 0 {
			n = 1
		}
		for ; ; n++ {
			suffix := fmt.Sprintf("~%d", n)
			limit := 8 - len(suffix)
			if limit < 1 {
				limit = 1
			}
			prefix := keyBase
			if len(prefix) > limit {
				prefix = prefix[:limit]
			}
			candidate := fat32ShortName(prefix+suffix, ext)
			if _, ok := used[string(candidate[:])]; ok {
				continue
			}
			node.short = candidate
			used[string(candidate[:])] = struct{}{}
			nextSuffix[key] = n + 1
			break
		}
	}
}

func fat32ShortName(base, ext string) [11]byte {
	var out [11]byte
	copy(out[0:8], padRight(base, 8))
	copy(out[8:11], padRight(ext, 3))
	return out
}

func fat32ShortParts(name string) (string, string) {
	base := name
	ext := ""
	if idx := strings.LastIndex(name, "."); idx > 0 {
		base = name[:idx]
		ext = name[idx+1:]
	}
	base = fat32ShortClean(base)
	ext = fat32ShortClean(ext)
	if base == "" {
		base = "FILE"
	}
	if len(base) > 8 {
		base = base[:8]
	}
	if len(ext) > 3 {
		ext = ext[:3]
	}
	return base, ext
}

func fat32ShortClean(s string) string {
	var out strings.Builder
	for _, r := range strings.ToUpper(s) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '$' || r == '~' {
			out.WriteRune(r)
		}
	}
	return out.String()
}

func fat32IsSimple83(name, base, ext string) bool {
	want := strings.TrimRight(base, " ")
	if ext != "" {
		want += "." + strings.TrimRight(ext, " ")
	}
	return strings.EqualFold(name, want) && len(base) <= 8 && len(ext) <= 3
}

func padRight(s string, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = ' '
	}
	copy(out, []byte(s))
	return out
}

func fat32DirEntry(name string, cluster uint32, size uint32, attr byte, short [11]byte) []byte {
	entry := make([]byte, 32)
	copy(entry[0:11], short[:])
	entry[11] = attr
	entry[12] = fat32NTResCaseFlags(name, short)
	binary.LittleEndian.PutUint16(entry[20:22], uint16(cluster>>16))
	binary.LittleEndian.PutUint16(entry[26:28], uint16(cluster))
	binary.LittleEndian.PutUint32(entry[28:32], size)
	return entry
}

func fat32NeedsLFN(name string, short [11]byte) bool {
	base := strings.TrimRight(string(short[0:8]), " ")
	ext := strings.TrimRight(string(short[8:11]), " ")
	if !fat32IsSimple83(name, base, ext) {
		return true
	}
	nameBase, nameExt := fat32NameParts(name)
	return fat32HasMixedASCIIAlpha(nameBase) || fat32HasMixedASCIIAlpha(nameExt)
}

func fat32NTResCaseFlags(name string, short [11]byte) byte {
	if name == "" || name == "." || name == ".." || fat32NeedsLFN(name, short) {
		return 0
	}
	base, ext := fat32NameParts(name)
	var flags byte
	if fat32HasLowerASCIIAlpha(base) && !fat32HasUpperASCIIAlpha(base) {
		flags |= 0x08
	}
	if fat32HasLowerASCIIAlpha(ext) && !fat32HasUpperASCIIAlpha(ext) {
		flags |= 0x10
	}
	return flags
}

func fat32NameParts(name string) (string, string) {
	if idx := strings.LastIndex(name, "."); idx > 0 {
		return name[:idx], name[idx+1:]
	}
	return name, ""
}

func fat32HasMixedASCIIAlpha(s string) bool {
	return fat32HasLowerASCIIAlpha(s) && fat32HasUpperASCIIAlpha(s)
}

func fat32HasLowerASCIIAlpha(s string) bool {
	for _, r := range s {
		if r >= 'a' && r <= 'z' {
			return true
		}
	}
	return false
}

func fat32HasUpperASCIIAlpha(s string) bool {
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			return true
		}
	}
	return false
}

func fat32LFNEntries(name string, short [11]byte) []byte {
	units := utf16.Encode([]rune(name))
	count := (len(units) + 12) / 13
	if count == 0 || !fat32NeedsLFN(name, short) {
		return nil
	}
	var out []byte
	checksum := fat32ShortChecksum(short)
	for i := count - 1; i >= 0; i-- {
		entry := make([]byte, 32)
		seq := byte(i + 1)
		if i == count-1 {
			seq |= 0x40
		}
		entry[0] = seq
		entry[11] = fatAttrLFN
		entry[13] = checksum
		for j := 0; j < 13; j++ {
			idx := i*13 + j
			value := uint16(0xffff)
			if idx < len(units) {
				value = units[idx]
			} else if idx == len(units) {
				value = 0
			}
			fat32PutLFNChar(entry, j, value)
		}
		out = append(out, entry...)
	}
	return out
}

func fat32PutLFNChar(entry []byte, idx int, value uint16) {
	offsets := []int{1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30}
	binary.LittleEndian.PutUint16(entry[offsets[idx]:offsets[idx]+2], value)
}

func fat32ShortChecksum(short [11]byte) byte {
	var sum byte
	for _, c := range short {
		sum = ((sum & 1) << 7) + (sum >> 1) + c
	}
	return sum
}

func fat32ShortDot() [11]byte {
	var out [11]byte
	copy(out[:], ".          ")
	return out
}

func fat32ShortDotDot() [11]byte {
	var out [11]byte
	copy(out[:], "..         ")
	return out
}
