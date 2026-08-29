package ntfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"

	filesystemapi "github.com/tinyrange/trex/filesystem"
	fsinternal "github.com/tinyrange/trex/filesystem/internal"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

const (
	ntfsSectorSize     = int64(512)
	ntfsCluster        = int64(512)
	ntfsRecordSize     = int64(1024)
	ntfsIndexSize      = int64(4096)
	ntfsBootSize       = int64(16 * ntfsSectorSize)
	ntfsLogFileMinimum = int64(2 * 1024 * 1024)
	ntfsLogFileMaximum = int64(64 * 1024 * 1024)
	ntfsLogFileQuantum = int64(64 * 1024)

	ntfsAttrStandardInformation = 0x10
	ntfsAttrAttributeList       = 0x20
	ntfsAttrFileName            = 0x30
	ntfsAttrObjectID            = 0x40
	ntfsAttrSecurityDescriptor  = 0x50
	ntfsAttrVolumeName          = 0x60
	ntfsAttrVolumeInformation   = 0x70
	ntfsAttrData                = 0x80
	ntfsAttrIndexRoot           = 0x90
	ntfsAttrIndexAllocation     = 0xa0
	ntfsAttrBitmap              = 0xb0
	ntfsAttrReparsePoint        = 0xc0
	ntfsAttrLoggedUtilityStream = 0x100
	ntfsAttrEnd                 = 0xffffffff

	ntfsFileInUse        = 0x0001
	ntfsFileDir          = 0x0002
	ntfsFileViewIndex    = 0x0004
	ntfsFileMetaIndex    = 0x0008
	ntfsIndexHasSub      = 0x0001
	ntfsIndexLast        = 0x0002
	ntfsIndexNode        = 0x01
	ntfsFileAttrDir      = 0x10000000
	ntfsFileAttrIndex    = 0x20000000
	ntfsFileAttrArch     = 0x00000020
	ntfsFileAttrRO       = 0x00000001
	ntfsFileAttrHide     = 0x00000002
	ntfsFileAttrSys      = 0x00000004
	ntfsSecurityID       = uint32(0x100)
	ntfsSecureMirrorBase = 0x40000
)

func NTFSBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	sizeValue := starlark.Value(starlark.None)
	var bootCodeValue starlark.Value = starlark.None
	var logFileValue starlark.Value = starlark.None
	var upCaseValue starlark.Value = starlark.None
	hiddenSectors := 0
	label := "NO NAME"
	version := "1.1"
	if err := starlark.UnpackArgs("ntfs", args, kwargs, "source", &value, "size?", &sizeValue, "boot_code?", &bootCodeValue, "hidden_sectors?", &hiddenSectors, "label?", &label, "version?", &version, "log_file?", &logFileValue, "upcase?", &upCaseValue); err != nil {
		return nil, err
	}
	if file, ok := value.(starfile.File); ok {
		if sizeValue != starlark.None || bootCodeValue != starlark.None || hiddenSectors != 0 || label != "NO NAME" || version != "1.1" || logFileValue != starlark.None || upCaseValue != starlark.None {
			return nil, fmt.Errorf("ntfs: mount does not accept builder options")
		}
		return newNTFSVolume(file)
	}
	dir, ok := value.(*filesystemapi.Directory)
	if !ok {
		return nil, fmt.Errorf("ntfs: got %s, want directory or file", value.Type())
	}
	if sizeValue == starlark.None {
		return nil, fmt.Errorf("ntfs: size is required when building a filesystem")
	}
	sizeInteger, ok := sizeValue.(starlark.Int)
	size, ok := sizeInteger.Int64()
	if !ok || size < 0 {
		return nil, fmt.Errorf("ntfs: size must be a non-negative int")
	}
	if hiddenSectors < 0 {
		return nil, fmt.Errorf("ntfs: hidden_sectors must be non-negative")
	}
	if err := validateNTFSVolumeName(label); err != nil {
		return nil, err
	}
	versionMajor, versionMinor, err := parseNTFSVersion(version)
	if err != nil {
		return nil, err
	}
	bootCode, err := fsinternal.BootCodeBytes("ntfs", bootCodeValue)
	if err != nil {
		return nil, err
	}
	var logFile starfile.File
	if logFileValue != starlark.None {
		var ok bool
		logFile, ok = logFileValue.(starfile.File)
		if !ok {
			return nil, fmt.Errorf("ntfs: log_file is %s, want file", logFileValue.Type())
		}
		if logFile.Size() < ntfsSectorSize || logFile.Size() > 256<<20 || logFile.Size()%ntfsSectorSize != 0 {
			return nil, fmt.Errorf("ntfs: log_file size must be sector-aligned and between 512 bytes and 256 MiB")
		}
	}
	var upCase []byte
	if upCaseValue != starlark.None {
		file, ok := upCaseValue.(starfile.File)
		if !ok {
			return nil, fmt.Errorf("ntfs: upcase is %s, want file", upCaseValue.Type())
		}
		if file.Size() != 65536*2 {
			return nil, fmt.Errorf("ntfs: upcase must be exactly 131072 bytes")
		}
		upCase, err = fsinternal.ReadBytesAt(file, 0, file.Size())
		if err != nil {
			return nil, fmt.Errorf("ntfs: read upcase: %w", err)
		}
	}
	return buildNTFSImageWithMetadata(dir, size, bootCode, int64(hiddenSectors), label, versionMajor, versionMinor, logFile, upCase)
}

type ntfsNode struct {
	id                 uint64
	name               string
	names              []ntfsName
	fullPath           string
	parent             *ntfsNode
	dir                bool
	size               int64
	file               starfile.File
	data               []byte
	writeOrder         uint64
	lcn                int64
	clusters           int64
	indexLCN           int64
	index              ntfsDirectoryIndex
	children           []*ntfsDirectoryLink
	attrs              filesystemapi.Attributes
	metadata           filesystemapi.Metadata
	securityID         uint32
	systemKind         string
	linkCount          uint16
	extensionOf        *ntfsNode
	extensionNames     []ntfsName
	extensionIndexRoot bool
	attributeList      []byte
	attributeListID    uint16
	dataAttributeID    uint16
	attributeListLCN   int64
	indexRootRecordID  uint64
}

type ntfsDirectoryLink struct {
	node      *ntfsNode
	name      string
	shortName string
	names     []ntfsName
}

type ntfsDirectoryIndex struct {
	rootValue []byte
	blocks    []byte
	bitmap    []byte
}

type ntfsSecurityRecord struct {
	descriptor []byte
	hash       uint32
	id         uint32
	offset     uint64
}

type ntfsSecurityIndex struct {
	rootValue []byte
	blocks    []byte
	bitmap    []byte
}

type ntfsName struct {
	value     string
	namespace byte
	parent    *ntfsNode
	attrID    uint16
}

type ntfsIndexKey struct {
	node *ntfsNode
	name ntfsName
}

var errNTFSIndexRootCapacity = errors.New("NTFS index root cannot hold a child separator")

type ntfsBuild struct {
	size            int64
	mftLCN          int64
	mftMirrLCN      int64
	mftRecords      int64
	mftBitmapLCN    int64
	mftBitmapData   []byte
	nextID          uint64
	nextLCN         int64
	nodes           []*ntfsNode
	root            *ntfsNode
	attrDefLCN      int64
	attrDef         []byte
	logFileLCN      int64
	logFile         starfile.File
	upCaseLCN       int64
	upCase          []byte
	bitmapLCN       int64
	bitmapSize      int64
	bootCode        []byte
	hiddenLBA       int64
	volumeName      string
	versionMajor    byte
	versionMinor    byte
	secureData      []byte
	secureLCN       int64
	secureIDIndex   ntfsSecurityIndex
	secureHashIndex ntfsSecurityIndex
	secureIDLCN     int64
	secureHashLCN   int64
	rootSecurity    []byte
	rootSecurityLCN int64
}

func buildNTFSImage(dir *filesystemapi.Directory, size int64, bootCode []byte, hiddenLBA int64) (starfile.File, error) {
	return buildNTFSImageWithLabel(dir, size, bootCode, hiddenLBA, "NO NAME")
}

func buildNTFSImageWithLabel(dir *filesystemapi.Directory, size int64, bootCode []byte, hiddenLBA int64, volumeName string) (starfile.File, error) {
	return buildNTFSImageWithOptions(dir, size, bootCode, hiddenLBA, volumeName, 1, 1)
}

func parseNTFSVersion(version string) (byte, byte, error) {
	switch version {
	case "1.1":
		return 1, 1, nil
	case "3.1":
		return 3, 1, nil
	default:
		return 0, 0, fmt.Errorf("ntfs: unsupported version %q (want \"1.1\" or \"3.1\")", version)
	}
}

func buildNTFSImageWithOptions(dir *filesystemapi.Directory, size int64, bootCode []byte, hiddenLBA int64, volumeName string, versionMajor, versionMinor byte) (starfile.File, error) {
	return buildNTFSImageWithMetadata(dir, size, bootCode, hiddenLBA, volumeName, versionMajor, versionMinor, nil, nil)
}

func buildNTFSImageWithMetadata(dir *filesystemapi.Directory, size int64, bootCode []byte, hiddenLBA int64, volumeName string, versionMajor, versionMinor byte, logFile starfile.File, upCase []byte) (starfile.File, error) {
	if size < 64*1024*1024 {
		return nil, fmt.Errorf("ntfs: size must be at least 64 MiB")
	}
	if versionMajor != 1 && versionMajor != 3 || versionMinor != 1 {
		return nil, fmt.Errorf("ntfs: unsupported version %d.%d", versionMajor, versionMinor)
	}
	if err := validateNTFSVolumeName(volumeName); err != nil {
		return nil, err
	}
	b := &ntfsBuild{
		size:         size,
		mftLCN:       16 * 1024 / ntfsCluster,
		nextID:       16,
		bootCode:     bootCode,
		hiddenLBA:    hiddenLBA,
		volumeName:   volumeName,
		versionMajor: versionMajor,
		versionMinor: versionMinor,
	}
	if err := b.importDirectory(dir); err != nil {
		return nil, err
	}
	if b.modern() {
		if err := b.prepareSecurity(); err != nil {
			return nil, err
		}
	}
	if err := b.createAttributeExtensions(); err != nil {
		return nil, err
	}
	directoryNodes := append([]*ntfsNode(nil), b.nodes...)
	for _, node := range directoryNodes {
		if !node.dir {
			continue
		}
		idx, err := buildNTFSDirectoryIndex(node, b.modern())
		if errors.Is(err, errNTFSIndexRootCapacity) && node.id >= 16 && len(node.names) > 0 {
			if err := b.createDirectoryAttributeExtensions(node); err != nil {
				return nil, err
			}
			idx, err = buildNTFSDirectoryIndex(node, b.modern())
		}
		if errors.Is(err, errNTFSIndexRootCapacity) && node.id >= 16 {
			if err := b.createDirectoryIndexRootExtension(node); err != nil {
				return nil, err
			}
			idx, err = buildNTFSDirectoryIndex(node, b.modern())
		}
		if err != nil {
			return nil, err
		}
		node.index = idx
		if len(node.attributeList) > 0 {
			b.appendDirectoryIndexAttributeList(node)
		}
	}
	b.mftRecords = ntfsMFTRecordCapacity(b.nextID)
	mftClusters := fsinternal.CeilDiv(b.mftRecords*ntfsRecordSize, ntfsCluster)
	b.nextLCN = b.mftLCN + mftClusters
	b.mftMirrLCN = size / ntfsCluster / 2
	for _, node := range b.nodes {
		if len(node.attributeList) > 0 {
			node.attributeListLCN = b.allocate(fsinternal.CeilDiv(int64(len(node.attributeList)), ntfsCluster))
		}
	}
	b.mftBitmapData = b.mftBitmap()
	b.mftBitmapLCN = b.allocate(fsinternal.CeilDiv(int64(len(b.mftBitmapData)), ntfsCluster))
	if logFile == nil {
		logSize := ntfsDefaultLogFileSize(size)
		logData := bytes.Repeat([]byte{0xff}, int(logSize))
		if !b.modern() {
			logData = ntfsInitialLogFile(logSize)
		}
		logFile = &starfile.Bytes{Name: "$LogFile", Data: logData}
	}
	b.logFile = logFile
	b.logFileLCN = b.allocate(fsinternal.CeilDiv(b.logFile.Size(), ntfsCluster))
	b.attrDef = ntfsAttrDefData(b.modern())
	b.attrDefLCN = b.allocate(fsinternal.CeilDiv(int64(len(b.attrDef)), ntfsCluster))
	if upCase == nil {
		upCase = ntfsUpCaseData(b.modern())
	}
	b.upCase = upCase
	b.upCaseLCN = b.allocate(fsinternal.CeilDiv(int64(len(b.upCase)), ntfsCluster))
	if b.modern() {
		b.rootSecurity = ntfsRootSecurityDescriptor()
		b.rootSecurityLCN = b.allocate(fsinternal.CeilDiv(int64(len(b.rootSecurity)), ntfsCluster))
		b.secureLCN = b.allocate(fsinternal.CeilDiv(int64(len(b.secureData)), ntfsCluster))
		if len(b.secureIDIndex.blocks) > 0 {
			b.secureIDLCN = b.allocate(fsinternal.CeilDiv(int64(len(b.secureIDIndex.blocks)), ntfsCluster))
		}
		if len(b.secureHashIndex.blocks) > 0 {
			b.secureHashLCN = b.allocate(fsinternal.CeilDiv(int64(len(b.secureHashIndex.blocks)), ntfsCluster))
		}
	}
	b.bitmapSize = fsinternal.CeilDiv(size/ntfsCluster, 8)
	b.nodes[0].size = b.mftRecords * ntfsRecordSize
	b.nodes[1].size = minInt64(4, b.mftRecords) * ntfsRecordSize
	b.nodes[2].size = b.logFile.Size()
	b.nodes[6].size = b.bitmapSize
	b.nodes[10].size = int64(len(b.upCase))

	for _, node := range b.nodes {
		if node.dir && len(node.index.blocks) > 0 {
			node.indexLCN = b.allocate(fsinternal.CeilDiv(int64(len(node.index.blocks)), ntfsCluster))
		}
	}
	for _, node := range b.nodes {
		if node.dir || node.size == 0 || node.id < 12 {
			continue
		}
		node.clusters = fsinternal.CeilDiv(node.size, ntfsCluster)
		node.lcn = b.allocate(node.clusters)
	}
	b.bitmapLCN = b.allocate(fsinternal.CeilDiv(b.bitmapSize, ntfsCluster))
	if b.nextLCN*ntfsCluster > size-ntfsSectorSize {
		return nil, fmt.Errorf("ntfs: filesystem contents require %d bytes, volume has %d", b.nextLCN*ntfsCluster, size)
	}

	mft, err := b.mftData()
	if err != nil {
		return nil, err
	}
	mirrorSize := minInt64(4, b.mftRecords) * ntfsRecordSize
	bootData := b.bootData()
	bootSector := b.bootSector()
	extents := []filesystemapi.ExtentSpec{
		{Start: 0, Size: int64(len(bootData)), Data: bootData},
		{Start: b.size - ntfsSectorSize, Size: ntfsSectorSize, Data: bootSector},
		{Start: b.mftLCN * ntfsCluster, Size: int64(len(mft)), Data: mft},
		{Start: b.mftMirrLCN * ntfsCluster, Size: mirrorSize, Data: mft[:mirrorSize]},
		{Start: b.mftBitmapLCN * ntfsCluster, Size: int64(len(b.mftBitmapData)), Data: b.mftBitmapData},
		{Start: b.logFileLCN * ntfsCluster, Size: b.logFile.Size(), File: b.logFile},
		{Start: b.attrDefLCN * ntfsCluster, Size: int64(len(b.attrDef)), Data: b.attrDef},
		{Start: b.upCaseLCN * ntfsCluster, Size: int64(len(b.upCase)), Data: b.upCase},
		{Start: b.bitmapLCN * ntfsCluster, Size: b.bitmapSize, Data: b.volumeBitmap()},
	}
	if b.modern() {
		extents = append(extents,
			filesystemapi.ExtentSpec{Start: b.rootSecurityLCN * ntfsCluster, Size: int64(len(b.rootSecurity)), Data: b.rootSecurity},
			filesystemapi.ExtentSpec{Start: b.secureLCN * ntfsCluster, Size: int64(len(b.secureData)), Data: b.secureData},
		)
		if len(b.secureIDIndex.blocks) > 0 {
			extents = append(extents, filesystemapi.ExtentSpec{Start: b.secureIDLCN * ntfsCluster, Size: int64(len(b.secureIDIndex.blocks)), Data: b.secureIDIndex.blocks})
		}
		if len(b.secureHashIndex.blocks) > 0 {
			extents = append(extents, filesystemapi.ExtentSpec{Start: b.secureHashLCN * ntfsCluster, Size: int64(len(b.secureHashIndex.blocks)), Data: b.secureHashIndex.blocks})
		}
	}
	for _, node := range b.nodes {
		if len(node.index.blocks) > 0 {
			extents = append(extents, filesystemapi.ExtentSpec{Start: node.indexLCN * ntfsCluster, Size: int64(len(node.index.blocks)), Data: node.index.blocks})
		}
		if node.size > 0 && node.id >= 12 {
			extents = append(extents, filesystemapi.ExtentSpec{Start: node.lcn * ntfsCluster, Size: node.size, File: node.file, Data: node.data})
		}
		if len(node.attributeList) > 0 {
			extents = append(extents, filesystemapi.ExtentSpec{Start: node.attributeListLCN * ntfsCluster, Size: int64(len(node.attributeList)), Data: node.attributeList})
		}
	}
	sort.Slice(extents, func(i, j int) bool { return extents[i].Start < extents[j].Start })
	return filesystemapi.NewGeneratedImage("ntfs.raw", size, extents), nil
}

func (b *ntfsBuild) modern() bool {
	return b.versionMajor >= 3
}

func (b *ntfsBuild) logFileSize() int64 {
	if b.logFile == nil {
		return ntfsDefaultLogFileSize(b.size)
	}
	return b.logFile.Size()
}

func ntfsDefaultLogFileSize(volumeSize int64) int64 {
	// Legacy NT formats $LogFile at one percent of the volume, rounded up to
	// 64 KiB. Matching that policy prevents CHKDSK from resizing the journal
	// and requiring an otherwise unnecessary first-boot restart.
	size := fsinternal.Align(fsinternal.CeilDiv(volumeSize, 100), ntfsLogFileQuantum)
	if size < ntfsLogFileMinimum {
		return ntfsLogFileMinimum
	}
	if size > ntfsLogFileMaximum {
		return ntfsLogFileMaximum
	}
	return size
}

func ntfsInitialLogFile(size int64) []byte {
	data := bytes.Repeat([]byte{0xff}, int(size))
	const (
		pageSize      = 4096
		restartOffset = 0x30
		clientOffset  = 0x28
	)
	for pageIndex := 0; pageIndex < 2; pageIndex++ {
		page := data[pageIndex*pageSize : (pageIndex+1)*pageSize]
		clear(page)
		copy(page[0:4], "RSTR")
		binary.LittleEndian.PutUint16(page[4:6], 0x1e)
		binary.LittleEndian.PutUint16(page[6:8], uint16(pageSize/ntfsSectorSize+1))
		binary.LittleEndian.PutUint32(page[0x10:0x14], pageSize)
		binary.LittleEndian.PutUint32(page[0x14:0x18], pageSize)
		binary.LittleEndian.PutUint16(page[0x18:0x1a], restartOffset)
		binary.LittleEndian.PutUint16(page[0x1a:0x1c], 0)
		binary.LittleEndian.PutUint16(page[0x1c:0x1e], 1)

		restart := page[restartOffset:]
		binary.LittleEndian.PutUint16(restart[0x08:0x0a], 1)
		binary.LittleEndian.PutUint16(restart[0x0a:0x0c], 0xffff)
		binary.LittleEndian.PutUint16(restart[0x0c:0x0e], 0)
		binary.LittleEndian.PutUint16(restart[0x0e:0x10], 1)
		binary.LittleEndian.PutUint32(restart[0x10:0x14], ntfsLogSequenceNumberBits(size))
		binary.LittleEndian.PutUint16(restart[0x14:0x16], 0xc8)
		binary.LittleEndian.PutUint16(restart[0x16:0x18], clientOffset)
		binary.LittleEndian.PutUint64(restart[0x18:0x20], uint64(size))
		binary.LittleEndian.PutUint32(restart[0x20:0x24], 0x40)
		binary.LittleEndian.PutUint16(restart[0x24:0x26], 0x30)
		binary.LittleEndian.PutUint16(restart[0x26:0x28], 0x30)

		client := restart[clientOffset:]
		binary.LittleEndian.PutUint16(client[0x10:0x12], 0xffff)
		binary.LittleEndian.PutUint16(client[0x12:0x14], 0xffff)
		binary.LittleEndian.PutUint32(client[0x1c:0x20], 8)
		copy(client[0x20:0x28], utf16Bytes("NTFS"))
		applyNTFSFixup(page, 0x1e, uint16(pageSize/ntfsSectorSize+1))
	}
	return data
}

func ntfsLogSequenceNumberBits(size int64) uint32 {
	bits := uint32(0)
	for value := size - 1; value > 0; value >>= 1 {
		bits++
	}
	return 67 - bits
}

func (b *ntfsBuild) allocate(clusters int64) int64 {
	lcn := b.nextLCN
	mirrorClusters := fsinternal.CeilDiv(minInt64(4, b.mftRecords)*ntfsRecordSize, ntfsCluster)
	if lcn < b.mftMirrLCN+mirrorClusters && lcn+clusters > b.mftMirrLCN {
		lcn = b.mftMirrLCN + mirrorClusters
	}
	b.nextLCN += clusters
	if lcn != b.nextLCN-clusters {
		b.nextLCN = lcn + clusters
	}
	return lcn
}

func (b *ntfsBuild) importDirectory(dir *filesystemapi.Directory) error {
	snapshot := dir.Snapshot()
	recordNineName := "$Quota"
	recordNineKind := ""
	if b.modern() {
		recordNineName = "$Secure"
		recordNineKind = "secure"
	}
	system := []*ntfsNode{
		{id: 0, name: "$MFT", fullPath: "/$MFT"},
		{id: 1, name: "$MFTMirr", fullPath: "/$MFTMirr"},
		{id: 2, name: "$LogFile", fullPath: "/$LogFile"},
		{id: 3, name: "$Volume", fullPath: "/$Volume"},
		{id: 4, name: "$AttrDef", fullPath: "/$AttrDef", size: int64(len(ntfsAttrDefData(b.modern())))},
		{id: 5, name: ".", fullPath: "/", dir: true},
		{id: 6, name: "$Bitmap", fullPath: "/$Bitmap"},
		{id: 7, name: "$Boot", fullPath: "/$Boot", size: b.bootFileSize()},
		{id: 8, name: "$BadClus", fullPath: "/$BadClus"},
		{id: 9, name: recordNineName, fullPath: "/" + recordNineName, systemKind: recordNineKind},
		{id: 10, name: "$UpCase", fullPath: "/$UpCase", size: 65536 * 2},
		{id: 11, name: "$Extend", fullPath: "/$Extend", dir: true},
	}
	b.root = system[5]
	for _, node := range system {
		node.parent = b.root
		if node.id != 5 {
			node.attrs.Hidden = true
			node.attrs.System = true
		}
		b.nodes = append(b.nodes, node)
	}
	for _, node := range append(system[:6], system[6:]...) {
		b.root.children = append(b.root.children, &ntfsDirectoryLink{node: node, name: node.name})
	}
	if b.modern() {
		for id := uint64(12); id < 16; id++ {
			b.nodes = append(b.nodes, &ntfsNode{
				id:         id,
				fullPath:   fmt.Sprintf("/$Reserved%d", id),
				systemKind: "reserved",
			})
		}
		extend := system[11]
		for _, spec := range []struct {
			id   uint64
			name string
			kind string
		}{
			{id: 24, name: "$Quota", kind: "quota"},
			{id: 25, name: "$ObjId", kind: "object_id"},
			{id: 26, name: "$Reparse", kind: "reparse"},
		} {
			node := &ntfsNode{
				id:         spec.id,
				name:       spec.name,
				fullPath:   "/$Extend/" + spec.name,
				parent:     extend,
				systemKind: spec.kind,
				attrs:      filesystemapi.Attributes{Hidden: true, System: true},
			}
			extend.children = append(extend.children, &ntfsDirectoryLink{node: node, name: node.name})
			b.nodes = append(b.nodes, node)
		}
		b.nextID = 27
	}

	byPath := map[string]*ntfsNode{"/": b.root}
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
	hardLinks := make(map[uint64]*ntfsNode)
	for _, name := range files {
		parent := b.ensureDir(byPath, path.Dir(name))
		vf := snapshot.Files[name]
		metadata := snapshot.Metadata[name]
		if existing := ntfsChildByName(parent, path.Base(name)); existing != nil {
			if existing.dir || vf.WriteOrder <= existing.writeOrder {
				continue
			}
			existing.name = path.Base(name)
			existing.fullPath = name
			existing.size = vf.Size
			existing.file = vf.File
			existing.data = vf.Data
			existing.writeOrder = vf.WriteOrder
			continue
		}
		if metadata.HardLink != 0 {
			if node := hardLinks[metadata.HardLink]; node != nil {
				if node.size != vf.Size {
					return fmt.Errorf("ntfs: hard-linked files %q and %q have different sizes", node.fullPath, name)
				}
				parent.children = append(parent.children, &ntfsDirectoryLink{node: node, name: path.Base(name), shortName: metadata.ShortName})
				continue
			}
		}
		node := &ntfsNode{id: b.nextID, name: path.Base(name), fullPath: name, parent: parent, size: vf.Size, file: vf.File, data: vf.Data, attrs: snapshot.Attributes[name], metadata: metadata, writeOrder: vf.WriteOrder}
		b.nextID++
		parent.children = append(parent.children, &ntfsDirectoryLink{node: node, name: node.name, shortName: metadata.ShortName})
		b.nodes = append(b.nodes, node)
		if metadata.HardLink != 0 {
			hardLinks[metadata.HardLink] = node
		}
	}
	for name, attrs := range snapshot.Attributes {
		name = storage.CleanPath(name)
		var node *ntfsNode
		if candidate := byPath[strings.ToLower(name)]; candidate != nil {
			node = candidate
		} else if parent := byPath[strings.ToLower(path.Dir(name))]; parent != nil {
			node = ntfsChildByName(parent, path.Base(name))
		}
		if node != nil {
			node.attrs = attrs
		}
	}
	for name, metadata := range snapshot.Metadata {
		name = storage.CleanPath(name)
		if node := byPath[strings.ToLower(name)]; node != nil {
			node.metadata = metadata
		}
	}
	for _, node := range b.nodes {
		sort.Slice(node.children, func(i, j int) bool {
			return ntfsCompareName(node.children[i].name, node.children[j].name) < 0
		})
	}
	return b.assignFileNames()
}

func (b *ntfsBuild) ensureDir(byPath map[string]*ntfsNode, name string) *ntfsNode {
	name = storage.CleanPath(name)
	key := strings.ToLower(name)
	if node := byPath[key]; node != nil {
		return node
	}
	parent := b.ensureDir(byPath, path.Dir(name))
	if node := ntfsChildByName(parent, path.Base(name)); node != nil && node.dir {
		byPath[key] = node
		return node
	}
	node := &ntfsNode{id: b.nextID, name: path.Base(name), fullPath: name, parent: parent, dir: true}
	b.nextID++
	byPath[key] = node
	parent.children = append(parent.children, &ntfsDirectoryLink{node: node, name: node.name})
	b.nodes = append(b.nodes, node)
	return node
}

func ntfsChildByName(parent *ntfsNode, name string) *ntfsNode {
	for _, link := range parent.children {
		if strings.EqualFold(link.name, name) {
			return link.node
		}
	}
	return nil
}

func (b *ntfsBuild) assignFileNames() error {
	linkCounts := make(map[*ntfsNode]int, len(b.nodes))
	for _, parent := range b.nodes {
		for _, link := range parent.children {
			linkCounts[link.node]++
		}
	}
	for _, parent := range b.nodes {
		if !parent.dir {
			continue
		}
		used := make(map[string]*ntfsNode, len(parent.children))
		for _, link := range parent.children {
			key := strings.ToUpper(link.name)
			if owner := used[key]; owner != nil {
				return fmt.Errorf("ntfs: %q and %q collide in %s", owner.name, link.name, parent.fullPath)
			}
			used[key] = link.node
		}
		for _, link := range parent.children {
			child := link.node
			if linkCounts[child] > 1 {
				link.names = []ntfsName{{value: link.name, namespace: 0, parent: parent}}
				child.names = append(child.names, link.names...)
				continue
			}
			if child.id < 16 {
				link.names = []ntfsName{{value: link.name, namespace: 3, parent: parent}}
				child.names = append(child.names, link.names...)
				continue
			}
			upper, exact := ntfsDOSName(link.name)
			if link.shortName != "" && !strings.EqualFold(link.shortName, link.name) {
				upper, exact = link.shortName, false
			}
			if exact {
				link.names = []ntfsName{{value: link.name, namespace: 3, parent: parent}}
				child.names = append(child.names, link.names...)
				continue
			}
			alias := upper
			if owner := used[alias]; alias == "" || owner != nil && owner != child {
				alias = ntfsDOSAlias(link.name, child, used)
			}
			used[alias] = child
			link.names = []ntfsName{
				{value: alias, namespace: 2, parent: parent},
				{value: link.name, namespace: 1, parent: parent},
			}
			child.names = append(child.names, link.names...)
		}
	}
	for _, node := range b.nodes {
		for _, name := range node.names {
			if name.namespace != 2 {
				node.linkCount++
			}
		}
	}
	return nil
}

func (b *ntfsBuild) createAttributeExtensions() error {
	baseNodes := append([]*ntfsNode(nil), b.nodes...)
	for _, node := range baseNodes {
		if node.dir || node.id < 16 || len(node.names) < 2 || ntfsNodeRecordSize(node, node.names, false) <= int(ntfsRecordSize) {
			continue
		}
		allNames := append([]ntfsName(nil), node.names...)
		for index := range allNames {
			allNames[index].attrID = uint16(index + 1)
		}
		baseCount := min(2, len(allNames))
		for baseCount > 0 && ntfsNodeRecordSize(node, allNames[:baseCount], true) > int(ntfsRecordSize) {
			baseCount--
		}
		if baseCount == 0 {
			return fmt.Errorf("ntfs: MFT base record for %q cannot hold its fixed attributes", node.fullPath)
		}
		if err := b.createNameAttributeExtensions(node, allNames, baseCount); err != nil {
			return err
		}
		node.attributeList = append(node.attributeList, ntfsAttributeListEntry(ntfsAttrData, node.dataAttributeID, node.id)...)
	}
	return nil
}

func (b *ntfsBuild) createDirectoryAttributeExtensions(node *ntfsNode) error {
	allNames := append([]ntfsName(nil), node.names...)
	if err := b.createNameAttributeExtensions(node, allNames, 0); err != nil {
		return fmt.Errorf("ntfs: extend directory %q: %w", node.fullPath, err)
	}
	return nil
}

func (b *ntfsBuild) createDirectoryIndexRootExtension(node *ntfsNode) error {
	if len(node.attributeList) == 0 {
		allNames := append([]ntfsName(nil), node.names...)
		if err := b.createNameAttributeExtensions(node, allNames, len(allNames)); err != nil {
			return fmt.Errorf("ntfs: prepare directory %q attribute list: %w", node.fullPath, err)
		}
	}
	extension := &ntfsNode{
		id:                 b.nextID,
		extensionOf:        node,
		extensionIndexRoot: true,
		fullPath:           node.fullPath + "::$I30:$INDEX_ROOT",
	}
	b.nextID++
	node.indexRootRecordID = extension.id
	b.nodes = append(b.nodes, extension)
	return nil
}

func (b *ntfsBuild) createNameAttributeExtensions(node *ntfsNode, allNames []ntfsName, baseCount int) error {
	for index := range allNames {
		allNames[index].attrID = uint16(index + 1)
	}
	node.names = allNames[:baseCount]
	node.attributeListID = uint16(len(allNames) + 1)
	node.dataAttributeID = node.attributeListID + 1
	ownerByAttribute := make(map[uint16]uint64, len(allNames))
	for _, name := range node.names {
		ownerByAttribute[name.attrID] = node.id
	}
	remaining := allNames[baseCount:]
	for len(remaining) > 0 {
		extension := &ntfsNode{id: b.nextID, extensionOf: node, fullPath: node.fullPath + "::$ATTRIBUTE_LIST"}
		b.nextID++
		used := ntfsExtensionRecordHeaderSize()
		for len(remaining) > 0 {
			attributeSize := len(ntfsResidentAttr(ntfsAttrFileName, "", ntfsFileNameAttribute(node, remaining[0])))
			if used+attributeSize+4 > int(ntfsRecordSize) {
				break
			}
			extension.extensionNames = append(extension.extensionNames, remaining[0])
			remaining = remaining[1:]
			used += attributeSize
		}
		if len(extension.extensionNames) == 0 {
			return fmt.Errorf("file name for %q cannot fit in an extension record", node.fullPath)
		}
		for _, name := range extension.extensionNames {
			ownerByAttribute[name.attrID] = extension.id
		}
		b.nodes = append(b.nodes, extension)
	}
	list := ntfsAttributeListEntry(ntfsAttrStandardInformation, 0, node.id)
	for _, name := range allNames {
		list = append(list, ntfsAttributeListEntry(ntfsAttrFileName, name.attrID, ownerByAttribute[name.attrID])...)
	}
	node.attributeList = list
	return nil
}

func (b *ntfsBuild) appendDirectoryIndexAttributeList(node *ntfsNode) {
	id := node.dataAttributeID
	rootRecordID := node.id
	if node.indexRootRecordID != 0 {
		rootRecordID = node.indexRootRecordID
	}
	node.attributeList = append(node.attributeList, ntfsNamedAttributeListEntry(ntfsAttrIndexRoot, "$I30", id, rootRecordID)...)
	if len(node.index.blocks) > 0 {
		node.attributeList = append(node.attributeList, ntfsNamedAttributeListEntry(ntfsAttrIndexAllocation, "$I30", id+1, node.id)...)
		node.attributeList = append(node.attributeList, ntfsNamedAttributeListEntry(ntfsAttrBitmap, "$I30", id+2, node.id)...)
	}
}

func ntfsNodeRecordSize(node *ntfsNode, names []ntfsName, attributeList bool) int {
	used := align8(0x30 + (int(ntfsRecordSize)/int(ntfsSectorSize)+1)*2)
	used += len(ntfsResidentAttr(ntfsAttrStandardInformation, "", ntfsStandardInformation(node, true)))
	if attributeList {
		used += len(ntfsNonResidentAttr(ntfsAttrAttributeList, "", 1, 1))
	}
	for _, name := range names {
		used += len(ntfsResidentAttr(ntfsAttrFileName, "", ntfsFileNameAttribute(node, name)))
	}
	if node.size > 0 {
		used += len(ntfsNonResidentAttr(ntfsAttrData, "", 1, node.size))
	} else {
		used += len(ntfsResidentAttr(ntfsAttrData, "", nil))
	}
	return align8(used + 4)
}

func ntfsExtensionRecordHeaderSize() int {
	return align8(0x30 + (int(ntfsRecordSize)/int(ntfsSectorSize)+1)*2)
}

func ntfsAttributeListEntry(typ uint32, attributeID uint16, recordID uint64) []byte {
	return ntfsNamedAttributeListEntry(typ, "", attributeID, recordID)
}

func ntfsNamedAttributeListEntry(typ uint32, name string, attributeID uint16, recordID uint64) []byte {
	nameBytes := utf16Bytes(name)
	entry := make([]byte, align8(26+len(nameBytes)))
	binary.LittleEndian.PutUint32(entry[0:4], typ)
	binary.LittleEndian.PutUint16(entry[4:6], uint16(len(entry)))
	entry[7] = 26
	if len(nameBytes) > 0 {
		entry[6] = byte(len([]rune(name)))
		copy(entry[26:], nameBytes)
	}
	binary.LittleEndian.PutUint64(entry[16:24], ntfsFileReference(recordID))
	binary.LittleEndian.PutUint16(entry[24:26], attributeID)
	return entry
}

func buildNTFSDirectoryIndex(node *ntfsNode, modern bool) (ntfsDirectoryIndex, error) {
	var items []*ntfsIndexKey
	for _, link := range node.children {
		for _, name := range link.names {
			items = append(items, &ntfsIndexKey{node: link.node, name: name})
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		return ntfsCompareName(items[i].name.value, items[j].name.value) < 0
	})
	if ntfsIndexEntriesSize(items, false)+32 <= ntfsIndexRootLimit(node, false, 0, modern) {
		entries := make([][]byte, 0, len(items)+1)
		for _, item := range items {
			entries = append(entries, ntfsIndexEntry(item, false, 0))
		}
		entries = append(entries, ntfsIndexEndEntry(false, 0))
		return ntfsDirectoryIndex{rootValue: ntfsIndexRootValue(entries, false)}, nil
	}

	level, separators, err := ntfsLeafLevel(items)
	if err != nil {
		return ntfsDirectoryIndex{}, fmt.Errorf("ntfs: build index for %s: %w", node.fullPath, err)
	}
	// The index bitmap has one bit per allocated INDX block, not one bit per
	// directory entry.  A balanced tree needs fewer than twice as many blocks
	// as its leaf level, including all intermediate levels.
	maxBitmapBytes := align8(int(fsinternal.CeilDiv(int64(len(level)*2), 8)))
	for ntfsIndexEntriesSize(separators, true)+32 > ntfsIndexRootLimit(node, true, maxBitmapBytes, modern) {
		nextLevel, nextSeparators := ntfsParentLevel(
			level,
			separators,
			ntfsIndexRootLimit(node, true, maxBitmapBytes, modern),
		)
		if len(nextLevel) >= len(level) {
			return ntfsDirectoryIndex{}, fmt.Errorf("%w: %s", errNTFSIndexRootCapacity, node.fullPath)
		}
		level, separators = nextLevel, nextSeparators
	}
	root := &ntfsIndexTreeNode{keys: separators, children: level}
	var allocation []*ntfsIndexTreeNode
	var assign func(*ntfsIndexTreeNode)
	assign = func(current *ntfsIndexTreeNode) {
		for _, child := range current.children {
			assign(child)
		}
		if current != root {
			current.vcn = ntfsIndexVCN(len(allocation))
			allocation = append(allocation, current)
		}
	}
	assign(root)

	rootEntries := ntfsTreeEntries(root)
	rootValue := ntfsIndexRootValue(rootEntries, true)
	blocks := make([]byte, 0, len(allocation)*int(ntfsIndexSize))
	for _, current := range allocation {
		blocks = append(blocks, ntfsIndexBlock(current.vcn, ntfsTreeEntries(current), len(current.children) > 0)...)
	}
	blockCount := len(allocation)
	bitmap := make([]byte, align8(int(fsinternal.CeilDiv(int64(blockCount), 8))))
	for i := 0; i < blockCount; i++ {
		bitmap[i/8] |= 1 << uint(i%8)
	}
	return ntfsDirectoryIndex{rootValue: rootValue, blocks: blocks, bitmap: bitmap}, nil
}

func ntfsIndexVCN(block int) uint64 {
	return uint64(block) * uint64(ntfsIndexSize/ntfsCluster)
}

func ntfsIndexRootLimit(node *ntfsNode, allocated bool, bitmapBytes int, modern bool) int {
	if node.indexRootRecordID != 0 {
		available := int(ntfsRecordSize) - ntfsExtensionRecordHeaderSize() - 4
		valueOffset := align8(24 + len(utf16Bytes("$I30")))
		return available&^7 - valueOffset
	}
	usaOffset := 0x2a
	if modern {
		usaOffset = 0x30
	}
	used := align8(usaOffset + (int(ntfsRecordSize)/int(ntfsSectorSize)+1)*2)
	legacySecurity := ntfsUsesLegacySecurityRecord(modern, node)
	used += len(ntfsResidentAttr(ntfsAttrStandardInformation, "", ntfsStandardInformation(node, modern && !legacySecurity)))
	if len(node.attributeList) > 0 {
		used += len(ntfsNonResidentAttr(ntfsAttrAttributeList, "", 1<<24, int64(len(node.attributeList))))
	}
	for _, name := range node.names {
		used += len(ntfsResidentAttr(ntfsAttrFileName, "", ntfsFileNameAttribute(node, name)))
	}
	if modern && node.id == 5 {
		used += len(ntfsNonResidentAttr(ntfsAttrSecurityDescriptor, "", 1<<24, int64(len(ntfsRootSecurityDescriptor()))))
	} else if legacySecurity {
		used += len(ntfsResidentAttr(ntfsAttrSecurityDescriptor, "", ntfsLegacySecurityDescriptor()))
	}
	if allocated {
		used += len(ntfsNonResidentAttr(ntfsAttrIndexAllocation, "$I30", 1<<24, ntfsIndexSize))
		used += len(ntfsResidentAttr(ntfsAttrBitmap, "$I30", make([]byte, bitmapBytes)))
	}
	available := int(ntfsRecordSize) - used - 4
	valueOffset := align8(24 + len(utf16Bytes("$I30")))
	limit := available&^7 - valueOffset
	if limit < 0 {
		return 0
	}
	return limit
}

type ntfsIndexTreeNode struct {
	keys     []*ntfsIndexKey
	children []*ntfsIndexTreeNode
	vcn      uint64
}

func ntfsIndexEntriesSize(items []*ntfsIndexKey, subnodes bool) int {
	size := 16
	for _, item := range items {
		size += len(ntfsIndexEntry(item, subnodes, 0))
	}
	if subnodes {
		size += 8
	}
	return size
}

func ntfsLeafLevel(items []*ntfsIndexKey) ([]*ntfsIndexTreeNode, []*ntfsIndexKey, error) {
	const capacity = int(ntfsIndexSize) - 0x58
	var level []*ntfsIndexTreeNode
	var separators []*ntfsIndexKey
	for index := 0; index < len(items); {
		current := &ntfsIndexTreeNode{}
		used := 16
		for index < len(items) {
			entrySize := len(ntfsIndexEntry(items[index], false, 0))
			if used+entrySize <= capacity {
				current.keys = append(current.keys, items[index])
				used += entrySize
				index++
				continue
			}
			if len(current.keys) == 0 {
				return nil, nil, fmt.Errorf("index entry %q is larger than an index block", items[index].name.value)
			}
			if index == len(items)-1 {
				separators = append(separators, current.keys[len(current.keys)-1])
				current.keys = current.keys[:len(current.keys)-1]
			} else {
				separators = append(separators, items[index])
				index++
			}
			break
		}
		level = append(level, current)
	}
	return level, separators, nil
}

func ntfsParentLevel(children []*ntfsIndexTreeNode, separators []*ntfsIndexKey, rootLimit int) ([]*ntfsIndexTreeNode, []*ntfsIndexKey) {
	const capacity = int(ntfsIndexSize) - 0x58
	if len(children) > 1 && ntfsIndexEntriesSize(separators, true) <= capacity {
		middle := len(separators) / 2
		for distance := 0; distance < len(separators); distance++ {
			candidates := []int{middle - distance, middle + distance}
			for _, candidate := range candidates {
				if candidate < 0 || candidate >= len(separators) {
					continue
				}
				if ntfsIndexEntriesSize(separators[candidate:candidate+1], true)+32 <= rootLimit {
					middle = candidate
					distance = len(separators)
					break
				}
			}
		}
		left := &ntfsIndexTreeNode{
			keys:     append([]*ntfsIndexKey(nil), separators[:middle]...),
			children: append([]*ntfsIndexTreeNode(nil), children[:middle+1]...),
		}
		right := &ntfsIndexTreeNode{
			keys:     append([]*ntfsIndexKey(nil), separators[middle+1:]...),
			children: append([]*ntfsIndexTreeNode(nil), children[middle+1:]...),
		}
		return []*ntfsIndexTreeNode{left, right}, []*ntfsIndexKey{separators[middle]}
	}
	var level []*ntfsIndexTreeNode
	var promoted []*ntfsIndexKey
	childIndex, separatorIndex := 0, 0
	for childIndex < len(children) {
		current := &ntfsIndexTreeNode{children: []*ntfsIndexTreeNode{children[childIndex]}}
		childIndex++
		used := 24
		for separatorIndex < len(separators) {
			entrySize := len(ntfsIndexEntry(separators[separatorIndex], true, 0))
			if used+entrySize <= capacity {
				current.keys = append(current.keys, separators[separatorIndex])
				current.children = append(current.children, children[childIndex])
				used += entrySize
				separatorIndex++
				childIndex++
				continue
			}
			promoted = append(promoted, separators[separatorIndex])
			separatorIndex++
			break
		}
		level = append(level, current)
	}
	return level, promoted
}

func ntfsTreeEntries(node *ntfsIndexTreeNode) [][]byte {
	hasChildren := len(node.children) > 0
	entries := make([][]byte, 0, len(node.keys)+1)
	for index, key := range node.keys {
		vcn := uint64(0)
		if hasChildren {
			vcn = node.children[index].vcn
		}
		entries = append(entries, ntfsIndexEntry(key, hasChildren, vcn))
	}
	endVCN := uint64(0)
	if hasChildren {
		endVCN = node.children[len(node.children)-1].vcn
	}
	entries = append(entries, ntfsIndexEndEntry(hasChildren, endVCN))
	return entries
}

func ntfsIndexRootValue(entries [][]byte, hasAllocation bool) []byte {
	entryBytes := joinBytes(entries)
	value := make([]byte, 32+len(entryBytes))
	binary.LittleEndian.PutUint32(value[0:4], ntfsAttrFileName)
	binary.LittleEndian.PutUint32(value[4:8], 1)
	binary.LittleEndian.PutUint32(value[8:12], uint32(ntfsIndexSize))
	value[12] = byte(ntfsIndexSize / ntfsCluster)
	binary.LittleEndian.PutUint32(value[16:20], 16)
	binary.LittleEndian.PutUint32(value[20:24], uint32(16+len(entryBytes)))
	binary.LittleEndian.PutUint32(value[24:28], uint32(16+len(entryBytes)))
	if hasAllocation {
		value[28] = ntfsIndexNode
	}
	copy(value[32:], entryBytes)
	return value
}

func ntfsMetadataIndexRoot(collation uint32, entries ...[]byte) []byte {
	entryBytes := joinBytes(append(entries, ntfsMetadataIndexEndEntry()))
	value := make([]byte, 32+len(entryBytes))
	binary.LittleEndian.PutUint32(value[4:8], collation)
	binary.LittleEndian.PutUint32(value[8:12], uint32(ntfsIndexSize))
	value[12] = byte(ntfsIndexSize / ntfsCluster)
	binary.LittleEndian.PutUint32(value[16:20], 16)
	binary.LittleEndian.PutUint32(value[20:24], uint32(16+len(entryBytes)))
	binary.LittleEndian.PutUint32(value[24:28], uint32(16+len(entryBytes)))
	copy(value[32:], entryBytes)
	return value
}

func ntfsMetadataIndexEndEntry() []byte {
	entry := make([]byte, 16)
	binary.LittleEndian.PutUint16(entry[8:10], uint16(len(entry)))
	binary.LittleEndian.PutUint16(entry[12:14], ntfsIndexLast)
	return entry
}

func ntfsEmptyIndexRoot(collation uint32) []byte {
	return ntfsMetadataIndexRoot(collation)
}

func ntfsSecurityHashIndexRoot(hash, securityID uint32, offset uint64, length uint32) []byte {
	entry := make([]byte, 48)
	binary.LittleEndian.PutUint16(entry[0:2], 24)
	binary.LittleEndian.PutUint16(entry[2:4], 20)
	binary.LittleEndian.PutUint16(entry[8:10], uint16(len(entry)))
	binary.LittleEndian.PutUint16(entry[10:12], 8)
	binary.LittleEndian.PutUint32(entry[16:20], hash)
	binary.LittleEndian.PutUint32(entry[20:24], securityID)
	ntfsSecurityIndexData(entry[24:], hash, securityID, offset, length)
	return ntfsMetadataIndexRoot(0x12, entry)
}

func ntfsSecurityIDIndexRoot(hash, securityID uint32, offset uint64, length uint32) []byte {
	entry := make([]byte, 40)
	binary.LittleEndian.PutUint16(entry[0:2], 20)
	binary.LittleEndian.PutUint16(entry[2:4], 20)
	binary.LittleEndian.PutUint16(entry[8:10], uint16(len(entry)))
	binary.LittleEndian.PutUint16(entry[10:12], 4)
	binary.LittleEndian.PutUint32(entry[16:20], securityID)
	ntfsSecurityIndexData(entry[20:], hash, securityID, offset, length)
	return ntfsMetadataIndexRoot(0x10, entry)
}

func ntfsSecurityIndexData(data []byte, hash, securityID uint32, offset uint64, length uint32) {
	binary.LittleEndian.PutUint32(data[0:4], hash)
	binary.LittleEndian.PutUint32(data[4:8], securityID)
	binary.LittleEndian.PutUint64(data[8:16], offset)
	binary.LittleEndian.PutUint32(data[16:20], length)
}

func ntfsIndexBlock(vcn uint64, entries [][]byte, hasChildren bool) []byte {
	const entryOffset = 0x58
	block := make([]byte, ntfsIndexSize)
	copy(block[0:4], "INDX")
	usaOff := uint16(0x28)
	usaCount := uint16(ntfsIndexSize/ntfsSectorSize + 1)
	binary.LittleEndian.PutUint16(block[4:6], usaOff)
	binary.LittleEndian.PutUint16(block[6:8], usaCount)
	binary.LittleEndian.PutUint64(block[16:24], vcn)
	entryBytes := joinBytes(entries)
	binary.LittleEndian.PutUint32(block[24:28], entryOffset-0x18)
	binary.LittleEndian.PutUint32(block[28:32], uint32(entryOffset-0x18+len(entryBytes)))
	binary.LittleEndian.PutUint32(block[32:36], uint32(ntfsIndexSize-0x18))
	if hasChildren {
		block[36] = ntfsIndexNode
	}
	copy(block[entryOffset:], entryBytes)
	applyNTFSFixup(block, usaOff, usaCount)
	return block
}

func ntfsIndexEntry(key *ntfsIndexKey, hasSubnode bool, vcn uint64) []byte {
	value := ntfsFileNameAttribute(key.node, key.name)
	length := align8(16 + len(value))
	if hasSubnode {
		length = align8(length + 8)
	}
	entry := make([]byte, length)
	binary.LittleEndian.PutUint64(entry[0:8], ntfsFileReference(key.node.id))
	binary.LittleEndian.PutUint16(entry[8:10], uint16(length))
	binary.LittleEndian.PutUint16(entry[10:12], uint16(len(value)))
	if hasSubnode {
		binary.LittleEndian.PutUint16(entry[12:14], ntfsIndexHasSub)
		binary.LittleEndian.PutUint64(entry[length-8:length], vcn)
	}
	copy(entry[16:], value)
	return entry
}

func ntfsIndexEndEntry(hasSubnode bool, vcn uint64) []byte {
	length := 16
	if hasSubnode {
		length = 24
	}
	entry := make([]byte, length)
	binary.LittleEndian.PutUint16(entry[8:10], uint16(length))
	flags := uint16(ntfsIndexLast)
	if hasSubnode {
		flags |= ntfsIndexHasSub
		binary.LittleEndian.PutUint64(entry[length-8:length], vcn)
	}
	binary.LittleEndian.PutUint16(entry[12:14], flags)
	return entry
}

func (b *ntfsBuild) mftData() ([]byte, error) {
	data := make([]byte, b.mftRecords*ntfsRecordSize)
	for _, node := range b.nodes {
		record, err := b.mftRecord(node)
		if err != nil {
			return nil, err
		}
		copy(data[int64(node.id)*ntfsRecordSize:], record)
	}
	return data, nil
}

func (b *ntfsBuild) mftRecord(node *ntfsNode) ([]byte, error) {
	record := make([]byte, ntfsRecordSize)
	copy(record[0:4], "FILE")
	usaOff := uint16(0x2a)
	if b.modern() {
		usaOff = 0x30
		binary.LittleEndian.PutUint32(record[44:48], uint32(node.id))
	}
	usaCount := uint16(ntfsRecordSize/ntfsSectorSize + 1)
	binary.LittleEndian.PutUint16(record[4:6], usaOff)
	binary.LittleEndian.PutUint16(record[6:8], usaCount)
	binary.LittleEndian.PutUint16(record[16:18], ntfsSequenceNumber(node.id))
	binary.LittleEndian.PutUint16(record[18:20], node.linkCount)
	attrOff := align8(int(usaOff) + int(usaCount)*2)
	binary.LittleEndian.PutUint16(record[20:22], uint16(attrOff))
	if node.extensionOf != nil {
		binary.LittleEndian.PutUint16(record[22:24], ntfsFileInUse)
		binary.LittleEndian.PutUint64(record[32:40], ntfsFileReference(node.extensionOf.id))
		offset := attrOff
		nextAttributeID := uint16(0)
		for _, name := range node.extensionNames {
			attribute := ntfsResidentFileNameAttr(node.extensionOf, name)
			if offset+len(attribute)+4 > len(record) {
				return nil, fmt.Errorf("ntfs: extension MFT record for %q overflowed", node.extensionOf.fullPath)
			}
			binary.LittleEndian.PutUint16(attribute[14:16], name.attrID)
			copy(record[offset:], attribute)
			offset += len(attribute)
			if name.attrID >= nextAttributeID {
				nextAttributeID = name.attrID + 1
			}
		}
		if node.extensionIndexRoot {
			attribute := ntfsResidentAttr(ntfsAttrIndexRoot, "$I30", node.extensionOf.index.rootValue)
			if offset+len(attribute)+4 > len(record) {
				return nil, fmt.Errorf("ntfs: index-root extension for %q overflowed", node.extensionOf.fullPath)
			}
			binary.LittleEndian.PutUint16(attribute[14:16], node.extensionOf.dataAttributeID)
			copy(record[offset:], attribute)
			offset += len(attribute)
			if node.extensionOf.dataAttributeID >= nextAttributeID {
				nextAttributeID = node.extensionOf.dataAttributeID + 1
			}
		}
		binary.LittleEndian.PutUint32(record[offset:offset+4], ntfsAttrEnd)
		offset = align8(offset + 4)
		binary.LittleEndian.PutUint32(record[24:28], uint32(offset))
		binary.LittleEndian.PutUint32(record[28:32], uint32(len(record)))
		binary.LittleEndian.PutUint16(record[40:42], nextAttributeID)
		applyNTFSFixup(record, usaOff, usaCount)
		return record, nil
	}
	flags := uint16(ntfsFileInUse)
	if node.dir {
		flags |= ntfsFileDir
	}
	switch node.systemKind {
	case "secure":
		flags |= ntfsFileMetaIndex
	case "quota", "object_id", "reparse":
		flags |= ntfsFileViewIndex | ntfsFileMetaIndex
	}
	binary.LittleEndian.PutUint16(record[22:24], flags)

	legacySecurity := b.legacySecurityRecord(node)
	attrs := [][]byte{ntfsResidentAttr(ntfsAttrStandardInformation, "", ntfsStandardInformation(node, b.modern() && !legacySecurity))}
	var explicitIDs []uint16
	if len(node.attributeList) > 0 {
		explicitIDs = append(explicitIDs, 0)
		attrs = append(attrs, ntfsNonResidentAttr(ntfsAttrAttributeList, "", node.attributeListLCN, int64(len(node.attributeList))))
		explicitIDs = append(explicitIDs, node.attributeListID)
	}
	if node.id != 5 || node.dir {
		for _, name := range node.names {
			attrs = append(attrs, ntfsResidentFileNameAttr(node, name))
			if explicitIDs != nil {
				explicitIDs = append(explicitIDs, name.attrID)
			}
		}
	}
	if b.modern() && node.id == 5 {
		attrs = append(attrs, ntfsNonResidentAttr(ntfsAttrSecurityDescriptor, "", b.rootSecurityLCN, int64(len(b.rootSecurity))))
	} else if !b.modern() || legacySecurity {
		descriptor := ntfsLegacySecurityDescriptor()
		if node.systemKind == "reserved" {
			descriptor = ntfsMetadataSecurityDescriptor(0x0012019f)
		}
		attrs = append(attrs, ntfsResidentAttr(ntfsAttrSecurityDescriptor, "", descriptor))
	}
	switch node.systemKind {
	case "secure":
		attrs = append(attrs,
			ntfsNonResidentAttr(ntfsAttrData, "$SDS", b.secureLCN, int64(len(b.secureData))),
			ntfsResidentAttr(ntfsAttrIndexRoot, "$SDH", b.secureHashIndex.rootValue),
			ntfsResidentAttr(ntfsAttrIndexRoot, "$SII", b.secureIDIndex.rootValue),
		)
		if len(b.secureHashIndex.blocks) > 0 {
			attrs = append(attrs, ntfsNonResidentAttr(ntfsAttrIndexAllocation, "$SDH", b.secureHashLCN, int64(len(b.secureHashIndex.blocks))))
		}
		if len(b.secureIDIndex.blocks) > 0 {
			attrs = append(attrs, ntfsNonResidentAttr(ntfsAttrIndexAllocation, "$SII", b.secureIDLCN, int64(len(b.secureIDIndex.blocks))))
		}
		if len(b.secureHashIndex.blocks) > 0 {
			attrs = append(attrs, ntfsResidentAttr(ntfsAttrBitmap, "$SDH", b.secureHashIndex.bitmap))
		}
		if len(b.secureIDIndex.blocks) > 0 {
			attrs = append(attrs, ntfsResidentAttr(ntfsAttrBitmap, "$SII", b.secureIDIndex.bitmap))
		}
	case "quota":
		attrs = append(attrs,
			ntfsResidentAttr(ntfsAttrIndexRoot, "$O", ntfsEmptyIndexRoot(0x11)),
			ntfsResidentAttr(ntfsAttrIndexRoot, "$Q", ntfsEmptyIndexRoot(0x10)),
		)
	case "object_id":
		attrs = append(attrs, ntfsResidentAttr(ntfsAttrIndexRoot, "$O", ntfsEmptyIndexRoot(0x13)))
	case "reparse":
		attrs = append(attrs, ntfsResidentAttr(ntfsAttrIndexRoot, "$R", ntfsEmptyIndexRoot(0x13)))
	default:
		switch node.id {
		case 0:
			attrs = append(attrs, ntfsNonResidentAttr(ntfsAttrData, "", b.mftLCN, b.mftRecords*ntfsRecordSize))
			attrs = append(attrs, ntfsNonResidentAttr(ntfsAttrBitmap, "", b.mftBitmapLCN, int64(len(b.mftBitmapData))))
		case 1:
			attrs = append(attrs, ntfsNonResidentAttr(ntfsAttrData, "", b.mftMirrLCN, minInt64(4*ntfsRecordSize, b.mftRecords*ntfsRecordSize)))
		case 2:
			attrs = append(attrs, ntfsNonResidentAttr(ntfsAttrData, "", b.logFileLCN, b.logFileSize()))
		case 3:
			attrs = append(attrs, ntfsResidentAttr(ntfsAttrVolumeName, "", utf16Bytes(b.volumeName)))
			attrs = append(attrs, ntfsResidentAttr(ntfsAttrVolumeInformation, "", []byte{0, 0, 0, 0, 0, 0, 0, 0, b.versionMajor, b.versionMinor, 0, 0}))
			attrs = append(attrs, ntfsResidentAttr(ntfsAttrData, "", nil))
		case 4:
			attrs = append(attrs, ntfsNonResidentAttr(ntfsAttrData, "", b.attrDefLCN, int64(len(b.attrDef))))
		case 6:
			attrs = append(attrs, ntfsNonResidentAttr(ntfsAttrData, "", b.bitmapLCN, b.bitmapSize))
		case 7:
			attrs = append(attrs, ntfsNonResidentAttr(ntfsAttrData, "", 0, b.bootFileSize()))
		case 8:
			attrs = append(attrs, ntfsResidentAttr(ntfsAttrData, "", nil))
			attrs = append(attrs, ntfsBadClustersAttr(b.size))
		case 10:
			attrs = append(attrs, ntfsNonResidentAttr(ntfsAttrData, "", b.upCaseLCN, int64(len(b.upCase))))
		default:
			if node.dir {
				if node.indexRootRecordID == 0 {
					attrs = append(attrs, ntfsResidentAttr(ntfsAttrIndexRoot, "$I30", node.index.rootValue))
				}
				if len(node.index.blocks) > 0 {
					attrs = append(attrs, ntfsNonResidentAttr(ntfsAttrIndexAllocation, "$I30", node.indexLCN, int64(len(node.index.blocks))))
					attrs = append(attrs, ntfsResidentAttr(ntfsAttrBitmap, "$I30", node.index.bitmap))
				}
			} else if node.size > 0 {
				attrs = append(attrs, ntfsNonResidentAttr(ntfsAttrData, "", node.lcn, node.size))
			} else {
				attrs = append(attrs, ntfsResidentAttr(ntfsAttrData, "", nil))
			}
		}
	}

	offset := attrOff
	nextAttributeID := uint16(0)
	nextExtendedID := node.dataAttributeID
	if node.indexRootRecordID != 0 {
		nextExtendedID++
	}
	for index, attr := range attrs {
		if offset+len(attr)+4 > len(record) {
			return nil, fmt.Errorf(
				"ntfs: MFT record for %q overflowed adding attribute %#x at %d (%d bytes)",
				node.fullPath,
				binary.LittleEndian.Uint32(attr[0:4]),
				offset,
				len(attr),
			)
		}
		id := ntfsAttributeID(node, binary.LittleEndian.Uint32(attr[0:4]), uint16(index))
		if explicitIDs != nil && index < len(explicitIDs) {
			id = explicitIDs[index]
		} else if explicitIDs != nil {
			id = nextExtendedID
			nextExtendedID++
		}
		binary.LittleEndian.PutUint16(attr[14:16], id)
		if id >= nextAttributeID {
			nextAttributeID = id + 1
		}
		copy(record[offset:], attr)
		offset += len(attr)
	}
	binary.LittleEndian.PutUint32(record[offset:offset+4], ntfsAttrEnd)
	offset = align8(offset + 4)
	binary.LittleEndian.PutUint32(record[24:28], uint32(offset))
	binary.LittleEndian.PutUint32(record[28:32], uint32(len(record)))
	binary.LittleEndian.PutUint16(record[40:42], nextAttributeID)
	applyNTFSFixup(record, usaOff, usaCount)
	return record, nil
}

func ntfsAttributeID(node *ntfsNode, typ uint32, fallback uint16) uint16 {
	if node.id == 5 {
		switch typ {
		case ntfsAttrStandardInformation:
			return 0
		case ntfsAttrFileName:
			return 1
		case ntfsAttrSecurityDescriptor:
			return 2
		case ntfsAttrIndexRoot:
			return 6
		case ntfsAttrBitmap:
			return 7
		case ntfsAttrIndexAllocation:
			return 8
		}
	}
	if node.systemKind == "reserved" {
		switch typ {
		case ntfsAttrStandardInformation:
			return 0
		case ntfsAttrData:
			return 1
		case ntfsAttrSecurityDescriptor:
			return 2
		}
	}
	return fallback
}

func (b *ntfsBuild) legacySecurityRecord(node *ntfsNode) bool {
	return ntfsUsesLegacySecurityRecord(b.modern(), node)
}

func ntfsUsesLegacySecurityRecord(modern bool, node *ntfsNode) bool {
	if !modern {
		return true
	}
	switch node.id {
	case 3, 4, 5, 7, 12, 13, 14, 15:
		return true
	default:
		return false
	}
}

func validateNTFSVolumeName(name string) error {
	if strings.ContainsRune(name, '\x00') {
		return fmt.Errorf("ntfs: label must not contain NUL")
	}
	if len(utf16.Encode([]rune(name))) > 32 {
		return fmt.Errorf("ntfs: label must be at most 32 UTF-16 code units")
	}
	return nil
}

func ntfsResidentAttr(typ uint32, name string, value []byte) []byte {
	nameBytes := utf16Bytes(name)
	const nameOff = 24
	valueOff := align8(24 + len(nameBytes))
	total := align8(valueOff + len(value))
	attr := make([]byte, total)
	binary.LittleEndian.PutUint32(attr[0:4], typ)
	binary.LittleEndian.PutUint32(attr[4:8], uint32(total))
	binary.LittleEndian.PutUint16(attr[10:12], nameOff)
	if len(nameBytes) > 0 {
		attr[9] = byte(len([]rune(name)))
		copy(attr[nameOff:], nameBytes)
	}
	binary.LittleEndian.PutUint32(attr[16:20], uint32(len(value)))
	binary.LittleEndian.PutUint16(attr[20:22], uint16(valueOff))
	if typ == ntfsAttrFileName {
		attr[22] = 1
	}
	copy(attr[valueOff:], value)
	return attr
}

func ntfsResidentFileNameAttr(node *ntfsNode, name ntfsName) []byte {
	return ntfsResidentAttr(ntfsAttrFileName, "", ntfsFileNameAttribute(node, name))
}

func ntfsNonResidentAttr(typ uint32, name string, lcn, size int64) []byte {
	nameBytes := utf16Bytes(name)
	nameOff := 0
	if len(nameBytes) > 0 {
		nameOff = 64
	}
	runOff := align8(64 + len(nameBytes))
	run := ntfsRunList(fsinternal.CeilDiv(size, ntfsCluster), lcn)
	total := align8(runOff + len(run))
	attr := make([]byte, total)
	binary.LittleEndian.PutUint32(attr[0:4], typ)
	binary.LittleEndian.PutUint32(attr[4:8], uint32(total))
	attr[8] = 1
	if len(nameBytes) > 0 {
		attr[9] = byte(len([]rune(name)))
		binary.LittleEndian.PutUint16(attr[10:12], uint16(nameOff))
		copy(attr[nameOff:], nameBytes)
	}
	lastVCN := fsinternal.CeilDiv(size, ntfsCluster) - 1
	if lastVCN < 0 {
		lastVCN = 0
	}
	binary.LittleEndian.PutUint64(attr[24:32], uint64(lastVCN))
	binary.LittleEndian.PutUint16(attr[32:34], uint16(runOff))
	alloc := fsinternal.CeilDiv(size, ntfsCluster) * ntfsCluster
	binary.LittleEndian.PutUint64(attr[40:48], uint64(alloc))
	binary.LittleEndian.PutUint64(attr[48:56], uint64(size))
	binary.LittleEndian.PutUint64(attr[56:64], uint64(size))
	copy(attr[runOff:], run)
	return attr
}

func ntfsBadClustersAttr(size int64) []byte {
	const name = "$Bad"
	nameBytes := utf16Bytes(name)
	const nameOff = 64
	runOff := align8(nameOff + len(nameBytes))
	dataSize := size - ntfsSectorSize
	clusters := dataSize / ntfsCluster
	runLength := ntfsUnsignedIntBytes(clusters)
	run := append([]byte{byte(len(runLength))}, runLength...)
	run = append(run, 0)
	total := align8(runOff + len(run))
	attr := make([]byte, total)
	binary.LittleEndian.PutUint32(attr[0:4], ntfsAttrData)
	binary.LittleEndian.PutUint32(attr[4:8], uint32(total))
	attr[8] = 1
	attr[9] = byte(len([]rune(name)))
	binary.LittleEndian.PutUint16(attr[10:12], nameOff)
	if clusters > 0 {
		binary.LittleEndian.PutUint64(attr[24:32], uint64(clusters-1))
	}
	binary.LittleEndian.PutUint16(attr[32:34], uint16(runOff))
	binary.LittleEndian.PutUint64(attr[40:48], uint64(dataSize))
	binary.LittleEndian.PutUint64(attr[48:56], uint64(dataSize))
	copy(attr[nameOff:], nameBytes)
	copy(attr[runOff:], run)
	return attr
}

func ntfsRunList(length, lcn int64) []byte {
	if length <= 0 {
		return []byte{0}
	}
	lenBytes := ntfsUnsignedIntBytes(length)
	lcnBytes := ntfsSignedIntBytes(lcn)
	run := []byte{byte(len(lenBytes)) | byte(len(lcnBytes))<<4}
	run = append(run, lenBytes...)
	run = append(run, lcnBytes...)
	run = append(run, 0)
	return run
}

func ntfsUnsignedIntBytes(value int64) []byte {
	var out []byte
	for value > 0 {
		out = append(out, byte(value))
		value >>= 8
	}
	if len(out) == 0 {
		out = []byte{0}
	}
	if out[len(out)-1]&0x80 != 0 {
		out = append(out, 0)
	}
	return out
}

func ntfsSignedIntBytes(value int64) []byte {
	var out []byte
	for {
		current := byte(value)
		out = append(out, current)
		value >>= 8
		if value == 0 && current&0x80 == 0 || value == -1 && current&0x80 != 0 {
			return out
		}
	}
}

func ntfsStandardInformation(node *ntfsNode, modern bool) []byte {
	size := 48
	if modern {
		size = 72
	}
	data := make([]byte, size)
	creation, write, change, access := ntfsNodeTimes(node)
	binary.LittleEndian.PutUint64(data[0:8], creation)
	binary.LittleEndian.PutUint64(data[8:16], write)
	binary.LittleEndian.PutUint64(data[16:24], change)
	binary.LittleEndian.PutUint64(data[24:32], access)
	flags := ntfsFileFlags(node)
	if node.id == 5 {
		flags &^= ntfsFileAttrDir
	}
	binary.LittleEndian.PutUint32(data[32:36], flags)
	if modern {
		securityID := node.securityID
		if securityID == 0 {
			securityID = ntfsSecurityID
		}
		binary.LittleEndian.PutUint32(data[52:56], securityID)
	}
	return data
}

func ntfsFileNameAttribute(node *ntfsNode, name ntfsName) []byte {
	nameBytes := utf16Bytes(name.value)
	data := make([]byte, 66+len(nameBytes))
	parent := uint64(5)
	if name.parent != nil {
		parent = name.parent.id
	} else if node.parent != nil {
		parent = node.parent.id
	}
	binary.LittleEndian.PutUint64(data[0:8], ntfsFileReference(parent))
	creation, write, change, access := ntfsNodeTimes(node)
	binary.LittleEndian.PutUint64(data[8:16], creation)
	binary.LittleEndian.PutUint64(data[16:24], write)
	binary.LittleEndian.PutUint64(data[24:32], change)
	binary.LittleEndian.PutUint64(data[32:40], access)
	alloc := fsinternal.CeilDiv(node.size, ntfsCluster) * ntfsCluster
	if node.dir {
		alloc = 0
	}
	binary.LittleEndian.PutUint64(data[40:48], uint64(alloc))
	binary.LittleEndian.PutUint64(data[48:56], uint64(node.size))
	binary.LittleEndian.PutUint32(data[56:60], ntfsFileFlags(node))
	data[64] = byte(len([]rune(name.value)))
	data[65] = name.namespace
	copy(data[66:], nameBytes)
	return data
}

func ntfsFileFlags(node *ntfsNode) uint32 {
	var flags uint32
	if node.metadata.HasFileAttributes {
		flags = node.metadata.FileAttributes &^ 0x10
	}
	if node.dir {
		flags |= ntfsFileAttrDir
	} else if !node.metadata.HasFileAttributes && node.id >= 16 && node.attrs.Archive {
		flags |= ntfsFileAttrArch
	}
	if node.id < 16 {
		flags |= ntfsFileAttrHide | ntfsFileAttrSys
	}
	if node.attrs.ReadOnly {
		flags |= ntfsFileAttrRO
	}
	if node.attrs.Hidden {
		flags |= ntfsFileAttrHide
	}
	if node.attrs.System {
		flags |= ntfsFileAttrSys
	}
	if !node.metadata.HasFileAttributes && node.id >= 16 && !node.dir && !node.attrs.Archive {
		flags |= ntfsFileAttrArch
	}
	if node.systemKind != "" && node.systemKind != "reserved" {
		flags |= ntfsFileAttrIndex
	}
	return flags
}

func ntfsNodeTimes(node *ntfsNode) (creation, write, change, access uint64) {
	fallback := uint64(windowsFiletime(time.Date(2026, 7, 4, 0, 0, 0, 0, time.UTC)))
	creation = node.metadata.CreationTime
	write = node.metadata.LastWriteTime
	access = node.metadata.LastAccessTime
	if creation == 0 {
		creation = fallback
	}
	if write == 0 {
		write = fallback
	}
	if access == 0 {
		access = fallback
	}
	return creation, write, write, access
}

func (b *ntfsBuild) mftBitmap() []byte {
	data := make([]byte, fsinternal.Align(fsinternal.CeilDiv(b.mftRecords, 8), 8))
	for _, node := range b.nodes {
		data[node.id/8] |= 1 << uint(node.id%8)
	}
	return data
}

func ntfsMFTRecordCapacity(used uint64) int64 {
	const (
		minimumRecords = int64(32)
		spareRecords   = int64(256)
	)
	if used <= uint64(minimumRecords) {
		return minimumRecords
	}
	return fsinternal.Align(int64(used)+spareRecords, 8)
}

type ntfsUpCaseIdentityRange struct {
	first int
	last  int
	step  int
}

// NTFS 3.1 uses a fixed historical Unicode table. Code points assigned
// lowercase mappings in later Unicode versions remain identity mappings.
var ntfs31UpCaseIdentity = []ntfsUpCaseIdentityRange{
	{0xb5, 0xb5, 1}, {0x131, 0x131, 1}, {0x17f, 0x17f, 1}, {0x180, 0x180, 1},
	{0x195, 0x195, 1}, {0x19a, 0x19a, 1}, {0x19e, 0x19e, 1}, {0x1bf, 0x1bf, 1},
	{0x1c5, 0x1cb, 3}, {0x1f2, 0x1f2, 1}, {0x1f9, 0x1f9, 1}, {0x219, 0x21f, 2},
	{0x223, 0x233, 2}, {0x23c, 0x23c, 1}, {0x23f, 0x23f, 1}, {0x240, 0x240, 1},
	{0x242, 0x242, 1}, {0x247, 0x24f, 2}, {0x250, 0x252, 1}, {0x25c, 0x25c, 1},
	{0x261, 0x261, 1}, {0x265, 0x265, 1}, {0x266, 0x266, 1}, {0x26a, 0x26c, 1},
	{0x271, 0x271, 1}, {0x27d, 0x27d, 1}, {0x280, 0x280, 1}, {0x282, 0x282, 1},
	{0x287, 0x287, 1}, {0x289, 0x289, 1}, {0x28c, 0x28c, 1}, {0x29d, 0x29d, 1},
	{0x29e, 0x29e, 1}, {0x345, 0x345, 1}, {0x371, 0x371, 1}, {0x373, 0x37b, 4},
	{0x37c, 0x37c, 1}, {0x37d, 0x37d, 1}, {0x3d0, 0x3d0, 1}, {0x3d1, 0x3d1, 1},
	{0x3d5, 0x3d7, 1}, {0x3d9, 0x3e1, 2}, {0x3f0, 0x3f3, 1}, {0x3f5, 0x3fb, 3},
	{0x450, 0x450, 1}, {0x45d, 0x45d, 1}, {0x48b, 0x48f, 2}, {0x4c6, 0x4ce, 4},
	{0x4cf, 0x4cf, 1}, {0x4ed, 0x4ed, 1}, {0x4f7, 0x4f7, 1}, {0x4fb, 0x52f, 2},
	{0x10d0, 0x10fa, 1}, {0x10fd, 0x10ff, 1}, {0x13f8, 0x13fd, 1}, {0x1c80, 0x1c88, 1},
	{0x1d79, 0x1d79, 1}, {0x1d7d, 0x1d7d, 1}, {0x1d8e, 0x1d8e, 1}, {0x1e9b, 0x1e9b, 1},
	{0x1efb, 0x1eff, 2}, {0x1f80, 0x1f87, 1}, {0x1f90, 0x1f97, 1}, {0x1fa0, 0x1fa7, 1},
	{0x1fb3, 0x1fb3, 1}, {0x1fbe, 0x1fbe, 1}, {0x1fc3, 0x1fc3, 1}, {0x1ff3, 0x1ff3, 1},
	{0x214e, 0x214e, 1}, {0x2184, 0x2184, 1}, {0x2c30, 0x2c5f, 1}, {0x2c61, 0x2c61, 1},
	{0x2c65, 0x2c65, 1}, {0x2c66, 0x2c6c, 2}, {0x2c73, 0x2c73, 1}, {0x2c76, 0x2c76, 1},
	{0x2c81, 0x2ce3, 2}, {0x2cec, 0x2cec, 1}, {0x2cee, 0x2cee, 1}, {0x2cf3, 0x2cf3, 1},
	{0x2d00, 0x2d25, 1}, {0x2d27, 0x2d27, 1}, {0x2d2d, 0x2d2d, 1}, {0xa641, 0xa66d, 2},
	{0xa681, 0xa69b, 2}, {0xa723, 0xa72f, 2}, {0xa733, 0xa76f, 2}, {0xa77a, 0xa77a, 1},
	{0xa77c, 0xa77c, 1}, {0xa77f, 0xa787, 2}, {0xa78c, 0xa78c, 1}, {0xa791, 0xa791, 1},
	{0xa793, 0xa793, 1}, {0xa794, 0xa794, 1}, {0xa797, 0xa7a9, 2}, {0xa7b5, 0xa7c3, 2},
	{0xa7c8, 0xa7c8, 1}, {0xa7ca, 0xa7ca, 1}, {0xa7d1, 0xa7d1, 1}, {0xa7d7, 0xa7d7, 1},
	{0xa7d9, 0xa7d9, 1}, {0xa7f6, 0xa7f6, 1}, {0xab53, 0xab53, 1}, {0xab70, 0xabbf, 1},
}

func ntfsUpCaseData(modern bool) []byte {
	data := make([]byte, 65536*2)
	for value := 0; value < 65536; value++ {
		upper := unicode.ToUpper(rune(value))
		if upper < 0 || upper > 0xffff {
			upper = rune(value)
		}
		binary.LittleEndian.PutUint16(data[value*2:value*2+2], uint16(upper))
	}
	if modern {
		for _, identity := range ntfs31UpCaseIdentity {
			for value := identity.first; value <= identity.last; value += identity.step {
				binary.LittleEndian.PutUint16(data[value*2:value*2+2], uint16(value))
			}
		}
	}
	return data
}

func ntfsDefaultSecurityDescriptor() []byte {
	system := ntfsSID(5, 18)
	administrators := ntfsSID(5, 32, 544)
	users := ntfsSID(5, 32, 545)
	creatorOwner := ntfsSID(3, 0)
	everyone := ntfsSID(1, 0)
	return ntfsSecurityDescriptorWithACEs(administrators, administrators, []ntfsAccessAllowedACE{
		{flags: 0x03, mask: 0x001f01ff, sid: administrators},
		{flags: 0x03, mask: 0x001f01ff, sid: system},
		{flags: 0x0b, mask: 0x10000000, sid: creatorOwner},
		{flags: 0x03, mask: 0x001200a9, sid: users},
		{flags: 0x02, mask: 0x00000004, sid: users},
		{flags: 0x0a, mask: 0x00000002, sid: users},
		{mask: 0x001200a9, sid: everyone},
	}, 0)
}

func ntfsLegacySecurityDescriptor() []byte {
	system := ntfsSID(5, 18)
	administrators := ntfsSID(5, 32, 544)
	return ntfsSecurityDescriptorWithACEs(administrators, administrators, []ntfsAccessAllowedACE{
		{flags: 0x03, mask: 0x001f01ff, sid: administrators},
		{flags: 0x03, mask: 0x001f01ff, sid: system},
	}, 0)
}

func ntfsMetadataSecurityDescriptor(accessMask uint32) []byte {
	system := ntfsSID(5, 18)
	administrators := ntfsSID(5, 32, 544)
	return ntfsSecurityDescriptor(administrators, administrators, accessMask, system, administrators)
}

func ntfsRootSecurityDescriptor() []byte {
	administrators := ntfsSID(5, 32, 544)
	descriptor := ntfsDefaultSecurityDescriptor()
	aclOffset := int(binary.LittleEndian.Uint32(descriptor[16:20]))
	aclSize := int(binary.LittleEndian.Uint16(descriptor[aclOffset+2 : aclOffset+4]))
	aces := append([]byte(nil), descriptor[aclOffset+8:aclOffset+aclSize]...)
	root := ntfsSecurityDescriptorFromACL(administrators, administrators, aces, 7, 4096)
	return append(root, make([]byte, 4160-len(root))...)
}

func ntfsSecurityDescriptor(owner, group []byte, accessMask uint32, trustees ...[]byte) []byte {
	aces := make([]ntfsAccessAllowedACE, 0, len(trustees))
	for _, trustee := range trustees {
		aces = append(aces, ntfsAccessAllowedACE{mask: accessMask, sid: trustee})
	}
	return ntfsSecurityDescriptorWithACEs(owner, group, aces, 0)
}

type ntfsAccessAllowedACE struct {
	flags byte
	mask  uint32
	sid   []byte
}

func ntfsSecurityDescriptorWithACEs(owner, group []byte, aces []ntfsAccessAllowedACE, paddedACLSize int) []byte {
	aceBytes := make([]byte, 0)
	for _, ace := range aces {
		size := 8 + len(ace.sid)
		entry := make([]byte, size)
		entry[1] = ace.flags
		binary.LittleEndian.PutUint16(entry[2:4], uint16(size))
		binary.LittleEndian.PutUint32(entry[4:8], ace.mask)
		copy(entry[8:], ace.sid)
		aceBytes = append(aceBytes, entry...)
	}
	return ntfsSecurityDescriptorFromACL(owner, group, aceBytes, len(aces), paddedACLSize)
}

func ntfsSecurityDescriptorFromACL(owner, group, aces []byte, aceCount, paddedACLSize int) []byte {
	aclSize := 8 + len(aces)
	if paddedACLSize > aclSize {
		aclSize = paddedACLSize
	}
	ownerOffset := 20 + aclSize
	groupOffset := ownerOffset + len(owner)
	descriptor := make([]byte, groupOffset+len(group))
	descriptor[0] = 1
	binary.LittleEndian.PutUint16(descriptor[2:4], 0x8004)
	binary.LittleEndian.PutUint32(descriptor[4:8], uint32(ownerOffset))
	binary.LittleEndian.PutUint32(descriptor[8:12], uint32(groupOffset))
	binary.LittleEndian.PutUint32(descriptor[16:20], 20)
	acl := descriptor[20:]
	acl[0] = 2
	binary.LittleEndian.PutUint16(acl[2:4], uint16(aclSize))
	binary.LittleEndian.PutUint16(acl[4:6], uint16(aceCount))
	copy(acl[8:], aces)
	copy(descriptor[ownerOffset:], owner)
	copy(descriptor[groupOffset:], group)
	return descriptor
}

func ntfsSecurityDescriptorHash(descriptor []byte) uint32 {
	var hash uint32
	for offset := 0; offset < len(descriptor); offset += 4 {
		var word [4]byte
		copy(word[:], descriptor[offset:min(offset+4, len(descriptor))])
		hash = hash<<3 | hash>>29
		hash += binary.LittleEndian.Uint32(word[:])
	}
	return hash
}

func (b *ntfsBuild) prepareSecurity() error {
	records := make([]*ntfsSecurityRecord, 0)
	byDescriptor := make(map[string]*ntfsSecurityRecord)
	add := func(descriptor []byte) (*ntfsSecurityRecord, error) {
		if len(descriptor) < 20 || descriptor[0] != 1 || binary.LittleEndian.Uint16(descriptor[2:4])&0x8000 == 0 {
			return nil, fmt.Errorf("ntfs: invalid self-relative security descriptor")
		}
		key := string(descriptor)
		if record := byDescriptor[key]; record != nil {
			return record, nil
		}
		record := &ntfsSecurityRecord{
			descriptor: append([]byte(nil), descriptor...),
			hash:       ntfsSecurityDescriptorHash(descriptor),
			id:         ntfsSecurityID + uint32(len(records)),
		}
		records = append(records, record)
		byDescriptor[key] = record
		return record, nil
	}
	defaultRecord, err := add(ntfsDefaultSecurityDescriptor())
	if err != nil {
		return err
	}
	for _, node := range b.nodes {
		record := defaultRecord
		if len(node.metadata.SecurityDescriptor) > 0 {
			record, err = add(node.metadata.SecurityDescriptor)
			if err != nil {
				return fmt.Errorf("ntfs: security descriptor for %q: %w", node.fullPath, err)
			}
		}
		node.securityID = record.id
	}

	data := make([]byte, 0)
	pairBase := 0
	withinSegment := 0
	for _, record := range records {
		entryLength := 20 + len(record.descriptor)
		entry := make([]byte, fsinternal.Align(int64(entryLength), 16))
		if len(entry) > ntfsSecureMirrorBase {
			return fmt.Errorf("ntfs: security descriptor entry requires %d bytes; maximum is %d", len(entry), ntfsSecureMirrorBase)
		}
		if withinSegment+len(entry) > ntfsSecureMirrorBase {
			pairBase += 2 * ntfsSecureMirrorBase
			withinSegment = 0
		}
		record.offset = uint64(pairBase + withinSegment)
		binary.LittleEndian.PutUint32(entry[0:4], record.hash)
		binary.LittleEndian.PutUint32(entry[4:8], record.id)
		binary.LittleEndian.PutUint64(entry[8:16], record.offset)
		binary.LittleEndian.PutUint32(entry[16:20], uint32(entryLength))
		copy(entry[20:], record.descriptor)
		end := pairBase + ntfsSecureMirrorBase + withinSegment + len(entry)
		if len(data) < end {
			data = append(data, make([]byte, end-len(data))...)
		}
		copy(data[pairBase+withinSegment:], entry)
		copy(data[pairBase+ntfsSecureMirrorBase+withinSegment:], entry)
		withinSegment += len(entry)
	}
	b.secureData = data
	b.secureIDIndex = buildNTFSSecurityIndex(records, false)
	b.secureHashIndex = buildNTFSSecurityIndex(records, true)
	return nil
}

type ntfsSecurityTreeNode struct {
	records  []*ntfsSecurityRecord
	children []*ntfsSecurityTreeNode
	vcn      uint64
}

func ntfsSecurityEntry(record *ntfsSecurityRecord, hashIndex, hasSubnode bool, vcn uint64) []byte {
	keyLength := 20
	total := 40
	keyOffset := 20
	if hashIndex {
		keyLength = 24
		total = 48
		keyOffset = 24
	}
	if hasSubnode {
		total += 8
	}
	entry := make([]byte, total)
	binary.LittleEndian.PutUint16(entry[0:2], uint16(keyLength))
	binary.LittleEndian.PutUint16(entry[2:4], 20)
	binary.LittleEndian.PutUint16(entry[8:10], uint16(total))
	binary.LittleEndian.PutUint16(entry[10:12], uint16(keyLength-16))
	if hasSubnode {
		binary.LittleEndian.PutUint16(entry[12:14], ntfsIndexHasSub)
		binary.LittleEndian.PutUint64(entry[total-8:], vcn)
	}
	if hashIndex {
		binary.LittleEndian.PutUint32(entry[16:20], record.hash)
		binary.LittleEndian.PutUint32(entry[20:24], record.id)
	} else {
		binary.LittleEndian.PutUint32(entry[16:20], record.id)
	}
	entryLength := uint32(20 + len(record.descriptor))
	ntfsSecurityIndexData(entry[keyOffset:], record.hash, record.id, record.offset, entryLength)
	return entry
}

func ntfsSecurityEndEntry(hasSubnode bool, vcn uint64) []byte {
	size := 16
	flags := uint16(ntfsIndexLast)
	if hasSubnode {
		size += 8
		flags |= ntfsIndexHasSub
	}
	entry := make([]byte, size)
	binary.LittleEndian.PutUint16(entry[8:10], uint16(size))
	binary.LittleEndian.PutUint16(entry[12:14], flags)
	if hasSubnode {
		binary.LittleEndian.PutUint64(entry[size-8:], vcn)
	}
	return entry
}

func ntfsSecurityTreeEntries(node *ntfsSecurityTreeNode, hashIndex bool) [][]byte {
	hasChildren := len(node.children) > 0
	entries := make([][]byte, 0, len(node.records)+1)
	for index, record := range node.records {
		vcn := uint64(0)
		if hasChildren {
			vcn = node.children[index].vcn
		}
		entries = append(entries, ntfsSecurityEntry(record, hashIndex, hasChildren, vcn))
	}
	endVCN := uint64(0)
	if hasChildren {
		endVCN = node.children[len(node.children)-1].vcn
	}
	return append(entries, ntfsSecurityEndEntry(hasChildren, endVCN))
}

func ntfsSecurityEntriesSize(records []*ntfsSecurityRecord, hashIndex, subnodes bool) int {
	size := len(ntfsSecurityEndEntry(subnodes, 0))
	for _, record := range records {
		size += len(ntfsSecurityEntry(record, hashIndex, subnodes, 0))
	}
	return size
}

func ntfsSecurityLeafLevel(records []*ntfsSecurityRecord, hashIndex bool) ([]*ntfsSecurityTreeNode, []*ntfsSecurityRecord) {
	const capacity = int(ntfsIndexSize) - 0x58
	var level []*ntfsSecurityTreeNode
	var separators []*ntfsSecurityRecord
	for index := 0; index < len(records); {
		current := &ntfsSecurityTreeNode{}
		used := len(ntfsSecurityEndEntry(false, 0))
		for index < len(records) {
			entrySize := len(ntfsSecurityEntry(records[index], hashIndex, false, 0))
			if used+entrySize <= capacity {
				current.records = append(current.records, records[index])
				used += entrySize
				index++
				continue
			}
			separators = append(separators, records[index])
			index++
			break
		}
		level = append(level, current)
	}
	return level, separators
}

func ntfsSecurityParentLevel(children []*ntfsSecurityTreeNode, separators []*ntfsSecurityRecord, hashIndex bool) ([]*ntfsSecurityTreeNode, []*ntfsSecurityRecord) {
	const capacity = int(ntfsIndexSize) - 0x58
	var level []*ntfsSecurityTreeNode
	var promoted []*ntfsSecurityRecord
	childIndex, separatorIndex := 0, 0
	for childIndex < len(children) {
		current := &ntfsSecurityTreeNode{children: []*ntfsSecurityTreeNode{children[childIndex]}}
		childIndex++
		used := len(ntfsSecurityEndEntry(true, 0))
		for separatorIndex < len(separators) && childIndex < len(children) {
			entrySize := len(ntfsSecurityEntry(separators[separatorIndex], hashIndex, true, 0))
			if used+entrySize <= capacity {
				current.records = append(current.records, separators[separatorIndex])
				current.children = append(current.children, children[childIndex])
				used += entrySize
				separatorIndex++
				childIndex++
				continue
			}
			promoted = append(promoted, separators[separatorIndex])
			separatorIndex++
			break
		}
		level = append(level, current)
	}
	return level, promoted
}

func ntfsSecurityIndexRoot(collation uint32, entries [][]byte, allocated bool) []byte {
	entryBytes := joinBytes(entries)
	value := make([]byte, 32+len(entryBytes))
	binary.LittleEndian.PutUint32(value[4:8], collation)
	binary.LittleEndian.PutUint32(value[8:12], uint32(ntfsIndexSize))
	value[12] = byte(ntfsIndexSize / ntfsCluster)
	binary.LittleEndian.PutUint32(value[16:20], 16)
	binary.LittleEndian.PutUint32(value[20:24], uint32(16+len(entryBytes)))
	binary.LittleEndian.PutUint32(value[24:28], uint32(16+len(entryBytes)))
	if allocated {
		value[28] = ntfsIndexNode
	}
	copy(value[32:], entryBytes)
	return value
}

func buildNTFSSecurityIndex(input []*ntfsSecurityRecord, hashIndex bool) ntfsSecurityIndex {
	records := append([]*ntfsSecurityRecord(nil), input...)
	sort.SliceStable(records, func(i, j int) bool {
		if hashIndex && records[i].hash != records[j].hash {
			return records[i].hash < records[j].hash
		}
		return records[i].id < records[j].id
	})
	collation := uint32(0x10)
	if hashIndex {
		collation = 0x12
	}
	const rootEntryLimit = 160
	if ntfsSecurityEntriesSize(records, hashIndex, false) <= rootEntryLimit {
		root := &ntfsSecurityTreeNode{records: records}
		return ntfsSecurityIndex{rootValue: ntfsSecurityIndexRoot(collation, ntfsSecurityTreeEntries(root, hashIndex), false)}
	}
	level, separators := ntfsSecurityLeafLevel(records, hashIndex)
	for ntfsSecurityEntriesSize(separators, hashIndex, true) > rootEntryLimit {
		level, separators = ntfsSecurityParentLevel(level, separators, hashIndex)
	}
	root := &ntfsSecurityTreeNode{records: separators, children: level}
	var allocation []*ntfsSecurityTreeNode
	var assign func(*ntfsSecurityTreeNode)
	assign = func(current *ntfsSecurityTreeNode) {
		for _, child := range current.children {
			assign(child)
		}
		if current != root {
			current.vcn = ntfsIndexVCN(len(allocation))
			allocation = append(allocation, current)
		}
	}
	assign(root)
	blocks := make([]byte, 0, len(allocation)*int(ntfsIndexSize))
	for _, current := range allocation {
		blocks = append(blocks, ntfsIndexBlock(current.vcn, ntfsSecurityTreeEntries(current, hashIndex), len(current.children) > 0)...)
	}
	bitmap := make([]byte, align8(int(fsinternal.CeilDiv(int64(len(allocation)), 8))))
	for index := range allocation {
		bitmap[index/8] |= 1 << uint(index%8)
	}
	return ntfsSecurityIndex{
		rootValue: ntfsSecurityIndexRoot(collation, ntfsSecurityTreeEntries(root, hashIndex), true),
		blocks:    blocks,
		bitmap:    bitmap,
	}
}

func ntfsSID(authority byte, subauth ...uint32) []byte {
	sid := make([]byte, 8+len(subauth)*4)
	sid[0] = 1
	sid[1] = byte(len(subauth))
	sid[7] = authority
	for index, value := range subauth {
		binary.LittleEndian.PutUint32(sid[8+index*4:12+index*4], value)
	}
	return sid
}

func ntfsAttrDefData(modern bool) []byte {
	type attrDef struct {
		name      string
		typ       uint32
		collation uint32
		flags     uint32
		minSize   uint64
		maxSize   uint64
	}
	standardMaximum := uint64(48)
	objectName := "$VOLUME_VERSION"
	objectMinimum := uint64(8)
	objectMaximum := uint64(8)
	reparseName := "$SYMBOLIC_LINK"
	reparseMaximum := ^uint64(0)
	if modern {
		standardMaximum = 72
		objectName = "$OBJECT_ID"
		objectMinimum = 0
		objectMaximum = 256
		reparseName = "$REPARSE_POINT"
		reparseMaximum = 0x4000
	}
	defs := []attrDef{
		{name: "$STANDARD_INFORMATION", typ: ntfsAttrStandardInformation, flags: 0x40, minSize: 48, maxSize: standardMaximum},
		{name: "$ATTRIBUTE_LIST", typ: ntfsAttrAttributeList, flags: 0x80, maxSize: ^uint64(0)},
		{name: "$FILE_NAME", typ: ntfsAttrFileName, flags: 0x42, minSize: 68, maxSize: 578},
		{name: objectName, typ: ntfsAttrObjectID, flags: 0x40, minSize: objectMinimum, maxSize: objectMaximum},
		{name: "$SECURITY_DESCRIPTOR", typ: ntfsAttrSecurityDescriptor, flags: 0x80, maxSize: ^uint64(0)},
		{name: "$VOLUME_NAME", typ: ntfsAttrVolumeName, flags: 0x40, minSize: 2, maxSize: 256},
		{name: "$VOLUME_INFORMATION", typ: ntfsAttrVolumeInformation, flags: 0x40, minSize: 12, maxSize: 12},
		{name: "$DATA", typ: ntfsAttrData, maxSize: ^uint64(0)},
		{name: "$INDEX_ROOT", typ: ntfsAttrIndexRoot, flags: 0x40, maxSize: ^uint64(0)},
		{name: "$INDEX_ALLOCATION", typ: ntfsAttrIndexAllocation, flags: 0x80, maxSize: ^uint64(0)},
		{name: "$BITMAP", typ: ntfsAttrBitmap, flags: 0x80, maxSize: ^uint64(0)},
		{name: reparseName, typ: ntfsAttrReparsePoint, flags: 0x80, maxSize: reparseMaximum},
		{name: "$EA_INFORMATION", typ: 0xd0, flags: 0x40, minSize: 8, maxSize: 8},
		{name: "$EA", typ: 0xe0, maxSize: 0x10000},
	}
	if modern {
		defs = append(defs, attrDef{name: "$LOGGED_UTILITY_STREAM", typ: ntfsAttrLoggedUtilityStream, flags: 0x80, maxSize: 0x10000})
	}
	rows := 225
	if modern {
		rows = 16
	}
	data := make([]byte, rows*160)
	for i, def := range defs {
		entry := data[i*160 : (i+1)*160]
		copy(entry[0:128], utf16Bytes(def.name))
		binary.LittleEndian.PutUint32(entry[128:132], def.typ)
		binary.LittleEndian.PutUint32(entry[132:136], 0)
		binary.LittleEndian.PutUint32(entry[136:140], def.collation)
		binary.LittleEndian.PutUint32(entry[140:144], def.flags)
		binary.LittleEndian.PutUint64(entry[144:152], def.minSize)
		binary.LittleEndian.PutUint64(entry[152:160], def.maxSize)
	}
	return data
}

func ntfsFileReference(id uint64) uint64 {
	return id | uint64(ntfsSequenceNumber(id))<<48
}

func ntfsSequenceNumber(id uint64) uint16 {
	if id >= 2 && id < 16 {
		return uint16(id)
	}
	return 1
}

func (b *ntfsBuild) bootSector() []byte {
	sector := make([]byte, ntfsSectorSize)
	if len(b.bootCode) > 0 {
		copy(sector, b.bootCode)
	} else {
		copy(sector[0:3], []byte{0xeb, 0x52, 0x90})
		copy(sector[3:11], "NTFS    ")
	}
	binary.LittleEndian.PutUint16(sector[11:13], uint16(ntfsSectorSize))
	sector[13] = byte(ntfsCluster / ntfsSectorSize)
	binary.LittleEndian.PutUint16(sector[14:16], 0)
	clear(sector[16:21])
	sector[21] = 0xf8
	binary.LittleEndian.PutUint16(sector[22:24], 0)
	heads, sectors := fsinternal.LegacyBIOSGeometry(uint32(b.hiddenLBA + b.size/ntfsSectorSize))
	binary.LittleEndian.PutUint16(sector[24:26], uint16(sectors))
	binary.LittleEndian.PutUint16(sector[26:28], uint16(heads))
	binary.LittleEndian.PutUint32(sector[28:32], uint32(b.hiddenLBA))
	binary.LittleEndian.PutUint32(sector[32:36], 0)
	sector[36] = 0x80
	clear(sector[37:40])
	binary.LittleEndian.PutUint64(sector[40:48], uint64(b.size/ntfsSectorSize-1))
	binary.LittleEndian.PutUint64(sector[48:56], uint64(b.mftLCN))
	binary.LittleEndian.PutUint64(sector[56:64], uint64(b.mftMirrLCN))
	sector[64] = ntfsBPBSizeDescriptor(ntfsRecordSize)
	clear(sector[65:68])
	sector[68] = ntfsBPBSizeDescriptor(ntfsIndexSize)
	clear(sector[69:72])
	binary.LittleEndian.PutUint64(sector[72:80], 0x544e52584e544653)
	sector[510] = 0x55
	sector[511] = 0xaa
	return sector
}

func ntfsBPBSizeDescriptor(size int64) byte {
	if size >= ntfsCluster && size%ntfsCluster == 0 {
		return byte(size / ntfsCluster)
	}
	power := byte(0)
	for v := size; v > 1; v >>= 1 {
		power++
	}
	return byte(int8(-int8(power)))
}

func (b *ntfsBuild) bootData() []byte {
	size := b.bootFileSize()
	data := make([]byte, size)
	if len(b.bootCode) > 0 {
		copy(data, b.bootCode)
	}
	copy(data, b.bootSector())
	return data
}

func (b *ntfsBuild) bootFileSize() int64 {
	size := ntfsBootSize
	if len(b.bootCode) > 0 {
		size = max(size, fsinternal.Align(int64(len(b.bootCode)), ntfsSectorSize))
	}
	if size > ntfsCluster {
		return fsinternal.Align(size, ntfsCluster)
	}
	return ntfsCluster
}

func (b *ntfsBuild) volumeBitmap() []byte {
	clusters := b.size / ntfsCluster
	data := make([]byte, fsinternal.CeilDiv(clusters, 8))
	mark := func(start, count int64) {
		for i := int64(0); i < count; i++ {
			c := start + i
			if c >= 0 && c < clusters {
				data[c/8] |= 1 << uint(c%8)
			}
		}
	}
	mark(0, fsinternal.CeilDiv(b.bootFileSize(), ntfsCluster))
	mark(clusters-1, 1)
	mark(b.mftLCN, fsinternal.CeilDiv(b.mftRecords*ntfsRecordSize, ntfsCluster))
	mark(b.mftMirrLCN, fsinternal.CeilDiv(minInt64(4, b.mftRecords)*ntfsRecordSize, ntfsCluster))
	mark(b.mftBitmapLCN, fsinternal.CeilDiv(int64(len(b.mftBitmapData)), ntfsCluster))
	mark(b.logFileLCN, fsinternal.CeilDiv(b.logFileSize(), ntfsCluster))
	mark(b.attrDefLCN, fsinternal.CeilDiv(int64(len(b.attrDef)), ntfsCluster))
	mark(b.upCaseLCN, fsinternal.CeilDiv(int64(len(b.upCase)), ntfsCluster))
	if b.modern() {
		mark(b.rootSecurityLCN, fsinternal.CeilDiv(int64(len(b.rootSecurity)), ntfsCluster))
		mark(b.secureLCN, fsinternal.CeilDiv(int64(len(b.secureData)), ntfsCluster))
		if len(b.secureIDIndex.blocks) > 0 {
			mark(b.secureIDLCN, fsinternal.CeilDiv(int64(len(b.secureIDIndex.blocks)), ntfsCluster))
		}
		if len(b.secureHashIndex.blocks) > 0 {
			mark(b.secureHashLCN, fsinternal.CeilDiv(int64(len(b.secureHashIndex.blocks)), ntfsCluster))
		}
	}
	mark(b.bitmapLCN, fsinternal.CeilDiv(b.bitmapSize, ntfsCluster))
	for _, node := range b.nodes {
		if node.attributeListLCN > 0 && len(node.attributeList) > 0 {
			mark(node.attributeListLCN, fsinternal.CeilDiv(int64(len(node.attributeList)), ntfsCluster))
		}
		if node.lcn > 0 && node.clusters > 0 {
			mark(node.lcn, node.clusters)
		}
		if node.indexLCN > 0 && len(node.index.blocks) > 0 {
			mark(node.indexLCN, fsinternal.CeilDiv(int64(len(node.index.blocks)), ntfsCluster))
		}
	}
	return data
}

func applyNTFSFixup(data []byte, usaOff, usaCount uint16) {
	seq := uint16(1)
	binary.LittleEndian.PutUint16(data[usaOff:usaOff+2], seq)
	for i := uint16(1); i < usaCount; i++ {
		sectorEnd := int(i)*int(ntfsSectorSize) - 2
		binary.LittleEndian.PutUint16(data[int(usaOff)+int(i)*2:], binary.LittleEndian.Uint16(data[sectorEnd:sectorEnd+2]))
		binary.LittleEndian.PutUint16(data[sectorEnd:sectorEnd+2], seq)
	}
}

func joinBytes(values [][]byte) []byte {
	var size int
	for _, value := range values {
		size += len(value)
	}
	out := make([]byte, 0, size)
	for _, value := range values {
		out = append(out, value...)
	}
	return out
}

func windowsFiletime(t time.Time) int64 {
	return t.UnixNano()/100 + 116444736000000000
}

func utf16Bytes(s string) []byte {
	units := utf16.Encode([]rune(s))
	data := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(data[i*2:i*2+2], unit)
	}
	return data
}

func ntfsCompareName(a, b string) int {
	left := utf16.Encode([]rune(a))
	right := utf16.Encode([]rune(b))
	for index := 0; index < min(len(left), len(right)); index++ {
		l := uint16(unicode.ToUpper(rune(left[index])))
		r := uint16(unicode.ToUpper(rune(right[index])))
		if l < r {
			return -1
		}
		if l > r {
			return 1
		}
	}
	if len(left) < len(right) {
		return -1
	}
	if len(left) > len(right) {
		return 1
	}
	return 0
}

func ntfsDOSName(name string) (string, bool) {
	if name == "" || name == "." || name == ".." || strings.Count(name, ".") > 1 {
		return "", false
	}
	upper := strings.ToUpper(name)
	base, extension := upper, ""
	if dot := strings.LastIndexByte(upper, '.'); dot >= 0 {
		base, extension = upper[:dot], upper[dot+1:]
	}
	if len(base) == 0 || len(base) > 8 || len(extension) > 3 {
		return "", false
	}
	for _, part := range []string{base, extension} {
		for _, character := range part {
			if !ntfsDOSCharacter(character) {
				return "", false
			}
		}
	}
	return upper, true
}

func ntfsDOSAlias(name string, node *ntfsNode, used map[string]*ntfsNode) string {
	base, extension := name, ""
	if dot := strings.LastIndexByte(name, '.'); dot >= 0 {
		base, extension = name[:dot], name[dot+1:]
	}
	base = ntfsSanitizeDOSPart(base)
	extension = ntfsSanitizeDOSPart(extension)
	if base == "" {
		base = "_"
	}
	if len(extension) > 3 {
		extension = extension[:3]
	}
	for serial := 1; ; serial++ {
		suffix := fmt.Sprintf("~%d", serial)
		prefixLength := 8 - len(suffix)
		if prefixLength < 1 {
			prefixLength = 1
		}
		prefix := base
		if len(prefix) > prefixLength {
			prefix = prefix[:prefixLength]
		}
		alias := prefix + suffix
		if extension != "" {
			alias += "." + extension
		}
		if owner := used[alias]; owner == nil || owner == node {
			return alias
		}
	}
}

func ntfsSanitizeDOSPart(value string) string {
	var builder strings.Builder
	for _, character := range strings.ToUpper(value) {
		if ntfsDOSCharacter(character) {
			builder.WriteRune(character)
		}
	}
	return builder.String()
}

func ntfsDOSCharacter(character rune) bool {
	if character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' {
		return true
	}
	return strings.ContainsRune("$%'-_@~`!(){}^#&", character)
}

func align8(v int) int {
	return (v + 7) &^ 7
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
