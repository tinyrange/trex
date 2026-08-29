package ntfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	filesystemapi "github.com/tinyrange/trex/filesystem"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func TestNTFSBuiltinAcceptsVolumesLargerThanTwoGiB(t *testing.T) {
	root := filesystemapi.New()
	value, err := NTFSBuiltin(nil, nil, starlark.Tuple{root}, []starlark.Tuple{{
		starlark.String("size"),
		starlark.MakeInt64(3 << 30),
	}})
	if err != nil {
		t.Fatal(err)
	}
	image, ok := value.(starfile.File)
	if !ok {
		t.Fatalf("ntfs result = %T, want starfile.File", value)
	}
	if got := image.Size(); got != 3<<30 {
		t.Fatalf("ntfs image size = %d, want %d", got, int64(3<<30))
	}
}

func TestNTFSIndexBlockVCNsUseClusterUnits(t *testing.T) {
	root := &ntfsNode{id: 16, name: "large", fullPath: "/large", dir: true}
	for i := 0; i < 160; i++ {
		name := fmt.Sprintf("Long directory entry %03d.txt", i)
		child := &ntfsNode{id: uint64(17 + i), name: name, fullPath: "/large/" + name, parent: root}
		child.names = []ntfsName{{value: name, namespace: 1}}
		root.children = append(root.children, &ntfsDirectoryLink{node: child, name: name, names: child.names})
	}
	index, err := buildNTFSDirectoryIndex(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if blocks := len(index.blocks) / int(ntfsIndexSize); blocks < 2 {
		t.Fatalf("index has %d blocks, want a multi-block index", blocks)
	}
	for offset, block := 0, 0; offset < len(index.blocks); offset, block = offset+int(ntfsIndexSize), block+1 {
		got := binary.LittleEndian.Uint64(index.blocks[offset+16 : offset+24])
		want := ntfsIndexVCN(block)
		if got != want {
			t.Fatalf("index block %d VCN = %d, want %d", block, got, want)
		}
	}
}

func TestNTFSLargeDirectoryIndexRootHasSeparatorKeys(t *testing.T) {
	root := &ntfsNode{
		id:       16,
		name:     "large",
		fullPath: "/large",
		dir:      true,
		names: []ntfsName{
			{value: "Large component directory with a long name", namespace: 1},
			{value: "LARGEC~1", namespace: 2},
		},
	}
	for index := 0; index < 900; index++ {
		name := fmt.Sprintf("Component directory entry with a long name %04d.dll", index)
		child := &ntfsNode{id: uint64(1000 + index), name: name, fullPath: "/large/" + name, parent: root}
		child.names = []ntfsName{{value: name, namespace: 1, parent: root}}
		root.children = append(root.children, &ntfsDirectoryLink{node: child, name: name, names: child.names})
	}
	index, err := buildNTFSDirectoryIndex(root, true)
	if err != nil {
		t.Fatal(err)
	}
	first := index.rootValue[32:]
	if got := binary.LittleEndian.Uint16(first[12:14]); got != ntfsIndexHasSub {
		t.Fatalf("large directory root starts with flags %#x, want a separator with a child", got)
	}
	length := int(binary.LittleEndian.Uint16(first[8:10]))
	if got := binary.LittleEndian.Uint16(first[length+12 : length+14]); got != ntfsIndexLast|ntfsIndexHasSub {
		t.Fatalf("large directory root end flags = %#x, want last entry with a child", got)
	}
}

func TestNTFSHardLinksShareAFileRecord(t *testing.T) {
	root := filesystemapi.New()
	root.Mkdir("/one")
	root.Mkdir("/two")
	root.PutFile("/one/example.txt", filesystemapi.FileRecord{Data: []byte("shared"), Size: 6})
	root.PutFile("/two/alias.txt", filesystemapi.FileRecord{Data: []byte("shared"), Size: 6})
	root.SetMetadata("/one/example.txt", filesystemapi.Metadata{HardLink: 99, ShortName: "EXAMPLE.TXT"})
	root.SetMetadata("/two/alias.txt", filesystemapi.Metadata{HardLink: 99, ShortName: "ALIAS.TXT"})
	image, err := buildNTFSImageWithOptions(root, 64<<20, nil, 0, "LINKS", 3, 1)
	if err != nil {
		t.Fatal(err)
	}
	volume, err := newNTFSVolume(image)
	if err != nil {
		t.Fatal(err)
	}
	one := volume.paths["/one/example.txt"]
	two := volume.paths["/two/alias.txt"]
	if one == nil || two == nil {
		t.Fatalf("hard-link paths missing: one=%v two=%v", one, two)
	}
	if one.id != two.id {
		t.Fatalf("hard links use records %d and %d", one.id, two.id)
	}
	boot := make([]byte, ntfsSectorSize)
	if _, err := image.ReadAt(boot, 0); err != nil {
		t.Fatal(err)
	}
	record := make([]byte, ntfsRecordSize)
	mftOffset := int64(binary.LittleEndian.Uint64(boot[48:56])) * ntfsCluster
	if _, err := image.ReadAt(record, mftOffset+int64(one.id)*ntfsRecordSize); err != nil {
		t.Fatal(err)
	}
	if err := applyNTFSReadFixup(record, ntfsSectorSize, "hard-linked file"); err != nil {
		t.Fatal(err)
	}
	attributes, err := parseNTFSReadAttributes(record, ntfsCluster)
	if err != nil {
		t.Fatal(err)
	}
	fileNames := 0
	for _, attribute := range attributes {
		if attribute.typ != ntfsAttrFileName {
			continue
		}
		fileNames++
		if got := attribute.value[65]; got != 0 {
			t.Errorf("hard-link name namespace = %d, want POSIX namespace 0", got)
		}
	}
	if fileNames != 2 {
		t.Fatalf("hard-linked file has %d file-name attributes, want one per link", fileNames)
	}
}

func TestNTFSAttributeListEntriesAreOrderedByType(t *testing.T) {
	node := &ntfsNode{id: 27, fullPath: "/many-links", size: 1}
	for index := 0; index < 12; index++ {
		node.names = append(node.names, ntfsName{
			value:     fmt.Sprintf("long-hard-link-name-%02d.bin", index),
			namespace: 0,
		})
	}
	b := &ntfsBuild{nodes: []*ntfsNode{node}, nextID: 28, versionMajor: 3, versionMinor: 1}
	if err := b.createAttributeExtensions(); err != nil {
		t.Fatal(err)
	}
	if len(node.attributeList) == 0 {
		t.Fatal("large file-name set did not create an attribute list")
	}
	previous := uint32(0)
	for offset := 0; offset < len(node.attributeList); offset += 32 {
		typ := binary.LittleEndian.Uint32(node.attributeList[offset : offset+4])
		if typ == ntfsAttrAttributeList {
			t.Fatal("attribute list contains an entry for itself")
		}
		if got := node.attributeList[offset+7]; got != 26 {
			t.Fatalf("attribute-list name offset = %d, want 26", got)
		}
		if typ < previous {
			t.Fatalf("attribute-list type %#x follows %#x", typ, previous)
		}
		previous = typ
	}
}

func TestNTFSIndexBlockEntryOffsetIsRelativeToIndexHeader(t *testing.T) {
	entry := ntfsIndexEndEntry(false, 0)
	block := ntfsIndexBlock(0, [][]byte{entry}, false)

	if got, want := binary.LittleEndian.Uint32(block[24:28]), uint32(0x40); got != want {
		t.Fatalf("index entry offset = %#x, want %#x", got, want)
	}
	if got, want := binary.LittleEndian.Uint16(block[0x58+8:0x58+10]), uint16(len(entry)); got != want {
		t.Fatalf("first index entry length = %#x, want %#x", got, want)
	}
}

func TestNTFSRunListPreservesPositiveSignedLCN(t *testing.T) {
	raw := ntfsRunList(1, 0x80)
	if want := []byte{0x21, 0x01, 0x80, 0x00, 0x00}; !bytes.Equal(raw, want) {
		t.Fatalf("run list = %x, want %x", raw, want)
	}
	runs, err := decodeNTFSDataRuns(raw, ntfsCluster)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].start != 0x80 || runs[0].length != 1 {
		t.Fatalf("decoded runs = %+v", runs)
	}
}

func TestNTFSRunListZeroExtendsHighBitRunLengths(t *testing.T) {
	raw := ntfsRunList(0x80, 1)
	if want := []byte{0x12, 0x80, 0x00, 0x01, 0x00}; !bytes.Equal(raw, want) {
		t.Fatalf("run list = %x, want %x", raw, want)
	}
	runs, err := decodeNTFSDataRuns(raw, ntfsCluster)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].start != 1 || runs[0].length != 0x80 {
		t.Fatalf("decoded runs = %+v", runs)
	}
}

func TestNTFSBadClustersUsesSparseVolumeRun(t *testing.T) {
	const volumeSize = int64(64 << 20)
	attr := ntfsBadClustersAttr(volumeSize)
	runOffset := int(binary.LittleEndian.Uint16(attr[32:34]))
	wantRun := []byte{0x03, 0xff, 0xff, 0x01, 0x00}
	if got := attr[runOffset : runOffset+len(wantRun)]; !bytes.Equal(got, wantRun) {
		t.Fatalf("$Bad run = %x, want sparse run %x", got, wantRun)
	}
	wantSize := uint64(volumeSize - ntfsSectorSize)
	if got := binary.LittleEndian.Uint64(attr[40:48]); got != wantSize {
		t.Fatalf("$Bad allocated size = %d, want %d", got, wantSize)
	}
	if got := binary.LittleEndian.Uint64(attr[48:56]); got != wantSize {
		t.Fatalf("$Bad data size = %d, want %d", got, wantSize)
	}
	if got := binary.LittleEndian.Uint64(attr[56:64]); got != 0 {
		t.Fatalf("$Bad initialized size = %d, want 0", got)
	}
}

func TestNTFS31UpCasePreservesHistoricalIdentityMappings(t *testing.T) {
	data := ntfsUpCaseData(true)
	if got := binary.LittleEndian.Uint16(data['a'*2:]); got != 'A' {
		t.Fatalf("uppercase(a) = %#x, want %#x", got, 'A')
	}
	for _, identity := range ntfs31UpCaseIdentity {
		for value := identity.first; value <= identity.last; value += identity.step {
			if got := binary.LittleEndian.Uint16(data[value*2:]); got != uint16(value) {
				t.Fatalf("uppercase(%#x) = %#x, want identity mapping", value, got)
			}
		}
	}
}

func TestNTFSVolumeBitmapAllocatesBackupBootSector(t *testing.T) {
	b := &ntfsBuild{size: 64 << 20}
	bitmap := b.volumeBitmap()
	lastCluster := b.size/ntfsCluster - 1
	if bitmap[lastCluster/8]&(1<<uint(lastCluster%8)) == 0 {
		t.Fatal("backup boot-sector cluster is free in $Bitmap")
	}
}

func TestNTFSAttrDefUsesNTFS11Layout(t *testing.T) {
	data := ntfsAttrDefData(false)
	if len(data) != 36000 {
		t.Fatalf("$AttrDef size = %d, want 36000", len(data))
	}
	type expectedDefinition struct {
		row     int
		name    string
		typ     uint32
		flags   uint32
		minSize uint64
		maxSize uint64
	}
	for _, want := range []expectedDefinition{
		{row: 0, name: "$STANDARD_INFORMATION", typ: ntfsAttrStandardInformation, flags: 0x40, minSize: 48, maxSize: 48},
		{row: 2, name: "$FILE_NAME", typ: ntfsAttrFileName, flags: 0x42, minSize: 68, maxSize: 578},
		{row: 9, name: "$INDEX_ALLOCATION", typ: ntfsAttrIndexAllocation, flags: 0x80, maxSize: ^uint64(0)},
		{row: 13, name: "$EA", typ: 0xe0, maxSize: 0x10000},
	} {
		row := data[want.row*160 : (want.row+1)*160]
		if !bytes.HasPrefix(row[:128], utf16Bytes(want.name)) {
			t.Fatalf("$AttrDef row %d does not start with %q", want.row, want.name)
		}
		if got := binary.LittleEndian.Uint32(row[128:132]); got != want.typ {
			t.Fatalf("$AttrDef row %d type = %#x, want %#x", want.row, got, want.typ)
		}
		if got := binary.LittleEndian.Uint32(row[140:144]); got != want.flags {
			t.Fatalf("$AttrDef row %d flags = %#x, want %#x", want.row, got, want.flags)
		}
		if got := binary.LittleEndian.Uint64(row[144:152]); got != want.minSize {
			t.Fatalf("$AttrDef row %d minimum = %d, want %d", want.row, got, want.minSize)
		}
		if got := binary.LittleEndian.Uint64(row[152:160]); got != want.maxSize {
			t.Fatalf("$AttrDef row %d maximum = %d, want %d", want.row, got, want.maxSize)
		}
	}
}

func TestNTFS31SystemMetadata(t *testing.T) {
	data := ntfsAttrDefData(true)
	if len(data) != 16*160 {
		t.Fatalf("$AttrDef size = %d, want %d", len(data), 16*160)
	}
	if got := binary.LittleEndian.Uint64(data[152:160]); got != 72 {
		t.Fatalf("$STANDARD_INFORMATION maximum = %d, want 72", got)
	}
	if !bytes.HasPrefix(data[3*160:4*160], utf16Bytes("$OBJECT_ID")) {
		t.Fatal("$AttrDef does not define $OBJECT_ID")
	}
	if !bytes.HasPrefix(data[14*160:15*160], utf16Bytes("$LOGGED_UTILITY_STREAM")) {
		t.Fatal("$AttrDef does not define $LOGGED_UTILITY_STREAM")
	}

	root := filesystemapi.New()
	image, err := buildNTFSImageWithOptions(root, 64<<20, nil, 0, "MODERN", 3, 1)
	if err != nil {
		t.Fatal(err)
	}
	volume, err := newNTFSVolume(image)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"/$secure", "/$extend/$quota", "/$extend/$objid", "/$extend/$reparse"} {
		if _, ok := volume.paths[name]; !ok {
			t.Errorf("missing NTFS 3.1 metadata file %s", name)
		}
	}

	boot := make([]byte, ntfsSectorSize)
	if _, err := image.ReadAt(boot, 0); err != nil {
		t.Fatal(err)
	}
	mftOffset := int64(binary.LittleEndian.Uint64(boot[48:56])) * ntfsCluster
	record := make([]byte, ntfsRecordSize)
	if _, err := image.ReadAt(record, mftOffset+9*ntfsRecordSize); err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint16(record[4:6]); got != 0x30 {
		t.Fatalf("$Secure USA offset = %#x, want 0x30", got)
	}
	if got := binary.LittleEndian.Uint16(record[20:22]); got != 0x38 {
		t.Fatalf("$Secure attribute offset = %#x, want 0x38", got)
	}
	if got := binary.LittleEndian.Uint32(record[44:48]); got != 9 {
		t.Fatalf("$Secure record number = %d, want 9", got)
	}
	if err := applyNTFSReadFixup(record, ntfsSectorSize, "$Secure"); err != nil {
		t.Fatal(err)
	}
	attributes, err := parseNTFSReadAttributes(record, ntfsCluster)
	if err != nil {
		t.Fatal(err)
	}
	var sds *ntfsReadAttribute
	indexes := make(map[string]bool)
	for index := range attributes {
		attribute := &attributes[index]
		if attribute.typ == ntfsAttrData && attribute.name == "$SDS" {
			sds = attribute
		}
		if attribute.typ == ntfsAttrIndexRoot {
			indexes[attribute.name] = true
		}
	}
	if sds == nil || len(sds.runs) != 1 || !indexes["$SDH"] || !indexes["$SII"] {
		t.Fatalf("$Secure attributes = %+v", attributes)
	}
	entryLength := 20 + len(ntfsDefaultSecurityDescriptor())
	stream := make([]byte, ntfsSecureMirrorBase+entryLength)
	if _, err := image.ReadAt(stream, sds.runs[0].start*ntfsCluster); err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(stream[0:4]); got != ntfsSecurityDescriptorHash(ntfsDefaultSecurityDescriptor()) {
		t.Fatalf("$SDS hash = %#x", got)
	}
	if got := binary.LittleEndian.Uint32(stream[4:8]); got != ntfsSecurityID {
		t.Fatalf("$SDS security ID = %#x", got)
	}
	if got := binary.LittleEndian.Uint32(stream[16:20]); got != uint32(entryLength) {
		t.Fatalf("$SDS entry length = %d", got)
	}
	if !bytes.Equal(stream[:entryLength], stream[ntfsSecureMirrorBase:]) {
		t.Fatal("$SDS mirror differs from primary entry")
	}

	rootRecord := make([]byte, ntfsRecordSize)
	if _, err := image.ReadAt(rootRecord, mftOffset+5*ntfsRecordSize); err != nil {
		t.Fatal(err)
	}
	if err := applyNTFSReadFixup(rootRecord, ntfsSectorSize, "root"); err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint16(rootRecord[40:42]); got != 9 {
		t.Fatalf("root next attribute ID = %d, want 9", got)
	}
	if got := binary.LittleEndian.Uint32(rootRecord[24:28]); got != 512 {
		t.Fatalf("root record used size = %d, want 512", got)
	}
	rootAttributes, err := parseNTFSReadAttributes(rootRecord, ntfsCluster)
	if err != nil {
		t.Fatal(err)
	}
	foundLegacySecurity := false
	for _, attribute := range rootAttributes {
		if attribute.typ == ntfsAttrStandardInformation && len(attribute.value) != 48 {
			t.Fatalf("root standard information size = %d, want 48", len(attribute.value))
		}
		if attribute.typ == ntfsAttrSecurityDescriptor {
			foundLegacySecurity = true
			if !attribute.nonresident || attribute.size != 4160 {
				t.Fatalf("root security descriptor = %+v, want 4160-byte nonresident attribute", attribute)
			}
		}
	}
	if !foundLegacySecurity {
		t.Fatal("NTFS 3.1 root lacks its compatibility security descriptor")
	}

	reservedRecord := make([]byte, ntfsRecordSize)
	if _, err := image.ReadAt(reservedRecord, mftOffset+12*ntfsRecordSize); err != nil {
		t.Fatal(err)
	}
	if err := applyNTFSReadFixup(reservedRecord, ntfsSectorSize, "reserved"); err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint16(reservedRecord[40:42]); got != 3 {
		t.Fatalf("reserved next attribute ID = %d, want 3", got)
	}
	ids := make(map[uint32]uint16)
	offset := int(binary.LittleEndian.Uint16(reservedRecord[20:22]))
	for binary.LittleEndian.Uint32(reservedRecord[offset:]) != ntfsAttrEnd {
		typ := binary.LittleEndian.Uint32(reservedRecord[offset:])
		ids[typ] = binary.LittleEndian.Uint16(reservedRecord[offset+14:])
		offset += int(binary.LittleEndian.Uint32(reservedRecord[offset+4:]))
	}
	for typ, want := range map[uint32]uint16{
		ntfsAttrStandardInformation: 0,
		ntfsAttrData:                1,
		ntfsAttrSecurityDescriptor:  2,
	} {
		if got := ids[typ]; got != want {
			t.Fatalf("reserved attribute %#x ID = %d, want %d", typ, got, want)
		}
	}
}

func TestNTFSResidentAttributeAlwaysHasANameOffset(t *testing.T) {
	for _, name := range []string{"", "$I30"} {
		attribute := ntfsResidentAttr(ntfsAttrData, name, []byte("value"))
		if got := binary.LittleEndian.Uint16(attribute[10:12]); got != 24 {
			t.Fatalf("resident attribute %q name offset = %d, want 24", name, got)
		}
	}
}

func TestNTFS31PreservesImportedSecurityDescriptors(t *testing.T) {
	root := filesystemapi.New()
	for index := 0; index < 150; index++ {
		name := fmt.Sprintf("/secured-%03d", index)
		root.PutFile(name, filesystemapi.FileRecord{Data: []byte{byte(index)}, Size: 1})
		descriptor := ntfsSecurityDescriptor(
			ntfsSID(5, 18),
			ntfsSID(5, 18),
			0x00120089,
			ntfsSID(5, 21, uint32(index+1)),
		)
		root.SetMetadata(name, filesystemapi.Metadata{SecurityDescriptor: descriptor})
	}
	image, err := buildNTFSImageWithOptions(root, 64<<20, nil, 0, "SECURITY", 3, 1)
	if err != nil {
		t.Fatal(err)
	}
	volume, err := newNTFSVolume(image)
	if err != nil {
		t.Fatal(err)
	}
	boot := make([]byte, ntfsSectorSize)
	if _, err := image.ReadAt(boot, 0); err != nil {
		t.Fatal(err)
	}
	mftOffset := int64(binary.LittleEndian.Uint64(boot[48:56])) * ntfsCluster
	securityIDs := make(map[uint32]bool)
	for _, index := range []int{0, 75, 149} {
		entry := volume.paths[fmt.Sprintf("/secured-%03d", index)]
		if entry == nil {
			t.Fatalf("secured file %d is missing", index)
		}
		record := make([]byte, ntfsRecordSize)
		if _, err := image.ReadAt(record, mftOffset+int64(entry.id)*ntfsRecordSize); err != nil {
			t.Fatal(err)
		}
		if err := applyNTFSReadFixup(record, ntfsSectorSize, entry.path); err != nil {
			t.Fatal(err)
		}
		attributes, err := parseNTFSReadAttributes(record, ntfsCluster)
		if err != nil {
			t.Fatal(err)
		}
		for _, attribute := range attributes {
			if attribute.typ == ntfsAttrStandardInformation {
				securityIDs[binary.LittleEndian.Uint32(attribute.value[52:56])] = true
			}
		}
	}
	if len(securityIDs) != 3 || securityIDs[ntfsSecurityID] {
		t.Fatalf("imported files use security IDs %v", securityIDs)
	}

	secureRecord := make([]byte, ntfsRecordSize)
	if _, err := image.ReadAt(secureRecord, mftOffset+9*ntfsRecordSize); err != nil {
		t.Fatal(err)
	}
	if err := applyNTFSReadFixup(secureRecord, ntfsSectorSize, "$Secure"); err != nil {
		t.Fatal(err)
	}
	attributes, err := parseNTFSReadAttributes(secureRecord, ntfsCluster)
	if err != nil {
		t.Fatal(err)
	}
	allocations := make(map[string]bool)
	previousType := uint32(0)
	for _, attribute := range attributes {
		if attribute.typ < previousType {
			t.Fatalf("$Secure attribute type %#x follows %#x", attribute.typ, previousType)
		}
		previousType = attribute.typ
		if attribute.typ == ntfsAttrIndexAllocation {
			allocations[attribute.name] = true
		}
	}
	if !allocations["$SDH"] || !allocations["$SII"] {
		t.Fatalf("large security indexes have allocations %v", allocations)
	}
}

func TestNTFS31SecurityStoreUsesMirroredSegments(t *testing.T) {
	b := &ntfsBuild{versionMajor: 3, versionMinor: 1}
	for index := 0; index < 5000; index++ {
		descriptor := ntfsSecurityDescriptor(
			ntfsSID(5, 18),
			ntfsSID(5, 18),
			0x00120089,
			ntfsSID(5, 21, uint32(index+1)),
		)
		b.nodes = append(b.nodes, &ntfsNode{
			fullPath: fmt.Sprintf("/secured-%04d", index),
			metadata: filesystemapi.Metadata{SecurityDescriptor: descriptor},
		})
	}
	if err := b.prepareSecurity(); err != nil {
		t.Fatal(err)
	}
	if len(b.secureData) <= 3*ntfsSecureMirrorBase {
		t.Fatalf("security store size = %d, want more than three segments", len(b.secureData))
	}
	if got := b.nodes[len(b.nodes)-1].securityID; got != ntfsSecurityID+uint32(len(b.nodes)) {
		t.Fatalf("last security ID = %#x", got)
	}
	secondPair := 2 * ntfsSecureMirrorBase
	if !bytes.Equal(
		b.secureData[secondPair:secondPair+20],
		b.secureData[secondPair+ntfsSecureMirrorBase:secondPair+ntfsSecureMirrorBase+20],
	) {
		t.Fatal("second $SDS segment mirror differs from its primary")
	}
	for name, index := range map[string]ntfsSecurityIndex{
		"$SDH": b.secureHashIndex,
		"$SII": b.secureIDIndex,
	} {
		if len(index.blocks) == 0 {
			t.Fatalf("%s has no index allocation", name)
		}
		first := index.rootValue[32:]
		if got := binary.LittleEndian.Uint16(first[12:14]); got != ntfsIndexLast|ntfsIndexHasSub {
			t.Fatalf("%s root flags = %#x, want the single-child metadata-index form", name, got)
		}
	}
}

func TestNTFS31VolumeBitmapMarksSecurityIndexes(t *testing.T) {
	b := &ntfsBuild{
		size:          64 << 20,
		versionMajor:  3,
		versionMinor:  1,
		secureIDLCN:   120,
		secureHashLCN: 140,
		secureIDIndex: ntfsSecurityIndex{
			blocks: make([]byte, 2*ntfsIndexSize),
		},
		secureHashIndex: ntfsSecurityIndex{
			blocks: make([]byte, 3*ntfsIndexSize),
		},
	}
	bitmap := b.volumeBitmap()
	for first, count := range map[int64]int64{120: 16, 140: 24} {
		for cluster := first; cluster < first+count; cluster++ {
			if bitmap[cluster/8]&(1<<uint(cluster%8)) == 0 {
				t.Fatalf("security-index cluster %d is free in the volume bitmap", cluster)
			}
		}
	}
}

func TestNTFSDefaultSecurityDescriptorInheritsUsableAccess(t *testing.T) {
	descriptor := ntfsDefaultSecurityDescriptor()
	aclOffset := int(binary.LittleEndian.Uint32(descriptor[16:20]))
	if aclOffset != 20 {
		t.Fatalf("DACL offset = %d, want 20", aclOffset)
	}
	acl := descriptor[aclOffset:]
	if got := binary.LittleEndian.Uint16(acl[4:6]); got != 7 {
		t.Fatalf("ACE count = %d, want 7", got)
	}

	wantFlags := []byte{0x03, 0x03, 0x0b, 0x03, 0x02, 0x0a, 0x00}
	wantMasks := []uint32{0x001f01ff, 0x001f01ff, 0x10000000, 0x001200a9, 0x00000004, 0x00000002, 0x001200a9}
	offset := 8
	for index := range wantFlags {
		size := int(binary.LittleEndian.Uint16(acl[offset+2 : offset+4]))
		if got := acl[offset+1]; got != wantFlags[index] {
			t.Errorf("ACE %d flags = %#x, want %#x", index, got, wantFlags[index])
		}
		if got := binary.LittleEndian.Uint32(acl[offset+4 : offset+8]); got != wantMasks[index] {
			t.Errorf("ACE %d mask = %#x, want %#x", index, got, wantMasks[index])
		}
		offset += size
	}
	if offset != int(binary.LittleEndian.Uint16(acl[2:4])) {
		t.Fatalf("ACEs end at %d, ACL ends at %d", offset, binary.LittleEndian.Uint16(acl[2:4]))
	}

	root := ntfsRootSecurityDescriptor()
	if len(root) != 4160 {
		t.Fatalf("root security descriptor size = %d, want 4160", len(root))
	}
	rootACL := root[binary.LittleEndian.Uint32(root[16:20]):]
	if got := binary.LittleEndian.Uint16(rootACL[2:4]); got != 4096 {
		t.Fatalf("root ACL size = %d, want 4096", got)
	}
	if got := binary.LittleEndian.Uint16(rootACL[4:6]); got != 7 {
		t.Fatalf("root ACE count = %d, want 7", got)
	}
	if !bytes.Equal(rootACL[8:offset], acl[8:offset]) {
		t.Fatal("root and shared security descriptors have different ACEs")
	}

	legacy := ntfsLegacySecurityDescriptor()
	if len(legacy) != 104 {
		t.Fatalf("legacy security descriptor size = %d, want 104", len(legacy))
	}
	legacyACL := legacy[binary.LittleEndian.Uint32(legacy[16:20]):]
	if got := binary.LittleEndian.Uint16(legacyACL[4:6]); got != 2 {
		t.Fatalf("legacy ACE count = %d, want 2", got)
	}
	legacyOffset := 8
	for index := 0; index < 2; index++ {
		if got := legacyACL[legacyOffset+1]; got != 0x03 {
			t.Errorf("legacy ACE %d flags = %#x, want 0x03", index, got)
		}
		legacyOffset += int(binary.LittleEndian.Uint16(legacyACL[legacyOffset+2 : legacyOffset+4]))
	}
}

func TestNTFSDirectoryIndexRejectsAnUnrepresentableRoot(t *testing.T) {
	node := &ntfsNode{
		name:     "oversized",
		fullPath: "/oversized",
		dir:      true,
		names: []ntfsName{
			{value: strings.Repeat("a", 220), namespace: 1},
			{value: strings.Repeat("b", 220), namespace: 2},
		},
	}
	for index := 0; index < 100; index++ {
		child := &ntfsNode{
			id:     uint64(index + 100),
			name:   fmt.Sprintf("file-%03d", index),
			parent: node,
		}
		child.names = []ntfsName{{value: child.name, namespace: 1}}
		node.children = append(node.children, &ntfsDirectoryLink{node: child, name: child.name, names: child.names})
	}
	if _, err := buildNTFSDirectoryIndex(node, false); err == nil {
		t.Fatal("unrepresentable index root was accepted")
	}
}

func TestNTFS31UsesCanonicalSystemRecordNumbers(t *testing.T) {
	root := filesystemapi.New()
	b := &ntfsBuild{nextID: 16, versionMajor: 3, versionMinor: 1}
	if err := b.importDirectory(root); err != nil {
		t.Fatal(err)
	}
	byID := make(map[uint64]*ntfsNode)
	for _, node := range b.nodes {
		byID[node.id] = node
	}
	for id := uint64(12); id < 16; id++ {
		if node := byID[id]; node == nil || node.systemKind != "reserved" || len(node.names) != 0 {
			t.Fatalf("MFT record %d = %+v, want unnamed reserved record", id, node)
		} else if got := ntfsFileFlags(node); got != ntfsFileAttrHide|ntfsFileAttrSys {
			t.Fatalf("MFT record %d file flags = %#x, want hidden and system", id, got)
		}
	}
	for id := uint64(16); id < 24; id++ {
		if node := byID[id]; node != nil {
			t.Fatalf("MFT record %d unexpectedly allocated to %+v", id, node)
		}
	}
	for id, name := range map[uint64]string{24: "$Quota", 25: "$ObjId", 26: "$Reparse"} {
		if node := byID[id]; node == nil || node.name != name || node.parent == nil || node.parent.id != 11 {
			t.Fatalf("MFT record %d = %+v, want %s under $Extend", id, node, name)
		}
	}
	if b.nextID != 27 {
		t.Fatalf("first ordinary NTFS 3.1 record = %d, want 27", b.nextID)
	}
	foundRootSelfEntry := false
	for _, child := range b.root.children {
		if child.node == b.root {
			foundRootSelfEntry = true
			break
		}
	}
	if !foundRootSelfEntry {
		t.Fatal("NTFS root directory lacks its canonical self-entry")
	}
}

func TestNTFSVersionValidation(t *testing.T) {
	for _, version := range []string{"1.1", "3.1"} {
		if _, _, err := parseNTFSVersion(version); err != nil {
			t.Errorf("parseNTFSVersion(%q): %v", version, err)
		}
	}
	if _, _, err := parseNTFSVersion("3.0"); err == nil {
		t.Fatal("unsupported NTFS version was accepted")
	}
}

func TestNTFSMFTRecordUsesNTFS11Layout(t *testing.T) {
	parent := &ntfsNode{id: 5, name: ".", fullPath: "/", dir: true}
	node := &ntfsNode{
		id:       16,
		name:     "example.txt",
		names:    []ntfsName{{value: "example.txt", namespace: 3}},
		fullPath: "/example.txt",
		parent:   parent,
	}
	record, err := (&ntfsBuild{}).mftRecord(node)
	if err != nil {
		t.Fatal(err)
	}
	if string(record[:4]) != "FILE" {
		t.Fatalf("MFT signature = %q", record[:4])
	}
	if got := binary.LittleEndian.Uint16(record[4:6]); got != 0x2a {
		t.Fatalf("USA offset = %#x, want 0x2a", got)
	}
	if got := binary.LittleEndian.Uint16(record[20:22]); got != 0x30 {
		t.Fatalf("attribute offset = %#x, want 0x30", got)
	}
	if got := binary.LittleEndian.Uint32(record[24:28]); got%8 != 0 {
		t.Fatalf("bytes in use = %d, want 8-byte alignment", got)
	}
	for sectorEnd := int(ntfsSectorSize) - 2; sectorEnd < len(record); sectorEnd += int(ntfsSectorSize) {
		if got := binary.LittleEndian.Uint16(record[sectorEnd : sectorEnd+2]); got != 1 {
			t.Fatalf("sector trailer at %d = %#x, want update sequence 1", sectorEnd, got)
		}
	}
	if err := applyNTFSReadFixup(record, ntfsSectorSize, "test record"); err != nil {
		t.Fatal(err)
	}
	foundFileName := false
	for offset := int(binary.LittleEndian.Uint16(record[20:22])); ; {
		typ := binary.LittleEndian.Uint32(record[offset : offset+4])
		if typ == ntfsAttrEnd {
			break
		}
		length := int(binary.LittleEndian.Uint32(record[offset+4 : offset+8]))
		if typ == ntfsAttrFileName {
			foundFileName = true
			if record[offset+22] != 1 {
				t.Fatalf("$FILE_NAME indexed flag = %d, want 1", record[offset+22])
			}
		}
		offset += length
	}
	if !foundFileName {
		t.Fatal("MFT record has no $FILE_NAME attribute")
	}
}

func TestNTFSBootGeometryAndMFTPlacement(t *testing.T) {
	root := filesystemapi.New()
	image, err := buildNTFSImage(root, 64<<20, nil, 63)
	if err != nil {
		t.Fatal(err)
	}
	sector := make([]byte, ntfsSectorSize)
	if _, err := image.ReadAt(sector, 0); err != nil {
		t.Fatal(err)
	}
	if string(sector[3:11]) != "NTFS    " {
		t.Fatalf("OEM ID = %q", sector[3:11])
	}
	if sector[13] != 1 {
		t.Fatalf("sectors per cluster = %d, want 1", sector[13])
	}
	if got := binary.LittleEndian.Uint32(sector[28:32]); got != 63 {
		t.Fatalf("hidden sectors = %d, want 63", got)
	}
	mftLCN := int64(binary.LittleEndian.Uint64(sector[48:56]))
	if mftLCN*ntfsCluster < 16*1024 {
		t.Fatalf("$MFT starts at byte %d, overlapping the boot area", mftLCN*ntfsCluster)
	}
	if sector[64] != byte(ntfsRecordSize/ntfsCluster) {
		t.Fatalf("MFT record descriptor = %d, want %d", sector[64], ntfsRecordSize/ntfsCluster)
	}
	if sector[68] != byte(ntfsIndexSize/ntfsCluster) {
		t.Fatalf("index descriptor = %d, want %d", sector[68], ntfsIndexSize/ntfsCluster)
	}
	volume, err := newNTFSVolume(image)
	if err != nil {
		t.Fatal(err)
	}
	boot := volume.paths["/$boot"]
	if boot == nil || boot.file == nil || boot.file.Size() != ntfsBootSize {
		t.Fatalf("$Boot size = %v, want %d", boot, ntfsBootSize)
	}
	record := make([]byte, ntfsRecordSize)
	if _, err := image.ReadAt(record, mftLCN*ntfsCluster); err != nil {
		t.Fatal(err)
	}
	if string(record[:4]) != "FILE" {
		t.Fatalf("$MFT record signature = %q", record[:4])
	}
}

func TestNTFSBuilderUsesFileBackedMetadataSeeds(t *testing.T) {
	root := filesystemapi.New()
	logData := bytes.Repeat([]byte{0x5a}, 4096)
	upCase := ntfsUpCaseData(true)
	image, err := buildNTFSImageWithMetadata(
		root, 64<<20, nil, 0, "SEEDED", 3, 1,
		&starfile.Bytes{Name: "$LogFile", Data: logData}, upCase,
	)
	if err != nil {
		t.Fatal(err)
	}
	volume, err := newNTFSVolume(image)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string][]byte{"/$logfile": logData, "/$upcase": upCase} {
		node := volume.paths[name]
		if node == nil || node.file == nil {
			t.Fatalf("%s is missing", name)
		}
		got := make([]byte, node.file.Size())
		if _, err := node.file.ReadAt(got, 0); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s does not contain the supplied seed", name)
		}
	}
}

func TestNTFSDefaultLogFileSizeTracksVolumeSize(t *testing.T) {
	tests := []struct {
		volume int64
		want   int64
	}{
		{64 << 20, 2 << 20},
		{256 << 20, 0x290000},
		{512 << 20, 0x520000},
		{1 << 30, 0xa40000},
		{32 << 40, 64 << 20},
	}
	for _, test := range tests {
		if got := ntfsDefaultLogFileSize(test.volume); got != test.want {
			t.Fatalf("default log size for %d-byte volume = %#x, want %#x", test.volume, got, test.want)
		}
	}
}

func TestNTFSInitialLogFileHasValidRestartPages(t *testing.T) {
	size := int64(0x290000)
	log := ntfsInitialLogFile(size)
	if int64(len(log)) != size {
		t.Fatalf("log size = %#x, want %#x", len(log), size)
	}
	for offset := 0; offset < 8192; offset += 4096 {
		page := append([]byte(nil), log[offset:offset+4096]...)
		if string(page[:4]) != "RSTR" {
			t.Fatalf("restart page at %#x has signature %q", offset, page[:4])
		}
		usaOffset := binary.LittleEndian.Uint16(page[4:6])
		usaCount := binary.LittleEndian.Uint16(page[6:8])
		sequence := binary.LittleEndian.Uint16(page[usaOffset : usaOffset+2])
		if usaOffset != 0x1e || usaCount != 9 || sequence == 0 {
			t.Fatalf("restart page at %#x has USA offset=%#x count=%d sequence=%d", offset, usaOffset, usaCount, sequence)
		}
		for sector := uint16(1); sector < usaCount; sector++ {
			trailer := sector*uint16(ntfsSectorSize) - 2
			if got := binary.LittleEndian.Uint16(page[trailer : trailer+2]); got != sequence {
				t.Fatalf("restart page at %#x sector %d trailer = %#x, want %#x", offset, sector, got, sequence)
			}
		}
		restart := page[0x30:]
		if got := binary.LittleEndian.Uint64(restart[0x18:0x20]); got != uint64(size) {
			t.Fatalf("restart page at %#x file size = %#x, want %#x", offset, got, size)
		}
		if got := binary.LittleEndian.Uint32(restart[0x10:0x14]); got != 45 {
			t.Fatalf("restart page at %#x sequence bits = %d, want 45", offset, got)
		}
		if got := string(restart[0x48:0x50]); got != "N\x00T\x00F\x00S\x00" {
			t.Fatalf("restart page at %#x client name = %q", offset, got)
		}
	}
	for index, value := range log[8192:] {
		if value != 0xff {
			t.Fatalf("initial log byte at %#x = %#x, want 0xff", index+8192, value)
		}
	}
}

func TestNTFSDefaultLogInitializationMatchesVolumeVersion(t *testing.T) {
	dir := filesystemapi.New()
	for _, test := range []struct {
		major       byte
		wantRestart bool
	}{
		{major: 1, wantRestart: true},
		{major: 3, wantRestart: false},
	} {
		image, err := buildNTFSImageWithMetadata(dir, 64<<20, nil, 0, "TEST", test.major, 1, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		volume, err := newNTFSVolume(image)
		if err != nil {
			t.Fatal(err)
		}
		log := volume.paths["/$logfile"]
		if log == nil || log.file == nil {
			t.Fatal("generated volume has no $LogFile")
		}
		header := make([]byte, 4)
		if _, err := log.file.ReadAt(header, 0); err != nil {
			t.Fatal(err)
		}
		if got := string(header) == "RSTR"; got != test.wantRestart {
			t.Fatalf("NTFS %d.1 restart header present = %v, want %v", test.major, got, test.wantRestart)
		}
		if !test.wantRestart && !bytes.Equal(header, []byte{0xff, 0xff, 0xff, 0xff}) {
			t.Fatalf("NTFS %d.1 empty log header = %x", test.major, header)
		}
	}
}

func TestNTFSMFTReservesFreeRecords(t *testing.T) {
	b := &ntfsBuild{
		mftRecords: ntfsMFTRecordCapacity(18),
		nodes: []*ntfsNode{
			{id: 0},
			{id: 5},
			{id: 16},
			{id: 17},
		},
	}
	bitmap := b.mftBitmap()
	if b.mftRecords != 32 {
		t.Fatalf("MFT capacity = %d, want 32", b.mftRecords)
	}
	if len(bitmap) != 8 {
		t.Fatalf("MFT bitmap size = %d, want 8", len(bitmap))
	}
	for _, record := range []uint64{0, 5, 16, 17} {
		if bitmap[record/8]&(1<<uint(record%8)) == 0 {
			t.Fatalf("record %d is not allocated", record)
		}
	}
	for _, record := range []uint64{18, 31} {
		if bitmap[record/8]&(1<<uint(record%8)) != 0 {
			t.Fatalf("spare record %d is allocated", record)
		}
	}
}

func TestNTFSMFTReservesGrowthForPopulatedVolumes(t *testing.T) {
	if got := ntfsMFTRecordCapacity(9510); got != 9768 {
		t.Fatalf("MFT capacity = %d, want 9768", got)
	}
}

func TestNTFSExtendUsesSystemRecordEleven(t *testing.T) {
	root := filesystemapi.New()
	b := &ntfsBuild{nextID: 16}
	if err := b.importDirectory(root); err != nil {
		t.Fatal(err)
	}
	var extend *ntfsNode
	for _, node := range b.nodes {
		if node.name == "$Extend" {
			extend = node
			break
		}
	}
	if extend == nil {
		t.Fatal("$Extend system directory is absent")
	}
	if extend.id != 11 || !extend.dir || extend.parent != b.root {
		t.Fatalf("$Extend = %+v, want root directory in MFT record 11", extend)
	}
	if len(extend.names) != 1 || extend.names[0].value != "$Extend" {
		t.Fatalf("$Extend names = %+v", extend.names)
	}

	image, err := buildNTFSImage(root, 64<<20, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	boot := make([]byte, ntfsSectorSize)
	if _, err := image.ReadAt(boot, 0); err != nil {
		t.Fatal(err)
	}
	mftLCN := int64(binary.LittleEndian.Uint64(boot[48:56]))
	record := make([]byte, ntfsRecordSize)
	if _, err := image.ReadAt(record, mftLCN*ntfsCluster+11*ntfsRecordSize); err != nil {
		t.Fatal(err)
	}
	if err := applyNTFSReadFixup(record, ntfsSectorSize, "$Extend"); err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint16(record[22:24])&ntfsFileDir == 0 {
		t.Fatal("$Extend MFT record is not a directory")
	}
	attributes, err := parseNTFSReadAttributes(record, ntfsCluster)
	if err != nil {
		t.Fatal(err)
	}
	for _, attribute := range attributes {
		if attribute.typ == ntfsAttrIndexRoot && attribute.name == "$I30" {
			if len(attribute.value) < 48 {
				t.Fatalf("$Extend index root is %d bytes, want at least 48", len(attribute.value))
			}
			return
		}
	}
	t.Fatal("$Extend MFT record has no $I30 index root")
}

func TestNTFSVolumeNameUsesConfiguredLabel(t *testing.T) {
	b := &ntfsBuild{volumeName: "Windows XP"}
	record, err := b.mftRecord(&ntfsNode{id: 3, name: "$Volume", fullPath: "/$Volume"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(record, utf16Bytes("Windows XP")) {
		t.Fatal("$Volume record does not contain the configured volume name")
	}
	if bytes.Contains(record, utf16Bytes("ReactOS")) {
		t.Fatal("$Volume record contains a product-specific hardcoded volume name")
	}
}

func TestNTFSVolumeNameValidation(t *testing.T) {
	if err := validateNTFSVolumeName("Windows XP"); err != nil {
		t.Fatal(err)
	}
	if err := validateNTFSVolumeName("bad\x00label"); err == nil {
		t.Fatal("volume name containing NUL was accepted")
	}
	if err := validateNTFSVolumeName("123456789012345678901234567890123"); err == nil {
		t.Fatal("volume name longer than 32 UTF-16 code units was accepted")
	}
}
