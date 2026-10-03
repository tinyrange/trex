package gpt

import (
	"encoding/binary"
	"go.starlark.net/starlark"
	"hash/crc32"
	"testing"

	blockpkg "github.com/tinyrange/trex/block"
	filesystemapi "github.com/tinyrange/trex/filesystem"
	fsinternal "github.com/tinyrange/trex/filesystem/internal"
	starfile "github.com/tinyrange/trex/storage/star"
)

func TestGPTBuildsPrimaryAndBackupPartitionTables(t *testing.T) {
	diskGUID, _ := fsinternal.ParseGUID("{01234567-89AB-CDEF-8123-456789ABCDEF}")
	typeGUID, _ := fsinternal.ParseGUID("{C12A7328-F81F-11D2-BA4B-00A0C93EC93B}")
	partitionGUID, _ := fsinternal.ParseGUID("{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}")
	filesystem := filesystemapi.NewGeneratedImage("esp", 64<<20, nil)
	builder := &gptBuilder{size: 128 << 20, diskGUID: diskGUID}
	builder, err := builder.withPartition(filesystem, typeGUID, partitionGUID, "EFI System", 2048, 1)
	if err != nil {
		t.Fatal(err)
	}

	primary := make([]byte, 512)
	if _, err := builder.ReadAt(primary, 512); err != nil {
		t.Fatal(err)
	}
	if string(primary[:8]) != "EFI PART" || binary.LittleEndian.Uint64(primary[24:32]) != 1 {
		t.Fatalf("invalid primary GPT header: %x", primary[:32])
	}
	wantHeaderCRC := binary.LittleEndian.Uint32(primary[16:20])
	binary.LittleEndian.PutUint32(primary[16:20], 0)
	if got := crc32.ChecksumIEEE(primary[:92]); got != wantHeaderCRC {
		t.Fatalf("primary header CRC = %#x, want %#x", got, wantHeaderCRC)
	}

	entries := make([]byte, gptEntryArrayBytes)
	if _, err := builder.ReadAt(entries, 2*512); err != nil {
		t.Fatal(err)
	}
	if string(entries[:16]) != string(typeGUID[:]) || string(entries[16:32]) != string(partitionGUID[:]) {
		t.Fatal("partition GUIDs were not encoded in GPT byte order")
	}
	if got := binary.LittleEndian.Uint64(entries[32:40]); got != 2048 {
		t.Fatalf("partition first LBA = %d", got)
	}
	if got := binary.LittleEndian.Uint64(entries[48:56]); got != 1 {
		t.Fatalf("partition attributes = %#x", got)
	}

	lastLBA := builder.Size()/512 - 1
	backup := make([]byte, 512)
	if _, err := builder.ReadAt(backup, lastLBA*512); err != nil {
		t.Fatal(err)
	}
	if string(backup[:8]) != "EFI PART" || binary.LittleEndian.Uint64(backup[24:32]) != uint64(lastLBA) || binary.LittleEndian.Uint64(backup[32:40]) != 1 {
		t.Fatalf("invalid backup GPT header: %x", backup[:40])
	}
	if got := binary.LittleEndian.Uint32(backup[88:92]); got != crc32.ChecksumIEEE(entries) {
		t.Fatalf("backup entry CRC = %#x", got)
	}

	mbr := make([]byte, 512)
	if _, err := builder.ReadAt(mbr, 0); err != nil {
		t.Fatal(err)
	}
	if mbr[446+4] != 0xee || binary.LittleEndian.Uint32(mbr[446+8:446+12]) != 1 || string(mbr[510:512]) != "\x55\xaa" {
		t.Fatalf("invalid protective MBR: %x", mbr[446:512])
	}
}

func TestGPTRejectsOverlappingPartitions(t *testing.T) {
	diskGUID, _ := fsinternal.ParseGUID("{01234567-89AB-CDEF-8123-456789ABCDEF}")
	typeGUID, _ := fsinternal.ParseGUID(gptBasicDataType)
	firstGUID, _ := fsinternal.ParseGUID("{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}")
	secondGUID, _ := fsinternal.ParseGUID("{11111111-2222-3333-4444-555555555555}")
	builder := &gptBuilder{size: 128 << 20, diskGUID: diskGUID}
	builder, err := builder.withPartition(filesystemapi.NewGeneratedImage("first", 32<<20, nil), typeGUID, firstGUID, "first", 2048, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := builder.withPartition(filesystemapi.NewGeneratedImage("second", 32<<20, nil), typeGUID, secondGUID, "second", 4096, 0); err == nil {
		t.Fatal("overlapping GPT partition accepted")
	}
}

func TestGPTGeneratedImageCanBeMounted(t *testing.T) {
	diskGUID, _ := fsinternal.ParseGUID("{01234567-89AB-CDEF-8123-456789ABCDEF}")
	builder := &gptBuilder{size: 16 << 20, diskGUID: diskGUID}
	partition := &starfile.Bytes{Name: "partition", Data: make([]byte, 2<<20)}
	typeGUID, _ := fsinternal.ParseGUID(gptBasicDataType)
	partitionGUID, _ := fsinternal.ParseGUID("{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}")
	builder, err := builder.withPartition(partition, typeGUID, partitionGUID, "Data", 2048, 7)
	if err != nil {
		t.Fatal(err)
	}
	volume, err := newGPTVolume(builder)
	if err != nil {
		t.Fatal(err)
	}
	if len(volume.partitions) != 1 {
		t.Fatalf("partitions = %d", len(volume.partitions))
	}
	got := volume.partitions[0]
	if got.name != "Data" || got.startLBA != 2048 || got.attributes != 7 || got.file.Size() != partition.Size() {
		t.Fatalf("partition = %+v", got)
	}
}

func TestGPTPropagatesPartitionSparseExtents(t *testing.T) {
	diskGUID, _ := fsinternal.ParseGUID("{01234567-89AB-CDEF-8123-456789ABCDEF}")
	typeGUID, _ := fsinternal.ParseGUID(gptBasicDataType)
	partitionGUID, _ := fsinternal.ParseGUID("{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}")
	partition := filesystemapi.NewGeneratedImage("sparse", 2<<20, []filesystemapi.ExtentSpec{
		{Start: 4096, Size: 4, Data: []byte("data")},
	})
	builder := &gptBuilder{size: 16 << 20, diskGUID: diskGUID}
	builder, err := builder.withPartition(partition, typeGUID, partitionGUID, "Data", 2048, 0)
	if err != nil {
		t.Fatal(err)
	}

	device, err := blockpkg.NewFileDevice(builder, blockpkg.FileDeviceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !device.Capabilities().Extents {
		t.Fatal("GPT block device did not advertise sparse extents")
	}
	extents, err := device.Extents(0, builder.Size())
	if err != nil {
		t.Fatal(err)
	}
	position := int64(0)
	allocated := int64(0)
	partitionData := int64(2048*512 + 4096)
	foundPartitionData := false
	for _, extent := range extents {
		if extent.Offset != position || extent.Length <= 0 {
			t.Fatalf("non-canonical extent at %d: %+v", position, extent)
		}
		if extent.Allocated {
			allocated += extent.Length
			if extent.Offset <= partitionData && partitionData+4 <= extent.Offset+extent.Length {
				foundPartitionData = true
			}
		}
		position += extent.Length
	}
	if position != builder.Size() {
		t.Fatalf("extent map covers %d bytes, want %d", position, builder.Size())
	}
	if allocated != 34308 {
		t.Fatalf("allocated bytes = %d, want 34308", allocated)
	}
	if !foundPartitionData {
		t.Fatal("partition allocation was not propagated into GPT extent map")
	}
}

func TestGPTSparseEntryNumbersAgreeAcrossAPIs(t *testing.T) {
	diskGUID, _ := fsinternal.ParseGUID("{01234567-89AB-CDEF-8123-456789ABCDEF}")
	typeGUID, _ := fsinternal.ParseGUID(gptBasicDataType)
	partitionGUID, _ := fsinternal.ParseGUID("{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}")
	builder := &gptBuilder{size: 2 << 20, diskGUID: diskGUID}
	builder, err := builder.withPartition(&starfile.Bytes{Data: make([]byte, 512)}, typeGUID, partitionGUID, "Data", 2048, 0)
	if err != nil {
		t.Fatal(err)
	}
	data, err := starfile.ReadAll(builder)
	if err != nil {
		t.Fatal(err)
	}
	table := data[1024 : 1024+gptEntryArrayBytes]
	copy(table[256:384], table[:128])
	clear(table[:128])
	header := data[512:1024]
	binary.LittleEndian.PutUint32(header[88:], crc32.ChecksumIEEE(table))
	clear(header[16:20])
	binary.LittleEndian.PutUint32(header[16:], crc32.ChecksumIEEE(header[:92]))
	source := &starfile.Bytes{Data: data}
	partitions, err := Read(source)
	if err != nil || len(partitions) != 1 || partitions[0].Index != 3 {
		t.Fatalf("native partitions=%+v err=%v", partitions, err)
	}
	volume, err := newGPTVolume(source)
	if err != nil {
		t.Fatal(err)
	}
	values, err := volume.Attr("partitions")
	if err != nil {
		t.Fatal(err)
	}
	index, _, err := values.(*starlark.List).Index(0).(*starlark.Dict).Get(starlark.String("index"))
	if err != nil || index.String() != "3" {
		t.Fatalf("Starlark index=%v err=%v", index, err)
	}
	if _, found, err := volume.Get(starlark.String("/partition3")); err != nil || !found {
		t.Fatalf("partition3: found=%v err=%v", found, err)
	}
	if _, found, _ := volume.Get(starlark.String("/partition1")); found {
		t.Fatal("unused slot exposed")
	}
}
