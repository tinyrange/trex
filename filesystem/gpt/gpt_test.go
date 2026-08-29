package gpt

import (
	"encoding/binary"
	"hash/crc32"
	"testing"

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
