package mbr

import (
	"encoding/binary"
	"io"
	"testing"

	fsinternal "github.com/tinyrange/trex/filesystem/internal"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func TestMBRSectorIncludesDiskSignature(t *testing.T) {
	builder := &mbrBuilder{diskSignature: 0x54525850}
	sector := builder.mbrSector(true, 0x0c, uint32(mbrPartitionStart), 1024)
	if got := binary.LittleEndian.Uint32(sector[440:444]); got != 0x54525850 {
		t.Fatalf("disk signature = %#x, want %#x", got, uint32(0x54525850))
	}
	if sector[446] != 0x80 || sector[450] != 0x0c {
		t.Fatalf("partition entry was corrupted: %x", sector[446:462])
	}
}

func TestLegacyBIOSGeometry(t *testing.T) {
	tests := []struct {
		sectors uint32
		heads   uint32
	}{
		{sectors: 512 * 1024 * 1024 / 512, heads: 32},
		{sectors: 3 * 1024 * 1024 * 1024 / 512, heads: 128},
		{sectors: 16 * 1024 * 1024 * 1024 / 512, heads: 255},
	}
	for _, tt := range tests {
		heads, sectors := fsinternal.LegacyBIOSGeometry(tt.sectors)
		if heads != tt.heads || sectors != 63 {
			t.Fatalf("legacyBIOSGeometry(%d) = (%d, %d), want (%d, 63)", tt.sectors, heads, sectors, tt.heads)
		}
	}
}

func TestMBRPartitionSupportsLegacyStartLBA(t *testing.T) {
	builder := &mbrBuilder{size: 64 * 1024 * 1024, diskSignature: 0x54523351}
	partition := &starfile.Bytes{Name: "partition.raw", Data: []byte{0xa5, 0x5a}}
	value, err := builder.partitionBuiltin(nil, nil, starlark.Tuple{partition}, []starlark.Tuple{
		{starlark.String("bootable"), starlark.True},
		{starlark.String("type"), starlark.MakeInt(0x06)},
		{starlark.String("start_lba"), starlark.MakeInt(63)},
	})
	if err != nil {
		t.Fatal(err)
	}
	image := value.(starfile.File)
	sector := make([]byte, 512)
	if _, err := image.ReadAt(sector, 0); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	entry := sector[446:462]
	if got := binary.LittleEndian.Uint32(entry[8:12]); got != 63 {
		t.Fatalf("partition start LBA = %d, want 63", got)
	}
	if entry[0] != 0x80 || entry[4] != 0x06 {
		t.Fatalf("partition entry flags = %x, want active FAT16", entry[:5])
	}
	payload := make([]byte, 2)
	if _, err := image.ReadAt(payload, 63*512); err != nil {
		t.Fatal(err)
	}
	if payload[0] != 0xa5 || payload[1] != 0x5a {
		t.Fatalf("partition payload = %x, want a55a", payload)
	}
}

func TestMBRVolumeExposesPartitionMetadataAndFile(t *testing.T) {
	builder := &mbrBuilder{size: 64 * 1024 * 1024, diskSignature: 0x12345678}
	payload := &starfile.Bytes{Name: "partition.raw", Data: []byte{0xa5, 0x5a}}
	value, err := builder.partitionBuiltin(nil, nil, starlark.Tuple{payload}, []starlark.Tuple{
		{starlark.String("bootable"), starlark.True},
		{starlark.String("type"), starlark.MakeInt(0x07)},
		{starlark.String("start_lba"), starlark.MakeInt(63)},
	})
	if err != nil {
		t.Fatal(err)
	}
	volume, err := newMBRVolume(value.(starfile.File))
	if err != nil {
		t.Fatal(err)
	}
	if volume.diskSignature != 0x12345678 || len(volume.partitions) != 1 {
		t.Fatalf("parsed MBR = signature %#x, partitions %d", volume.diskSignature, len(volume.partitions))
	}
	partition := volume.partitions[0]
	if !partition.bootable || partition.kind != 0x07 || partition.startLBA != 63 || partition.sectors != 1 {
		t.Fatalf("parsed partition = %+v", partition)
	}
	file, found, err := volume.Get(starlark.String("/partition1"))
	if err != nil || !found {
		t.Fatalf("partition lookup = %v, %v, %v", file, found, err)
	}
	got := make([]byte, 2)
	if _, err := file.(starfile.File).ReadAt(got, 0); err != nil {
		t.Fatal(err)
	}
	if got[0] != 0xa5 || got[1] != 0x5a {
		t.Fatalf("partition data = %x", got)
	}
}
