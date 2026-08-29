package vhdx

import (
	"encoding/binary"
	starfile "github.com/tinyrange/trex/storage/star"
	"hash/crc32"
	"testing"
)

func TestVHDXReadsAllocatedAndZeroPayloadBlocks(t *testing.T) {
	data := buildTestVHDX(t)
	image, err := newVHDXImage(&starfile.Bytes{Name: "test.vhdx", Data: data})
	if err != nil {
		t.Fatal(err)
	}
	if image.Size() != 2*vhdxMiB {
		t.Fatalf("size = %d", image.Size())
	}
	buffer := make([]byte, 8)
	if _, err := image.ReadAt(buffer, 0); err != nil {
		t.Fatal(err)
	}
	if string(buffer) != "VHDXTEST" {
		t.Fatalf("allocated payload = %q", buffer)
	}
	for index := range buffer {
		buffer[index] = 0xff
	}
	if _, err := image.ReadAt(buffer, vhdxMiB); err != nil {
		t.Fatal(err)
	}
	for index, value := range buffer {
		if value != 0 {
			t.Fatalf("zero payload byte %d = %#x", index, value)
		}
	}
}

func TestVHDXRejectsDifferencingDisk(t *testing.T) {
	data := buildTestVHDX(t)
	binary.LittleEndian.PutUint32(data[2*vhdxMiB+vhdxMetadataTableSize+4:], 2)
	if _, err := newVHDXImage(&starfile.Bytes{Name: "parent.vhdx", Data: data}); err == nil {
		t.Fatal("expected differencing disk rejection")
	}
}

func buildTestVHDX(t *testing.T) []byte {
	t.Helper()
	data := make([]byte, 5*vhdxMiB)
	copy(data, "vhdxfile")
	for _, offset := range []int64{64 << 10, 128 << 10} {
		header := data[offset : offset+vhdxHeaderSize]
		copy(header, "head")
		binary.LittleEndian.PutUint64(header[8:16], uint64(offset))
		binary.LittleEndian.PutUint16(header[66:68], 1)
		setVHDXChecksum(header, 4)
	}
	for _, offset := range []int64{192 << 10, 256 << 10} {
		table := data[offset : offset+vhdxRegionTableSize]
		copy(table, "regi")
		binary.LittleEndian.PutUint32(table[8:12], 2)
		putTestVHDXRegion(table[16:48], vhdxBATRegionGUID, 3*vhdxMiB, vhdxMiB)
		putTestVHDXRegion(table[48:80], vhdxMetadataRegionGUID, 2*vhdxMiB, vhdxMiB)
		setVHDXChecksum(table, 4)
	}

	metadata := data[2*vhdxMiB : 3*vhdxMiB]
	copy(metadata, "metadata")
	binary.LittleEndian.PutUint16(metadata[10:12], 5)
	putTestVHDXMetadata(metadata[32:64], vhdxFileParametersGUID, 0x10000, 8)
	putTestVHDXMetadata(metadata[64:96], vhdxVirtualDiskSizeGUID, 0x10008, 8)
	putTestVHDXMetadata(metadata[96:128], vhdxLogicalSectorGUID, 0x10010, 4)
	putTestVHDXMetadata(metadata[128:160], vhdxPhysicalSectorGUID, 0x10014, 4)
	putTestVHDXMetadata(metadata[160:192], vhdxVirtualDiskIDGUID, 0x10018, 16)
	binary.LittleEndian.PutUint32(metadata[0x10000:0x10004], uint32(vhdxMiB))
	binary.LittleEndian.PutUint64(metadata[0x10008:0x10010], uint64(2*vhdxMiB))
	binary.LittleEndian.PutUint32(metadata[0x10010:0x10014], 512)
	binary.LittleEndian.PutUint32(metadata[0x10014:0x10018], 4096)

	bat := data[3*vhdxMiB : 4*vhdxMiB]
	binary.LittleEndian.PutUint64(bat[0:8], uint64(4)<<20|vhdxPayloadFullyPresent)
	copy(data[4*vhdxMiB:], "VHDXTEST")
	return data
}

func putTestVHDXRegion(entry []byte, guid [16]byte, offset, length int64) {
	copy(entry[0:16], guid[:])
	binary.LittleEndian.PutUint64(entry[16:24], uint64(offset))
	binary.LittleEndian.PutUint32(entry[24:28], uint32(length))
	binary.LittleEndian.PutUint32(entry[28:32], 1)
}

func putTestVHDXMetadata(entry []byte, guid [16]byte, offset, length uint32) {
	copy(entry[0:16], guid[:])
	binary.LittleEndian.PutUint32(entry[16:20], offset)
	binary.LittleEndian.PutUint32(entry[20:24], length)
	binary.LittleEndian.PutUint32(entry[24:28], 4)
}

func setVHDXChecksum(data []byte, offset int) {
	binary.LittleEndian.PutUint32(data[offset:offset+4], 0)
	binary.LittleEndian.PutUint32(data[offset:offset+4], crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli)))
}
