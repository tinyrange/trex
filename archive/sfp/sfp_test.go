package sfp

import (
	"encoding/binary"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func TestSFPArchiveEntriesMetadataAndPayload(t *testing.T) {
	data := sfpFixture(t)
	archive, err := Open(&starfile.Bytes{Name: "fixture.sfp", Data: data}, 10, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if archive.packageLabel != "fixture" || len(archive.entries) != 3 {
		t.Fatalf("archive = package %q, entries %d", archive.packageLabel, len(archive.entries))
	}
	value, ok, err := archive.Get(starlark.String("Content/hello.txt"))
	if err != nil || !ok {
		t.Fatalf("Get: value=%v ok=%v err=%v", value, ok, err)
	}
	entry := value.(*Entry)
	if got, err := starfile.ReadAll(entry); err != nil || string(got) != "hello" {
		t.Fatalf("payload = %q, err=%v", got, err)
	}
}

func sfpFixture(t *testing.T) []byte {
	t.Helper()
	const (
		rootOffset      = uint64(64)
		directoryOffset = uint64(144)
		fileOffset      = uint64(224)
		nameTableOffset = uint64(304)
		dataOffset      = uint64(330)
	)
	data := make([]byte, dataOffset+5)
	binary.LittleEndian.PutUint32(data[0:4], sfpMagic)
	binary.LittleEndian.PutUint32(data[4:8], 1)
	binary.LittleEndian.PutUint64(data[16:24], rootOffset)
	binary.LittleEndian.PutUint64(data[24:32], nameTableOffset)
	binary.LittleEndian.PutUint64(data[32:40], dataOffset)
	binary.LittleEndian.PutUint64(data[40:48], uint64(len(data)))
	binary.LittleEndian.PutUint64(data[48:56], nameTableOffset)

	writeSFPFixtureRecord(data[rootOffset:rootOffset+sfpRecordSize], 0, 0, true, directoryOffset, sfpRecordSize, 0)
	writeSFPFixtureRecord(data[directoryOffset:directoryOffset+sfpRecordSize], nameTableOffset+8, rootOffset, true, fileOffset, sfpRecordSize, 0)
	writeSFPFixtureRecord(data[fileOffset:fileOffset+sfpRecordSize], nameTableOffset+16, directoryOffset, false, dataOffset, 5, 5)
	copy(data[nameTableOffset:dataOffset], []byte("fixture\x00Content\x00hello.txt\x00"))
	copy(data[dataOffset:], "hello")
	return data
}

func writeSFPFixtureRecord(data []byte, nameOffset, parentOffset uint64, directory bool, startOffset, dataLength, fileLength uint64) {
	binary.LittleEndian.PutUint32(data[0:4], sfpDirectoryMagic)
	binary.LittleEndian.PutUint64(data[4:12], nameOffset)
	binary.LittleEndian.PutUint64(data[16:24], parentOffset)
	if directory {
		binary.LittleEndian.PutUint32(data[24:28], 1)
	}
	binary.LittleEndian.PutUint64(data[28:36], fileLength)
	binary.LittleEndian.PutUint64(data[68:76], startOffset)
	binary.LittleEndian.PutUint32(data[76:80], uint32(dataLength))
}
