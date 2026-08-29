package sevenzip

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"io"
	"testing"
	"unicode/utf16"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func sevenZipTestUint(value uint64) []byte {
	for extra := 0; extra < 8; extra++ {
		limitBits := 7 * (extra + 1)
		if limitBits < 64 && value >= uint64(1)<<limitBits {
			continue
		}
		first := byte(0)
		for i := 0; i < extra; i++ {
			first |= 0x80 >> i
		}
		first |= byte(value >> (8 * extra))
		out := []byte{first}
		for i := 0; i < extra; i++ {
			out = append(out, byte(value>>(8*i)))
		}
		return out
	}
	out := []byte{0xff}
	for i := 0; i < 8; i++ {
		out = append(out, byte(value>>(8*i)))
	}
	return out
}

func sevenZipTestCopyArchive(name string, payload []byte) []byte {
	var names []byte
	names = append(names, 0)
	for _, unit := range utf16.Encode([]rune(name)) {
		names = binary.LittleEndian.AppendUint16(names, unit)
	}
	names = binary.LittleEndian.AppendUint16(names, 0)
	checksum := crc32.ChecksumIEEE(payload)
	header := []byte{sevenZipHeader, sevenZipMainStreams, sevenZipPackInfo, 0, 1, sevenZipSize}
	header = append(header, sevenZipTestUint(uint64(len(payload)))...)
	header = append(header, sevenZipCRC, 1)
	header = binary.LittleEndian.AppendUint32(header, checksum)
	header = append(header, sevenZipEnd, sevenZipUnpackInfo, sevenZipFolderID, 1, 0, 1, 1, 0, sevenZipCodersUnpackSize)
	header = append(header, sevenZipTestUint(uint64(len(payload)))...)
	header = append(header, sevenZipCRC, 1)
	header = binary.LittleEndian.AppendUint32(header, checksum)
	header = append(header, sevenZipEnd, sevenZipEnd, sevenZipFilesInfo, 1, sevenZipName)
	header = append(header, sevenZipTestUint(uint64(len(names)))...)
	header = append(header, names...)
	header = append(header, sevenZipEnd, sevenZipEnd)

	start := make([]byte, 32)
	copy(start, sevenZipSignature)
	start[6], start[7] = 0, 4
	binary.LittleEndian.PutUint64(start[12:20], uint64(len(payload)))
	binary.LittleEndian.PutUint64(start[20:28], uint64(len(header)))
	binary.LittleEndian.PutUint32(start[28:32], crc32.ChecksumIEEE(header))
	binary.LittleEndian.PutUint32(start[8:12], crc32.ChecksumIEEE(start[12:32]))
	return append(append(start, payload...), header...)
}

func TestLZMAReaderDecodesRawStream(t *testing.T) {
	compressed, err := hex.DecodeString("003a1c88cf5c7005de33282e82cfeafc4d13b6fae680d354ecc2f3f9df0841b053fc97ffffeb418000")
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("trex native LZMA decoder. trex native LZMA decoder.\n")
	reader, err := newLZMAReader(bytes.NewReader(compressed), []byte{0x5d, 0x00, 0x00, 0x10, 0x00}, uint64(len(want)), 2<<20)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("decoded LZMA data = %q, want %q", got, want)
	}
}

func TestSevenZipCopyArchiveMapping(t *testing.T) {
	payload := []byte("hello from a native 7z file\n")
	fixture := sevenZipTestCopyArchive("folder/hello.txt", payload)
	archive, err := Open(&starfile.Bytes{Name: "fixture.7z", Data: fixture}, 16, 1<<20, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	value, found, err := archive.Get(starlark.String("/folder/hello.txt"))
	if err != nil || !found {
		t.Fatalf("lookup = %v, %v, %v", value, found, err)
	}
	got, err := starfile.ReadAll(value.(starfile.File))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("entry = %q, want %q", got, payload)
	}
}

func TestSevenZipRejectsCorruptEntry(t *testing.T) {
	fixture := sevenZipTestCopyArchive("hello.txt", []byte("payload"))
	fixture[32] ^= 0x80
	archive, err := Open(&starfile.Bytes{Name: "corrupt.7z", Data: fixture}, 16, 1<<20, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	value, _, _ := archive.Get(starlark.String("hello.txt"))
	if _, err := starfile.ReadAll(value.(starfile.File)); err == nil {
		t.Fatal("corrupt entry unexpectedly passed CRC validation")
	}
}
