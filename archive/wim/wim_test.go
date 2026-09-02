package wim

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"unicode/utf16"

	bytecache "github.com/tinyrange/trex/storage/cache"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type countingWIMFile struct {
	data  []byte
	reads int
}

func (f *countingWIMFile) ReadAt(p []byte, off int64) (int, error) {
	f.reads++
	if off >= int64(len(f.data)) {
		return 0, io.EOF
	}
	n := copy(p, f.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (f *countingWIMFile) WriteAt([]byte, int64) (int, error) { return 0, io.ErrClosedPipe }
func (f *countingWIMFile) Size() int64                        { return int64(len(f.data)) }
func (f *countingWIMFile) String() string                     { return "<counting-wim-file>" }
func (f *countingWIMFile) Type() string                       { return "file" }
func (f *countingWIMFile) Freeze()                            {}
func (f *countingWIMFile) Truth() starlark.Bool               { return starlark.True }
func (f *countingWIMFile) Hash() (uint32, error)              { return 0, nil }

func TestWIMResourceFileReadsAndCachesIndividualChunks(t *testing.T) {
	container := make([]byte, 12)
	binary.LittleEndian.PutUint32(container[0:4], 4)
	copy(container[4:8], "abcd")
	copy(container[8:12], "efgh")
	base := &countingWIMFile{data: container}
	archive := &Archive{
		file:       base,
		chunkSize:  4,
		cacheStore: bytecache.New(bytecache.DefaultBytes), cacheSource: 1,
	}
	resource := wimResource{size: 12, flags: wimResourceCompressed, originalSize: 8}
	file := newResourceFile("fixture", archive, resource)

	buffer := make([]byte, 4)
	if n, err := file.ReadAt(buffer, 2); n != 4 || err != nil {
		t.Fatalf("ReadAt crossing chunks = %d, %v", n, err)
	}
	if !bytes.Equal(buffer, []byte("cdef")) {
		t.Fatalf("ReadAt crossing chunks = %q", buffer)
	}
	reads := base.reads
	if n, err := file.ReadAt(buffer[:2], 2); n != 2 || err != nil {
		t.Fatalf("cached ReadAt = %d, %v", n, err)
	}
	if base.reads != reads {
		t.Fatalf("cached chunk caused %d additional source reads", base.reads-reads)
	}
}

func TestParseWIMSecurityAndEntryMetadata(t *testing.T) {
	metadata := make([]byte, 256)
	binary.LittleEndian.PutUint32(metadata[0:4], 20)
	binary.LittleEndian.PutUint32(metadata[4:8], 1)
	binary.LittleEndian.PutUint64(metadata[8:16], 4)
	copy(metadata[16:20], []byte{1, 2, 3, 4})
	descriptors, err := parseWIMSecurity(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if len(descriptors) != 1 || !bytes.Equal(descriptors[0], []byte{1, 2, 3, 4}) {
		t.Fatalf("security descriptors = %x", descriptors)
	}

	offset := 24
	name := utf16Bytes("Long Name.txt")
	shortName := utf16Bytes("LONGNA~1.TXT")
	length := wimMetadataEntryBaseLen + len(name) + len(shortName)
	binary.LittleEndian.PutUint64(metadata[offset:offset+8], uint64(length))
	binary.LittleEndian.PutUint32(metadata[offset+8:offset+12], 0x2421)
	binary.LittleEndian.PutUint32(metadata[offset+12:offset+16], 7)
	binary.LittleEndian.PutUint64(metadata[offset+40:offset+48], 11)
	binary.LittleEndian.PutUint64(metadata[offset+48:offset+56], 12)
	binary.LittleEndian.PutUint64(metadata[offset+56:offset+64], 13)
	binary.LittleEndian.PutUint32(metadata[offset+88:offset+92], 0xa000000c)
	binary.LittleEndian.PutUint16(metadata[offset+96:offset+98], 2)
	binary.LittleEndian.PutUint16(metadata[offset+98:offset+100], uint16(len(shortName)))
	binary.LittleEndian.PutUint16(metadata[offset+100:offset+102], uint16(len(name)))
	copy(metadata[offset+102:], name)
	copy(metadata[offset+102+len(name):], shortName)
	entry, err := parseWIMEntry(metadata, offset, "/image1")
	if err != nil {
		t.Fatal(err)
	}
	if entry.name != "Long Name.txt" || entry.shortName != "LONGNA~1.TXT" || entry.attrs != 0x2421 || entry.securityID != 7 || entry.creationTime != 11 || entry.lastAccessTime != 12 || entry.lastWriteTime != 13 || entry.reparseTag != 0xa000000c || entry.hardLink != 0 || entry.streamCount != 2 {
		t.Fatalf("entry metadata = %+v", entry)
	}

	file := (&Archive{}).newFile(entry)
	value, err := file.Attr("metadata")
	if err != nil {
		t.Fatal(err)
	}
	record := value.(*starfile.Record)
	for name, want := range map[string]string{
		"creation_time":    "11",
		"file_attributes":  "9249",
		"hard_link_id":     "0",
		"last_access_time": "12",
		"last_write_time":  "13",
		"name":             `"Long Name.txt"`,
		"path":             `"/image1/Long Name.txt"`,
		"reparse_tag":      "2684354572",
		"security_id":      "7",
		"short_name":       `"LONGNA~1.TXT"`,
		"stream_count":     "2",
	} {
		got, err := record.Attr(name)
		if err != nil || got.String() != want {
			t.Fatalf("metadata.%s = %v, want %s (err=%v)", name, got, want, err)
		}
	}
	if got, err := record.Attr("sha1"); err != nil || got != starlark.Bytes(make([]byte, 20)) {
		t.Fatalf("metadata.sha1 = %v (err=%v)", got, err)
	}
	found := false
	for _, name := range file.AttrNames() {
		found = found || name == "metadata"
	}
	if !found {
		t.Fatal("WIM file attribute names omit metadata")
	}
}

func utf16Bytes(value string) []byte {
	encoded := utf16.Encode([]rune(value))
	data := make([]byte, len(encoded)*2)
	for index, code := range encoded {
		binary.LittleEndian.PutUint16(data[index*2:], code)
	}
	return data
}
