package cab

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"io"
	"testing"

	mszipcompression "github.com/tinyrange/trex/compression/mszip"
	bytecache "github.com/tinyrange/trex/storage/cache"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

type countingCABFile struct {
	data  []byte
	reads int
}

func (f *countingCABFile) ReadAt(p []byte, off int64) (int, error) {
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
func (f *countingCABFile) WriteAt([]byte, int64) (int, error) { return 0, io.ErrClosedPipe }
func (f *countingCABFile) Size() int64                        { return int64(len(f.data)) }
func (f *countingCABFile) String() string                     { return "<counting-cab-file>" }
func (f *countingCABFile) Type() string                       { return "file" }
func (f *countingCABFile) Freeze()                            {}
func (f *countingCABFile) Truth() starlark.Bool               { return starlark.True }
func (f *countingCABFile) Hash() (uint32, error)              { return 0, nil }

func TestCABUncachedEntryDecompressesOnce(t *testing.T) {
	payload := []byte("random access cabinet entry")
	data := appendMSZIPTestDataBlock(nil, mszipTestBlock(t, payload, nil), len(payload))
	source := &countingCABFile{data: data}
	archive := &Archive{
		file:    source,
		folders: []folder{{blocks: 1, compression: 1}},
		cache:   false,
	}
	entry := &Entry{archive: archive, file: fileRecord{name: "/test", size: uint32(len(payload))}}

	for _, offset := range []int64{0, 7, 3, 12} {
		buffer := make([]byte, 4)
		if _, err := entry.ReadAt(buffer, offset); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buffer, payload[offset:offset+4]) {
			t.Fatalf("read at %d = %q, want %q", offset, buffer, payload[offset:offset+4])
		}
	}
	if source.reads != 2 {
		t.Fatalf("CAB source reads = %d, want one header and one payload read", source.reads)
	}
}

func testCABIdentifiers(names []string) []byte {
	data := make([]byte, 44)
	copy(data, "MSCF")
	data[24] = 3
	data[25] = 1
	binary.LittleEndian.PutUint32(data[16:], 44)
	binary.LittleEndian.PutUint16(data[26:], 1)
	binary.LittleEndian.PutUint16(data[28:], 2)
	binary.LittleEndian.PutUint16(data[40:], 1)
	for i, name := range names {
		record := make([]byte, 16)
		binary.LittleEndian.PutUint32(record, uint32(i+1))
		binary.LittleEndian.PutUint32(record[4:], uint32(i))
		data = append(data, record...)
		data = append(data, []byte(name)...)
		data = append(data, 0)
	}
	binary.LittleEndian.PutUint32(data[36:], uint32(len(data)))
	block := make([]byte, 8)
	binary.LittleEndian.PutUint16(block[4:], 3)
	binary.LittleEndian.PutUint16(block[6:], 3)
	data = append(data, block...)
	data = append(data, []byte("ABB")...)
	binary.LittleEndian.PutUint32(data[8:], uint32(len(data)))
	return data
}

func TestCABDuplicateNames(t *testing.T) {
	a, err := Open(&starfile.Bytes{Data: testCABIdentifiers([]string{"notepad.exe", "notepad.exe"})}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.files) != 2 {
		t.Fatalf("file records = %d, want 2", len(a.files))
	}
	for _, lookup := range []func(string) (*Entry, error){a.Lookup, a.LookupExact} {
		f, err := lookup("notepad.exe")
		if err != nil {
			t.Fatal(err)
		}
		b, err := starfile.ReadAll(f)
		if err != nil || string(b) != "A" {
			t.Fatalf("duplicate lookup = %q, %v; want first entry A", b, err)
		}
	}
}

func TestCABExactIdentifierLookup(t *testing.T) {
	data := testCABIdentifiers([]string{"resource.h", "Resource.h"})
	a, err := Open(&starfile.Bytes{Data: data}, false)
	if err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{"resource.h", "Resource.h"} {
		f, err := a.LookupExact(name)
		if err != nil {
			t.Fatal(err)
		}
		b, err := starfile.ReadAll(f)
		if err != nil || string(b) != []string{"A", "BB"}[i] {
			t.Fatal(string(b), err)
		}
	}
	if _, err := a.LookupExact("RESOURCE.H"); err == nil {
		t.Fatal("exact lookup folded case")
	}
	if _, err := a.Lookup("RESOURCE.H"); err != nil {
		t.Fatal("Windows lookup regressed", err)
	}
}

func TestCABFolderCacheSharesDecodingAcrossEntries(t *testing.T) {
	payload := []byte("firstsecond")
	data := appendMSZIPTestDataBlock(nil, mszipTestBlock(t, payload, nil), len(payload))
	source := &countingCABFile{data: data}
	archive := &Archive{
		file:        source,
		folders:     []folder{{blocks: 1, compression: 1}},
		cache:       true,
		cacheStore:  bytecache.New(1024),
		cacheSource: 1,
	}
	for _, item := range []struct {
		start uint32
		want  string
	}{{0, "first"}, {5, "second"}} {
		entry := &Entry{archive: archive, file: fileRecord{size: uint32(len(item.want)), uncompressedStart: item.start}}
		out := make([]byte, len(item.want))
		if _, err := entry.ReadAt(out, 0); err != nil || string(out) != item.want {
			t.Fatalf("entry at %d = %q, %v", item.start, out, err)
		}
	}
	if source.reads != 2 {
		t.Fatalf("source reads = %d, want one folder header and payload", source.reads)
	}
}

func mszipTestBlock(t *testing.T, data, dictionary []byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	compressed.WriteString("CK")
	var (
		writer *flate.Writer
		err    error
	)
	if dictionary == nil {
		writer, err = flate.NewWriter(&compressed, flate.BestCompression)
	} else {
		writer, err = flate.NewWriterDict(&compressed, flate.BestCompression, dictionary)
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func appendMSZIPTestDataBlock(dst []byte, compressed []byte, uncompressedSize int) []byte {
	header := make([]byte, 8)
	binary.LittleEndian.PutUint16(header[4:6], uint16(len(compressed)))
	binary.LittleEndian.PutUint16(header[6:8], uint16(uncompressedSize))
	dst = append(dst, header...)
	return append(dst, compressed...)
}

func TestCABMSZIPCarriesDictionaryAcrossBlocks(t *testing.T) {
	first := bytes.Repeat([]byte("0123456789abcdef"), 1<<11)
	second := append([]byte(nil), first[len(first)-(1<<15):]...)
	second = append(second, []byte("dictionary continuation")...)

	var cabinetData []byte
	cabinetData = appendMSZIPTestDataBlock(cabinetData, mszipTestBlock(t, first, nil), len(first))
	cabinetData = appendMSZIPTestDataBlock(cabinetData, mszipTestBlock(t, second, first[len(first)-(1<<15):]), len(second))
	archive := &Archive{file: &starfile.Bytes{Name: "mszip.cab", Data: cabinetData}}
	got, err := archive.readFolderBlocks(folder{blocks: 2}, true)
	if err != nil {
		t.Fatal(err)
	}
	want := append(append([]byte(nil), first...), second...)
	if !bytes.Equal(got, want) {
		t.Fatalf("decoded data differs: got %d bytes, want %d", len(got), len(want))
	}
}

func TestCompatibleMSZIPInflater(t *testing.T) {
	first := bytes.Repeat([]byte("compatible inflater payload "), 2000)
	compressed := mszipTestBlock(t, first, nil)
	got, err := mszipcompression.Inflate(compressed[2:], nil, len(first))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, first) {
		t.Fatalf("decoded payload differs: got %d bytes, want %d", len(got), len(first))
	}
	second := append([]byte(nil), first[len(first)-(1<<15):]...)
	second = append(second, []byte("dictionary tail")...)
	compressed = mszipTestBlock(t, second, first[len(first)-(1<<15):])
	got, err = mszipcompression.Inflate(compressed[2:], first, len(second))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, second) {
		t.Fatalf("dictionary payload differs: got %d bytes, want %d", len(got), len(second))
	}
}

func TestCompatibleMSZIPInflaterAcceptsNT3StoredTail(t *testing.T) {
	compressed := []byte{0x01, 0x04, 0x00, 't', 'e', 's', 't'}
	got, err := mszipcompression.Inflate(compressed, nil, 4)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "test" {
		t.Fatalf("decoded stored tail = %q", got)
	}
}

func TestCABMSZIPContinuesDeflateStreamAcrossBlocks(t *testing.T) {
	first := bytes.Repeat([]byte("first continuation segment "), 1300)
	second := bytes.Repeat([]byte("second continuation segment "), 500)
	var compressed bytes.Buffer
	writer, err := flate.NewWriter(&compressed, flate.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(first); err != nil {
		t.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatal(err)
	}
	boundary := compressed.Len()
	if _, err := writer.Write(second); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	firstBlock := append([]byte("CK"), compressed.Bytes()[:boundary]...)
	secondBlock := append([]byte("CK"), compressed.Bytes()[boundary:]...)
	data := appendMSZIPTestDataBlock(nil, firstBlock, len(first))
	data = appendMSZIPTestDataBlock(data, secondBlock, len(second))
	archive := &Archive{file: &starfile.Bytes{Name: "continued-mszip.cab", Data: data}}
	got, err := archive.readFolderBlocks(folder{blocks: 2}, true)
	if err != nil {
		t.Fatal(err)
	}
	want := append(append([]byte(nil), first...), second...)
	if !bytes.Equal(got, want) {
		t.Fatalf("decoded continuation differs: got %d bytes, want %d", len(got), len(want))
	}
}

func TestCABMSZIPRejectsIncorrectBlockSize(t *testing.T) {
	payload := []byte("payload")
	data := appendMSZIPTestDataBlock(nil, mszipTestBlock(t, payload, nil), len(payload)+1)
	archive := &Archive{file: &starfile.Bytes{Name: "mszip.cab", Data: data}}
	if _, err := archive.readFolderBlocks(folder{blocks: 1}, true); err == nil {
		t.Fatal("expected decoded-size error")
	}
}

func TestCABSetAcceptsRebasedDuplicateInContinuedFolder(t *testing.T) {
	archives := []*Archive{
		{
			setID: 7, cabinet: 0,
			folders: []folder{{compression: 1}},
			files:   []fileRecord{{name: "/pcimp.dll", size: 64, folder: 0, uncompressedStart: 1234}},
		},
		{
			setID: 7, cabinet: 1,
			folders: []folder{{compression: 1}, {compression: 1}},
			files: []fileRecord{
				{name: "/continued.bin", size: 8, folder: cabFolderContinuedFromPrevious, uncompressedStart: 0},
				{name: "/pcimp.dll", size: 32, folder: 1, uncompressedStart: 0},
			},
		},
	}
	set, err := OpenSetWithCache(archives, false, bytecache.New(bytecache.DefaultBytes), 1)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(set.files), 3; got != want {
		t.Fatalf("file count = %d, want %d", got, want)
	}
	value, err := set.lookup("/pcimp.dll")
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := value.(*SetEntry)
	if !ok {
		t.Fatalf("lookup returned %T, want *SetEntry", value)
	}
	if got, want := entry.file.uncompressedStart, uint32(0); got != want {
		t.Fatalf("latest duplicate offset = %d, want %d", got, want)
	}
	if got, want := entry.file.size, uint32(32); got != want {
		t.Fatalf("latest duplicate size = %d, want %d", got, want)
	}
}
