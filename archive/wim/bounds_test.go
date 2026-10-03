package wim

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"
	"strings"
	"testing"

	bytecache "github.com/tinyrange/trex/storage/cache"
)

func malformedLookupWIM(compressed bool) []byte {
	data := minimalWIMHeader(0, 0)
	size, original := uint64(50), uint64(50)
	if compressed {
		binary.LittleEndian.PutUint32(data[16:], wimFlagLZX)
		binary.LittleEndian.PutUint32(data[20:], 4)
		size, original = 20|uint64(wimResourceCompressed)<<56, 12
		data = append(data, make([]byte, 20)...)
		binary.LittleEndian.PutUint32(data[208:], 4)
		binary.LittleEndian.PutUint32(data[212:], 0) // descending offsets
		copy(data[216:], "abcd00000000")
	}
	binary.LittleEndian.PutUint64(data[48:], size)
	binary.LittleEndian.PutUint64(data[56:], 208)
	binary.LittleEndian.PutUint64(data[64:], original)
	return data
}

func TestOpenRejectsMalformedLookupResource(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		_, err := OpenWithCache(&countingWIMFile{data: malformedLookupWIM(compressed)}, bytecache.New(0), 1)
		if err == nil {
			t.Fatalf("compressed=%v: malformed lookup accepted", compressed)
		}
	}
}

type shortWIMReader struct{ *countingWIMFile }

func (f shortWIMReader) ReadAt(p []byte, offset int64) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n, _ := f.countingWIMFile.ReadAt(p[:len(p)-1], offset)
	return n, io.EOF
}

func TestWIMRejectsShortResourceAndChunkReads(t *testing.T) {
	base := shortWIMReader{&countingWIMFile{data: []byte("abcd")}}
	archive := &Archive{file: base, chunkSize: 4}
	resource := wimResource{size: 4, originalSize: 4}
	if _, err := archive.readResource(resource); err != io.ErrUnexpectedEOF {
		t.Fatalf("short resource: %v", err)
	}
	resource.flags = wimResourceCompressed
	if _, err := archive.readChunk(resource, wimChunk{inSize: 4, outputSize: 4}); err != io.ErrUnexpectedEOF {
		t.Fatalf("short chunk: %v", err)
	}
}

func TestWIMResourceGeometryBounds(t *testing.T) {
	for _, resource := range []wimResource{
		{size: 4, originalSize: 4, offset: -1},
		{size: 4, originalSize: 4, offset: math.MaxInt64},
		{size: math.MaxInt64, originalSize: 4},
		{size: 4, originalSize: -1},
		{size: 4, originalSize: 4, flags: wimResourceSolid, chunkSize: 4},
		{size: 4, originalSize: math.MaxInt64, flags: wimResourceCompressed},
		{size: 4, originalSize: 100, flags: wimResourceCompressed},
	} {
		archive := &Archive{file: &countingWIMFile{data: make([]byte, 16)}, chunkSize: 4}
		if _, err := archive.resourceChunks(resource); err == nil {
			t.Fatalf("accepted %+v", resource)
		}
	}
}

func TestRawResourceFileDoesNotExposeAdjacentResource(t *testing.T) {
	source := &countingWIMFile{data: []byte("abcdSECRET")}
	archive := &Archive{file: source}
	file := newResourceFile("malformed", archive, wimResource{size: 4, originalSize: 10})
	buffer := make([]byte, 10)
	if n, err := file.ReadAt(buffer, 0); n != 0 || err == nil {
		t.Fatalf("malformed raw resource returned %d bytes %q, error %v", n, buffer[:n], err)
	}
	if source.reads != 0 {
		t.Fatal("invalid resource reached backing reader")
	}
}

func TestResourceFileRejectsInvalidPhysicalAndLogicalRanges(t *testing.T) {
	for _, test := range []struct {
		name     string
		resource wimResource
		offset   int64
		size     int64
	}{
		{"negative resource offset", wimResource{offset: -1, size: 4, originalSize: 4}, 0, 4},
		{"resource offset overflow", wimResource{offset: math.MaxInt64, size: 4, originalSize: 4}, 0, 4},
		{"physical range", wimResource{offset: 8, size: 4, originalSize: 4}, 0, 4},
		{"negative file offset", wimResource{size: 4, originalSize: 4}, -1, 4},
		{"negative file size", wimResource{size: 4, originalSize: 4}, 0, -1},
		{"file size overflow", wimResource{size: 4, originalSize: 4}, 1, math.MaxInt64},
		{"file offset overflow", wimResource{size: 4, originalSize: 4}, math.MaxInt64, 1},
		{"logical range", wimResource{size: 4, originalSize: 4}, 2, 3},
		{"compressed logical range", wimResource{size: 4, originalSize: 4, flags: wimResourceCompressed}, 2, 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := &countingWIMFile{data: []byte("abcdSECRET")}
			file := newResourceFileRange(test.name, &Archive{file: source, chunkSize: 4}, test.resource, test.offset, test.size)
			if n, err := file.ReadAt(make([]byte, 4), 0); n != 0 || err == nil {
				t.Fatalf("invalid range returned %d bytes, error %v", n, err)
			}
			if source.reads != 0 {
				t.Fatal("invalid range reached backing reader")
			}
		})
	}
}

func TestRawResourceFileClipsLogicalSubrange(t *testing.T) {
	source := &countingWIMFile{data: []byte("preabcdefpost")}
	file := newResourceFileRange("subrange", &Archive{file: source}, wimResource{offset: 3, size: 6, originalSize: 6}, 1, 3)
	buffer := make([]byte, 6)
	if n, err := file.ReadAt(buffer, 1); n != 2 || err != io.EOF || string(buffer[:n]) != "cd" {
		t.Fatalf("clipped read = %d %q, %v", n, buffer[:n], err)
	}
	if source.reads != 1 || file.chunksReady {
		t.Fatal("raw subrange did more than a single direct read")
	}
}

type largeRawWIMReader struct {
	size       int64
	readOffset int64
	readBytes  int
}

func (f *largeRawWIMReader) Size() int64 { return f.size }
func (f *largeRawWIMReader) ReadAt(p []byte, offset int64) (int, error) {
	f.readOffset, f.readBytes = offset, len(p)
	for index := range p {
		p[index] = 'x'
	}
	return len(p), nil
}

func TestLargeRawResourceFileRemainsLazy(t *testing.T) {
	const size = int64(8 << 30)
	source := &largeRawWIMReader{size: size + 16}
	file := newResourceFile("large", &Archive{file: source}, wimResource{offset: 16, size: size, originalSize: size})
	buffer := make([]byte, 4)
	if n, err := file.ReadAt(buffer, size-4); n != 4 || err != nil || string(buffer) != "xxxx" {
		t.Fatalf("large raw read = %d %q, %v", n, buffer, err)
	}
	if source.readOffset != size+12 || source.readBytes != 4 || file.chunksReady {
		t.Fatal("large raw resource was not read directly at the requested range")
	}
}

func storedChunks(count int) ([]byte, wimResource) {
	data := make([]byte, (count-1)*4+count*4)
	for index := 0; index < count-1; index++ {
		binary.LittleEndian.PutUint32(data[index*4:], uint32((index+1)*4))
	}
	copy(data[(count-1)*4:], bytes.Repeat([]byte("abcd"), count))
	return data, wimResource{size: int64(len(data)), originalSize: int64(count * 4), flags: wimResourceCompressed}
}

func TestReadResourceParsesChunkTableOnce(t *testing.T) {
	for _, count := range []int{2, 16, 128} {
		data, resource := storedChunks(count)
		source := &countingWIMFile{data: data}
		archive := &Archive{file: source, chunkSize: 4}
		got, err := archive.readResource(resource)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != strings.Repeat("abcd", count) {
			t.Fatal("decoded bytes differ")
		}
		if source.reads != count+1 {
			t.Fatalf("%d chunks: %d reads, want %d", count, source.reads, count+1)
		}
	}
}

func BenchmarkReadResourceChunkTable(b *testing.B) {
	data, resource := storedChunks(1024)
	archive := &Archive{file: &countingWIMFile{data: data}, chunkSize: 4}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := archive.readResource(resource); err != nil {
			b.Fatal(err)
		}
	}
}

func FuzzWIMResourceBounds(f *testing.F) {
	f.Add(malformedLookupWIM(false))
	f.Add(malformedLookupWIM(true))
	f.Add(minimalWIMHeader(0, 0))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			t.Skip()
		}
		// Bound decompressor output during fuzzing; resource geometry remains
		// unmodified so overflowing offsets and lengths are still exercised.
		if len(data) >= 24 && binary.LittleEndian.Uint32(data[20:24]) > 64<<10 {
			t.Skip()
		}
		_, _ = OpenWithCache(&countingWIMFile{data: data}, bytecache.New(0), 1)
	})
}
