package wim

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	bytecache "github.com/tinyrange/trex/storage/cache"
	"go.starlark.net/starlark"
)

func TestSolidLargeBlobSegmentsSurviveChunkAndHotEviction(t *testing.T) {
	const chunk = 1 << 20
	plain := make([]byte, solidBlobSegmentSize+chunk+17)
	for i := range plain {
		plain[i] = byte((i/chunk)*13 + i%251)
	}
	count := (len(plain) + chunk - 1) / chunk
	table := make([]byte, 16+count*4)
	for i := 0; i < count; i++ {
		binary.LittleEndian.PutUint32(table[16+i*4:], uint32(min(chunk, len(plain)-i*chunk)))
	}
	source := &countingWIMFile{data: append(table, plain...)}
	resource := wimResource{flags: wimResourceSolid | wimResourceCompressed, size: int64(len(source.data)), originalSize: int64(len(plain)), chunkSize: chunk, compression: 3}
	archive := &Archive{file: source, cacheStore: bytecache.New(0), blobCache: bytecache.New(4 << 20), blobHotCache: bytecache.New(1), cacheSource: 1}
	f := blobFile(archive, resource, plain, 0, int64(len(plain)), "large")
	// A cross-segment read must retain both segments, without requiring an
	// unbounded whole-file buffer, or decoding them again on subsequent paging.
	at := solidBlobSegmentSize - 9
	got := make([]byte, 33)
	if n, err := f.ReadAt(got, at); n != len(got) || err != nil || !bytes.Equal(got, plain[at:at+int64(len(got))]) {
		t.Fatalf("cross-segment read: %d %v", n, err)
	}
	reads := source.reads
	alias := blobFile(archive, resource, plain, 0, int64(len(plain)), "alias")
	for _, off := range []int64{0, solidBlobSegmentSize - 1, solidBlobSegmentSize, int64(len(plain) - 7)} {
		buf := bytes.Repeat([]byte{0xcc}, 20)
		n, err := alias.ReadAt(buf[1:19], off)
		want := min(18, len(plain)-int(off))
		if n != want || (want == 18 && err != nil) || (want < 18 && err != io.EOF) || !bytes.Equal(buf[1:1+n], plain[off:off+int64(n)]) || buf[0] != 0xcc || buf[19] != 0xcc {
			t.Fatalf("offset %d: %d %v", off, n, err)
		}
	}
	if source.reads != reads || archive.blobCache.Stats().Loads != 2 {
		t.Fatalf("repeated paging revisited source: reads %d -> %d, loads %d", reads, source.reads, archive.blobCache.Stats().Loads)
	}
	if stats := archive.blobCache.Stats(); stats.Bytes > 4<<20 {
		t.Fatalf("cache bound exceeded: %+v", stats)
	}

	// Prefetch must prepare every segment, not just the first byte of a large
	// file. Afterwards no range (including the tail) may consult the source.
	archive.blobCache = bytecache.New(4 << 20)
	archive.images = []image{{index: 1, root: entry{path: "/image1", isDir: true}, byPath: map[string]*entry{wimPathKey("/image1/large"): &f.entry}}}
	archive.addResourceLocation(string(f.entry.hash[:]), *f.location)
	paths := starlark.NewList([]starlark.Value{starlark.String("/image1/large")})
	prepared, err := archive.prefetchBuiltin(nil, nil, starlark.Tuple{paths}, nil)
	if err != nil {
		t.Fatal(err)
	}
	total, err := starlark.AsInt32(prepared)
	if err != nil || int64(total) != f.Size() || archive.blobCache.Stats().Loads != 2 {
		t.Fatalf("large prefetch: %v %v", prepared, err)
	}
	reads = source.reads
	source.data = nil
	for _, off := range []int64{0, solidBlobSegmentSize - 9, int64(len(plain) - len(got))} {
		if _, err := f.ReadAt(got, off); err != nil || !bytes.Equal(got, plain[off:off+int64(len(got))]) {
			t.Fatalf("prepared range %d: %v", off, err)
		}
	}
	if source.reads != reads {
		t.Fatal("prepared large file revisited source")
	}
}
