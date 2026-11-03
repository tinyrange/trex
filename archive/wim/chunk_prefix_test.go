package wim

import (
	"bytes"
	"testing"

	bytecache "github.com/tinyrange/trex/storage/cache"
)

func TestSolidPrefixReusesLongerAndPromotesExtendingReads(t *testing.T) {
	const size = 16 << 20
	plain := make([]byte, size)
	for i := range plain {
		plain[i] = byte(i % 251)
	}
	source := &countingWIMFile{data: append(make([]byte, 20), plain...)}
	resource := wimResource{offset: 0, size: int64(len(source.data)), originalSize: size, flags: wimResourceSolid | wimResourceCompressed, compression: 3, chunkSize: size}
	chunk := wimChunk{index: 0, inOffset: 20, inSize: size, outputSize: size}
	a := &Archive{file: source, cacheSource: 1, cacheStore: bytecache.New(32 << 20), blobCache: bytecache.New(1 << 20)}
	first, err := a.cachedResourceChunkRange(resource, chunk, 1<<20)
	if err != nil || len(first) != 4<<20 || cap(first) != len(first) || !bytes.Equal(first, plain[:4<<20]) {
		t.Fatalf("prefix content/backing: len=%d cap=%d err=%v", len(first), cap(first), err)
	}
	reads := source.reads
	larger, err := a.cachedResourceChunkRange(resource, chunk, 2<<20)
	if err != nil || &first[0] != &larger[0] || source.reads != reads {
		t.Fatal("resident longer prefix was decoded again")
	}
	full, err := a.cachedResourceChunkRange(resource, chunk, 6<<20)
	if err != nil || !bytes.Equal(full, plain) || source.reads != reads+1 {
		t.Fatalf("extending read did not promote: %v", err)
	}
	reads = source.reads
	if _, err := a.cachedResourceChunkRange(resource, chunk, 1<<20); err != nil || source.reads != reads {
		t.Fatal("full chunk was not reused")
	}
	if a.cacheStore.Stats().Bytes > 32<<20 {
		t.Fatal("prefix backing exceeded cache budget")
	}
}
