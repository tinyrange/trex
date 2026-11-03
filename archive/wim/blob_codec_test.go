package wim

import (
	"bytes"
	bytecache "github.com/tinyrange/trex/storage/cache"
	"testing"
)

func TestCompressedBlobSurvivesHotEvictionWithoutSourceReads(t *testing.T) {
	a, source, resource, plain := solidBlobFixture()
	a.blobCache = bytecache.New(2048)
	a.blobHotCache = bytecache.New(64) // Neither file fits in the decoded hot tier.
	first := blobFile(a, resource, plain, 0, 32000, "first")
	second := blobFile(a, resource, plain, 32000, 32000, "second")
	for _, file := range []*File{first, second} {
		if _, err := file.ReadAt(make([]byte, 1), 0); err != nil {
			t.Fatal(err)
		}
	}
	if stats := a.blobCache.Stats(); stats.Loads != 2 || stats.Bytes >= 64000 || stats.Bytes > 2048 {
		t.Fatalf("compressed retention: %+v", stats)
	}
	reads := source.reads
	source.data = nil // No cold/source path may be needed to read retained blobs.
	for _, file := range []*File{second, first, second, first} {
		got := make([]byte, 32)
		if _, err := file.ReadAt(got, 31111); err != nil {
			t.Fatal(err)
		}
		start := file.location.blobOffset + 31111
		if !bytes.Equal(got, plain[start:start+32]) {
			t.Fatal("compressed paging bytes differ")
		}
	}
	if source.reads != reads {
		t.Fatal("hot eviction repeated source reads")
	}
	if a.blobHotCache.Stats().Bytes != 0 {
		t.Fatal("oversized hot entries retained")
	}
}

func TestCompressedBlobBackingMatchesChargedBytes(t *testing.T) {
	plain := bytes.Repeat([]byte("small retained working set"), 100000)
	encoded, err := encodeCachedBlob(plain)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) >= len(plain)/10 || cap(encoded) != len(encoded) {
		t.Fatalf("hidden oversized cache backing: len=%d cap=%d", len(encoded), cap(encoded))
	}
	got, err := decodeCachedBlob(encoded, int64(len(plain)))
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("compressed round trip: %v", err)
	}
}

func TestCachedBlobCodecsRejectBoundsAndPreserveIncompressibleBytes(t *testing.T) {
	data := make([]byte, 513)
	state := uint64(7)
	for i := range data {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		data[i] = byte(state)
	}
	encoded, err := encodeCachedBlob(data)
	if err != nil {
		t.Fatal(err)
	}
	if encoded[0] != 0 {
		t.Fatal("incompressible data did not retain raw encoding")
	}
	decoded, err := decodeCachedBlob(encoded, int64(len(data)))
	if err != nil || !bytes.Equal(decoded, data) {
		t.Fatalf("raw round trip: %v", err)
	}
	for _, item := range []struct {
		data []byte
		size int64
	}{{nil, 1}, {[]byte{2}, 1}, {encoded, 512}, {[]byte{1, 0}, 8}, {encoded, -1}, {encoded, 33 << 20}} {
		if _, err := decodeCachedBlob(item.data, item.size); err == nil {
			t.Fatal("invalid private cache bounds accepted")
		}
	}
}
