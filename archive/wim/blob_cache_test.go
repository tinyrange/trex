package wim

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"io"
	"sync"
	"testing"

	bytecache "github.com/tinyrange/trex/storage/cache"
)

func solidBlobFixture() (*Archive, *countingWIMFile, wimResource, []byte) {
	const chunk = 32768
	plain := make([]byte, chunk*2)
	for i := range plain {
		plain[i] = byte(i % 251)
	}
	table := make([]byte, 24)
	binary.LittleEndian.PutUint32(table[16:], chunk)
	binary.LittleEndian.PutUint32(table[20:], chunk)
	r := &countingWIMFile{data: append(table, plain...)}
	resource := wimResource{flags: wimResourceSolid | wimResourceCompressed, size: int64(len(r.data)), originalSize: int64(len(plain)), chunkSize: chunk, compression: 3}
	a := &Archive{file: r, cacheStore: bytecache.New(0), blobCache: bytecache.New(1024), cacheSource: 1}
	return a, r, resource, plain
}

func blobFile(a *Archive, resource wimResource, plain []byte, offset, size int64, name string) *File {
	hash := sha1.Sum(plain[offset : offset+size])
	location := wimResourceLocation{archive: a, resource: resource, blobOffset: offset, blobSize: size}
	return &File{archive: a, entry: entry{path: name, hash: hash, size: size}, reader: readerForLocation(name, location), location: &location}
}

func TestSolidBlobCachePreservesRangesAndSharesAliases(t *testing.T) {
	a, r, resource, plain := solidBlobFixture()
	const offset = 32768 - 17
	first := blobFile(a, resource, plain, offset, 96, "first")
	want := plain[offset : offset+96]
	var group sync.WaitGroup
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			data := make([]byte, 5)
			if n, err := first.ReadAt(data, 20); n != 5 || err != nil || !bytes.Equal(data, want[20:25]) {
				t.Errorf("partial read: %d %v %x", n, err, data)
			}
		}()
	}
	group.Wait()
	reads := r.reads
	alias := blobFile(a, resource, plain, offset, 96, "different-name-same-blob")
	for _, f := range []*File{first, alias} {
		data := bytes.Repeat([]byte{0xcc}, 18)
		n, err := f.ReadAt(data[1:17], 90)
		if n != 6 || err != io.EOF || !bytes.Equal(data[1:7], want[90:]) || data[0] != 0xcc || data[17] != 0xcc {
			t.Fatal("EOF/range isolation changed")
		}
		if _, err := f.ReadAt(data, -1); err == nil {
			t.Fatal("negative offset accepted")
		}
	}
	if r.reads != reads || a.blobCache.Stats().Loads != 1 {
		t.Fatal("paging or alias redecoded solid chunks")
	}
	other := blobFile(a, resource, plain, 1000, 64, "other")
	data := make([]byte, 64)
	if _, err := other.ReadAt(data, 0); err != nil || !bytes.Equal(data, plain[1000:1064]) {
		t.Fatal("distinct content identities aliased")
	}
}

func TestSolidBlobCacheDoesNotPublishFailedReads(t *testing.T) {
	a, r, resource, plain := solidBlobFixture()
	f := blobFile(a, resource, plain, 32760, 96, "cross-chunk")
	complete := r.data
	r.data = r.data[:len(r.data)-10]
	if _, err := f.ReadAt(make([]byte, 16), 0); err == nil {
		t.Fatal("truncated source accepted")
	}
	if a.blobCache.Stats().Bytes != 0 {
		t.Fatal("failed prefix cached")
	}
	r.data = complete
	data := make([]byte, 96)
	if _, err := f.ReadAt(data, 0); err != nil || !bytes.Equal(data, plain[32760:32856]) {
		t.Fatalf("failed read poisoned retry: %v", err)
	}
}
