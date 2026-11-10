package wim

import (
	"bytes"
	"crypto/sha1"
	"github.com/tinyrange/trex/storage"
	bytecache "github.com/tinyrange/trex/storage/cache"
	"io"
	"testing"
)

func TestCompactResourceIndexPreservesReaderAndExtent(t *testing.T) {
	a, _, resource, plain := solidBlobFixture()
	imported := &Archive{}
	var shared *wimResourceBacking
	for _, offset := range []int64{100, 40000} {
		expected := plain[offset : offset+1000]
		digest := sha1.Sum(expected)
		a.addResourceLocation(string(digest[:]), wimResourceLocation{
			archive: a, resource: resource, blobOffset: offset, blobSize: 1000,
			lookupPart: 3, refCount: 7,
		})
		compact := a.expandIndexed(a.byHash[digest])
		if shared != nil && compact.wimResourceBacking != shared {
			t.Fatal("solid members did not share their physical descriptor")
		}
		shared = compact.wimResourceBacking
		imported.addCompactLocation(digest, compact)
	}
	// References retain the reading context, not the imported private index.
	a.byHash, a.lastResource, a.resourceBackings = nil, nil, nil
	for _, offset := range []int64{100, 40000} {
		expected := plain[offset : offset+1000]
		digest := sha1.Sum(expected)
		location, ok := imported.lookupResource(digest)
		if !ok || location.blobOffset != offset || location.lookupPart != 3 || location.refCount != 7 {
			t.Fatalf("lost resource extent/provenance: %+v", location)
		}
		f := imported.newFile(entry{path: "/member", hash: digest, size: 1000})
		got, err := io.ReadAll(io.NewSectionReader(f, 0, f.Size()))
		if err != nil || !bytes.Equal(got, expected) {
			t.Fatalf("imported member: %v", err)
		}
	}
	// Equal offsets and compression do not identify the source archive.
	other := &Archive{}
	var digest [20]byte
	other.addResourceLocation(string(digest[:]), wimResourceLocation{archive: a, resource: resource})
	first := other.expandIndexed(other.byHash[digest]).wimResourceBacking
	other.addResourceLocation(string(digest[:]), wimResourceLocation{archive: other, resource: resource})
	if other.expandIndexed(other.byHash[digest]).wimResourceBacking == first {
		t.Fatal("merged different physical sources")
	}
	locations := other.resourceLocations(string(digest[:]))
	if len(locations) != 2 || locations[0].archive != a || locations[1].archive != other {
		t.Fatal("duplicate source provenance changed")
	}
}

func TestReferenceBackingOrdinalsSurviveImportAndDuplicates(t *testing.T) {
	a := &Archive{}
	first := []byte("first payload")
	second := []byte("second payload")
	third := []byte("third payload")
	a.addResourceLocation(string(sha1Digest(first)), wimResourceLocation{external: &countingWIMFile{data: first}, blobSize: int64(len(first))})
	refs := []storage.Reader{
		&countingWIMFile{data: legacyTestArchive(make([]byte, 16), second, third)},
		&countingWIMFile{data: legacyTestArchive(make([]byte, 16), third, second, second)},
	}
	if err := a.addReferenceIndexes(bytecache.New(0), refs); err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{first, second, third} {
		digest := sha1.Sum(data)
		f := a.newFile(entry{path: "/member", hash: digest})
		got, err := io.ReadAll(io.NewSectionReader(f, 0, f.Size()))
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("import %q: %q %v", data, got, err)
		}
	}
	locations := a.resourceLocations(string(sha1Digest(second)))
	if len(locations) != 3 {
		t.Fatalf("duplicate history: %d", len(locations))
	}
	if locations[0].archive.cacheSource != 2 || locations[1].archive.cacheSource != 3 || locations[2].archive.cacheSource != 3 {
		t.Fatal("reference order changed")
	}
	for _, l := range locations {
		if len(l.archive.byHash) != 0 || len(l.archive.resourceBackings) != 0 {
			t.Fatal("reference index retained")
		}
	}
}
func sha1Digest(data []byte) []byte { digest := sha1.Sum(data); return digest[:] }
