package wim

import (
	"bytes"
	"testing"

	bytecache "github.com/tinyrange/trex/storage/cache"
	"go.starlark.net/starlark"
)

func prefetchFixture() (*Archive, *countingWIMFile, map[string]*File, []byte) {
	a, source, resource, plain := solidBlobFixture()
	a.blobCache = bytecache.New(2048)
	a.images = []image{{index: 1, root: entry{path: "/image1", isDir: true}, byPath: map[string]*entry{}}}
	a.byHash = map[[20]byte]indexedResourceLocation{}
	files := map[string]*File{}
	for name, offset := range map[string]int64{"/image1/early": 100, "/image1/late": 40000} {
		file := blobFile(a, resource, plain, offset, 1000, name)
		a.images[0].byPath[wimPathKey(name)] = &file.entry
		a.addResourceLocation(string(file.entry.hash[:]), *file.location)
		files[name] = file
	}
	return a, source, files, plain
}

func TestPrefetchWarmsExplicitFilesAndDeduplicatesAliases(t *testing.T) {
	a, source, files, plain := prefetchFixture()
	early := files["/image1/early"].entry
	early.path = "/image1/alias"
	a.images[0].byPath[wimPathKey(early.path)] = &early
	a.images[0].byPath[wimPathKey("/image1/empty")] = &entry{path: "/image1/empty"}
	paths := starlark.NewList([]starlark.Value{starlark.String("/image1/late"), starlark.String("/image1/alias"), starlark.String("/image1/early"), starlark.String("/image1/empty")})
	result, err := a.prefetchBuiltin(nil, nil, starlark.Tuple{paths}, nil)
	if err != nil {
		t.Fatal(err)
	}
	total, err := starlark.AsInt32(result)
	if err != nil || total != 2000 || a.blobCache.Stats().Loads != 2 {
		t.Fatalf("deduplicated prefetch: %v %v", result, err)
	}
	reads := source.reads
	source.data = nil
	for _, file := range files {
		got := make([]byte, 1000)
		if _, err := file.ReadAt(got, 0); err != nil {
			t.Fatal(err)
		}
		offset := file.location.blobOffset
		if !bytes.Equal(got, plain[offset:offset+1000]) {
			t.Fatal("prepared file bytes changed")
		}
	}
	if source.reads != reads {
		t.Fatal("prepared bytes required source redecoding")
	}
}

func TestPrefetchValidatesWholeSelectionBeforePayloadReads(t *testing.T) {
	a, source, _, _ := prefetchFixture()
	paths := starlark.NewList([]starlark.Value{starlark.String("/image1/early"), starlark.String("/missing")})
	if _, err := a.prefetchBuiltin(nil, nil, starlark.Tuple{paths}, nil); err == nil {
		t.Fatal("missing file accepted")
	}
	if source.reads != 0 || a.blobCache.Stats().Loads != 0 {
		t.Fatal("invalid selection performed payload reads")
	}
}
