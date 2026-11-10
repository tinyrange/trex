package wim

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"io"
	"testing"

	"go.starlark.net/starlark"
)

func TestResourceLocationsRetainDuplicateOrderAndLastSelection(t *testing.T) {
	a := &Archive{byHash: make(map[[20]byte]indexedResourceLocation), locationsByHash: make(map[string][]wimResourceLocation)}
	good := []byte("verified resource")
	digest := sha1.Sum(good)
	// A corrupt earlier source must remain visible to diagnostics, while normal
	// reads select the last source just as before the compact index.
	sources := []*countingWIMFile{{data: []byte("corrupt resource!")}, {data: good}, {data: good}}
	for i, source := range sources {
		if err := a.AddExternalResources([]ExternalResource{{SHA1: digest, File: source}}); err != nil {
			t.Fatal(err)
		}
		if i == 0 && len(a.locationsByHash) != 0 {
			t.Fatal("singleton allocated duplicate history")
		}
		locations := a.resourceLocations(string(digest[:]))
		if len(locations) != i+1 {
			t.Fatalf("locations = %d, want %d", len(locations), i+1)
		}
		for j, location := range locations {
			if location.external != sources[j] {
				t.Fatalf("location %d changed order", j)
			}
		}
	}
	f := a.newFile(entry{path: "/image1/member", hash: digest})
	data, err := io.ReadAll(io.NewSectionReader(f, 0, f.Size()))
	if err != nil || !bytes.Equal(data, good) {
		t.Fatalf("selected content = %q, %v", data, err)
	}
	value, err := a.resourceLocationsBuiltin(nil, nil, starlark.Tuple{starlark.String(hex.EncodeToString(digest[:]))}, nil)
	if err != nil || value.(*starlark.List).Len() != 3 {
		t.Fatalf("public locations = %v, %v", value, err)
	}
	value, err = f.verifyLocationsBuiltin(nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	results := value.(*starlark.List)
	if results.Len() != 3 {
		t.Fatal(results)
	}
	for i := 0; i < results.Len(); i++ {
		valid, err := results.Index(i).(starlark.HasAttrs).Attr("valid")
		if err != nil || valid != starlark.Bool(i != 0) {
			t.Fatalf("verification %d = %v, %v", i, valid, err)
		}
	}
	if got := a.resourceLocations("missing"); len(got) != 0 {
		t.Fatal(got)
	}
}
