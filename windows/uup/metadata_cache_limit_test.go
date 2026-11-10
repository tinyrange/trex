package uup

import (
	"bytes"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func TestMetadataCacheHandoffBoundsSubsequentReads(t *testing.T) {
	cache, err := NewStageMetadataCache(4096)
	if err != nil {
		t.Fatal(err)
	}
	var stages []*CumulativeStage
	for _, payload := range []string{"first", "second", "third"} {
		stage, err := OpenCanonicalStageCache(payload, &starfile.Bytes{Data: canonicalCacheFixture(t, payload)}, cache)
		if err != nil {
			t.Fatal(err)
		}
		stages = append(stages, stage)
	}
	read := func() {
		t.Helper()
		for _, stage := range stages {
			f, err := stage.metadataCAB.Lookup("0")
			if err != nil {
				t.Fatal(err)
			}
			got, err := starfile.ReadAll(f)
			if err != nil || !bytes.Equal(got, []byte(stage.MetadataName)) {
				t.Fatalf("read after resize: %q %v", got, err)
			}
		}
	}
	read()
	if cache.store.Stats().Bytes <= 600 {
		t.Fatal("fixture did not populate construction cache")
	}
	cache.SetLimit(600)
	if cache.store.Stats().Bytes > 600 {
		t.Fatal("resize did not evict")
	}
	for _, stage := range stages {
		stage.ReleaseReadCaches()
	}
	for range 3 {
		read()
		if stats := cache.store.Stats(); stats.Bytes > 600 {
			t.Fatalf("runtime cache regrew: %+v", stats)
		}
	}
}
