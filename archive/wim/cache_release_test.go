package wim

import (
	"sync"
	"testing"
)

func TestReleaseReadCachesPreservesConcurrentNamespace(t *testing.T) {
	a := indexedLookupFixture([]string{"Σ.txt", "Hello.txt", "S.txt"})
	entries, err := a.readWIMDir(&a.images[0], a.images[0].root)
	if err != nil {
		t.Fatal(err)
	}
	a.ReleaseReadCaches()
	if len(entries) != 3 {
		t.Fatal("returned directory invalidated")
	}
	var group sync.WaitGroup
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			for range 100 {
				a.ReleaseReadCaches()
				for query, want := range map[string]string{"/IMAGE1/hello.TXT": "Hello.txt", "/image1/ς.txt": "Σ.txt", "/image1/ſ.txt": "S.txt"} {
					got, err := a.lookupPath(query)
					if err != nil || got.name != want {
						t.Errorf("lookup %s: %s %v", query, got.name, err)
					}
				}
			}
		}()
	}
	group.Wait()
}

func TestReleaseReadCachesRetainsMetadataIdentityValidation(t *testing.T) {
	a, source := boundedMetadataFixture(t)
	if _, err := a.lookupPath("/image1/x"); err != nil {
		t.Fatal(err)
	}
	a.ReleaseReadCaches()
	source.data[152+126] ^= 1
	if _, err := a.lookupPath("/image1/x"); err == nil {
		t.Fatal("changed backing metadata accepted after release")
	}
}
