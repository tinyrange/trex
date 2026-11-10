package native

import (
	"crypto/sha256"
	"fmt"
	"github.com/tinyrange/trex/storage"
	bytecache "github.com/tinyrange/trex/storage/cache"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func TestStagedReaderSlabsPreserveIndependentProofs(t *testing.T) {
	var store stagedEffectStore
	cache := stageTestCache(t, 512)
	readers := make([]*reopenedStageReader, 513)
	for i := range readers {
		data := []byte(fmt.Sprintf("admitted-%04d", i))
		readers[i] = store.newReader(int64(len(data)), cache, bytecache.Key{Index: i}, func() (storage.Reader, error) { return &starfile.Bytes{Data: data}, nil }, sha256.Sum256(data), true)
	}
	// Read backward across several slabs, then reread after cache eviction.
	for pass := 0; pass < 2; pass++ {
		for i := len(readers) - 1; i >= 0; i-- {
			reader := readers[i]
			want := fmt.Sprintf("admitted-%04d", i)
			got := make([]byte, len(want))
			if _, err := reader.ReadAt(got, 0); err != nil || string(got) != want {
				t.Fatalf("reader %d: %q %v", i, got, err)
			}
			if hash, ok := reader.VerifiedSHA256(); !ok || hash != sha256.Sum256(got) {
				t.Fatalf("reader %d proof changed", i)
			}
		}
	}
	// Existing proof flags cannot admit changed content after its cached bytes
	// are evicted, including when its digest lives next to another reader.
	readers[len(readers)-1].open = func() (storage.Reader, error) { return &starfile.Bytes{Data: []byte("tampered-0512")}, nil }
	if _, err := readers[len(readers)-1].ReadAt(make([]byte, 1), 0); err == nil {
		t.Fatal("changed evicted target accepted")
	}
}
