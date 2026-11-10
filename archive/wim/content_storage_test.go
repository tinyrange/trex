package wim

import (
	"crypto/sha1"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func TestContentSlabsKeepEarlierReadersAndBackingIdentity(t *testing.T) {
	archive := &Archive{}
	store := contentFileStore{archive: archive}
	files := make([]*contentFile, 1025)
	for i := range files {
		name := fmt.Sprintf("/image1/Windows/日本語/component-long-name-%04d/file.dll", i)
		data := []byte(fmt.Sprintf("payload-%04d", i))
		hash := sha1.Sum(data)
		archive.addResourceLocation(string(hash[:]), wimResourceLocation{external: &starfile.Bytes{Data: data}, blobSize: int64(len(data))})
		files[i] = store.newFile(entry{path: name, size: int64(len(data)), hash: hash})
	}
	// Readers from the first slab must still address the same source after
	// enough additions to replace both allocator tails and the path block.
	for i, f := range files {
		want := fmt.Sprintf("payload-%04d", i)
		got := make([]byte, len(want))
		if _, err := f.ReadAt(got, 0); err != nil || string(got) != want {
			t.Fatalf("reader %d: %q %v", i, got, err)
		}
		if f.path != fmt.Sprintf("/image1/Windows/日本語/component-long-name-%04d/file.dll", i) {
			t.Fatalf("path %d overwritten", i)
		}
	}
}
