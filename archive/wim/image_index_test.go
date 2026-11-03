package wim

import (
	"encoding/binary"
	"strings"
	"testing"
)

// The first image of MCT ESDs is setup media, with a zero-sized empty
// security table. Silently skipping it used to renumber every OS image.
func imageIndexFixture(metadata ...[]byte) *Archive {
	var data []byte
	var lookup []wimLookupEntry
	for _, item := range metadata {
		lookup = append(lookup, wimLookupEntry{resource: wimResource{
			offset: int64(len(data)), size: int64(len(item)), originalSize: int64(len(item)), flags: wimResourceMetadata,
		}})
		data = append(data, item...)
	}
	return &Archive{file: &countingWIMFile{data: data}, imageCount: len(metadata), lookup: lookup}
}

func emptyImageMetadata(securitySize uint32, marker uint64) []byte {
	data := make([]byte, 120)
	binary.LittleEndian.PutUint32(data, securitySize)
	binary.LittleEndian.PutUint64(data[8:], 104)
	binary.LittleEndian.PutUint32(data[16:], 0x10)
	binary.LittleEndian.PutUint32(data[20:], 0xffffffff)
	binary.LittleEndian.PutUint64(data[48:], marker)
	return data
}

func TestSetupMediaEmptySecurityTablePreservesImageIndexes(t *testing.T) {
	archive := imageIndexFixture(emptyImageMetadata(0, 101), emptyImageMetadata(8, 202))
	if err := archive.readImages(); err != nil {
		t.Fatal(err)
	}
	if len(archive.images) != 2 {
		t.Fatalf("images = %d", len(archive.images))
	}
	for index, marker := range []uint64{101, 202} {
		image := &archive.images[index]
		if image.index != index+1 || image.root.creationTime != marker {
			t.Fatalf("image %d mapped incorrectly: %+v", index+1, image.root)
		}
		if len(image.security) != 0 {
			t.Fatal("empty table acquired descriptors")
		}
	}
}

func TestMalformedImageIsNotSilentlySkippedOrRenumbered(t *testing.T) {
	invalid := emptyImageMetadata(0, 101)
	binary.LittleEndian.PutUint32(invalid[4:], 1) // zero size with nonzero descriptor count
	archive := imageIndexFixture(invalid, emptyImageMetadata(8, 202))
	if err := archive.readImages(); err == nil || !strings.Contains(err.Error(), "image 1") {
		t.Fatalf("expected indexed error, got %v", err)
	}
	truncated := imageIndexFixture([]byte{0, 0, 0, 0}, emptyImageMetadata(8, 202))
	if err := truncated.readImages(); err == nil || !strings.Contains(err.Error(), "image 1") {
		t.Fatalf("truncated image: %v", err)
	}
	missing := imageIndexFixture(emptyImageMetadata(8, 202))
	missing.imageCount = 2
	if err := missing.readImages(); err == nil || !strings.Contains(err.Error(), "declares 2 images") {
		t.Fatalf("missing metadata: %v", err)
	}
}
