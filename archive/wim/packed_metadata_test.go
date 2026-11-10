package wim

import (
	"encoding/binary"
	bytecache "github.com/tinyrange/trex/storage/cache"
	"reflect"
	"testing"
)

func TestPackedMetadataHandoffCrossesChunksAndRevalidates(t *testing.T) {
	_, fixture := boundedMetadataFixture(t)
	data := make([]byte, 152+1000*128+8)
	copy(data, fixture.data[:152])
	for i := 0; i < 1000; i++ {
		record := data[152+i*128 : 152+(i+1)*128]
		copy(record, fixture.data[152:280])
		binary.LittleEndian.PutUint16(record[102:], uint16(0x400+i))
		record[126] = byte(i)
	}
	source := &countingWIMFile{data: data}
	a := &Archive{file: source, imageCount: 1, cacheStore: bytecache.New(256 << 10), cacheSource: 77,
		lookup: []wimLookupEntry{{resource: wimResource{size: int64(len(data)), originalSize: int64(len(data)), flags: wimResourceMetadata}}}}
	if err := a.readImages(); err != nil {
		t.Fatal(err)
	}
	want, err := a.readWIMDir(&a.images[0], a.images[0].root)
	if err != nil || len(want) != 1000 {
		t.Fatalf("ordinary directory: %d %v", len(want), err)
	}
	a.ReleaseReadCaches()
	got, err := a.readWIMDir(&a.images[0], a.images[0].root)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("packed directory changed entries: %v", err)
	}
	if stats := a.cacheStore.Stats(); stats.Bytes >= int64(len(data))/2 {
		t.Fatalf("expanded metadata retained: %+v", stats)
	}
	a.ReleaseReadCaches()
	// Even corruption outside the requested entry is rejected: reload still
	// verifies the complete metadata identity, not just individual pages.
	source.data[len(data)-1] ^= 1
	if _, err := a.lookupPath("/image1/" + want[0].name); err == nil {
		t.Fatal("changed backing metadata accepted")
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("returned entries borrowed a reused scan buffer")
	}
}
