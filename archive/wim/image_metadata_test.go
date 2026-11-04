package wim

import (
	"bytes"
	"encoding/binary"
	"strings"
	"sync"
	"testing"

	bytecache "github.com/tinyrange/trex/storage/cache"
)

func boundedMetadataFixture(t *testing.T) (*Archive, *countingWIMFile) {
	t.Helper()
	// Security descriptor, root with a tagged EA, and one child with an EA.
	metadata := make([]byte, 512)
	binary.LittleEndian.PutUint32(metadata, 20)
	binary.LittleEndian.PutUint32(metadata[4:], 1)
	binary.LittleEndian.PutUint64(metadata[8:], 4)
	copy(metadata[16:], []byte{1, 2, 3, 4})
	dentry := func(off int, name string, child uint64) {
		b := metadata[off : off+128]
		binary.LittleEndian.PutUint64(b, 128)
		binary.LittleEndian.PutUint64(b[16:], child)
		encoded := utf16Bytes(name)
		binary.LittleEndian.PutUint16(b[100:], uint16(len(encoded)))
		copy(b[102:], encoded)
		// Name x occupies 106 bytes including terminator; tags begin at 112.
		binary.LittleEndian.PutUint32(b[112:], 2)
		binary.LittleEndian.PutUint32(b[116:], 7)
		copy(b[120:], []byte{1, 0, 1, 0, 'A', 0, 0x65})
	}
	dentry(24, "", 152)
	// Empty root name has no terminator: tags begin at 104, not 112.
	copy(metadata[24+104:24+120], metadata[24+112:24+128])
	clear(metadata[24+120 : 24+128])
	dentry(152, "x", 0)
	reader := &countingWIMFile{data: append(append([]byte{}, metadata...), metadata...)}
	c := &Archive{file: reader, imageCount: 2, cacheStore: bytecache.New(512), cacheSource: 1}
	for _, off := range []int64{0, 512} {
		c.lookup = append(c.lookup, wimLookupEntry{resource: wimResource{offset: off, size: 512, originalSize: 512, flags: wimResourceMetadata}})
	}
	if err := c.readImages(); err != nil {
		t.Fatal(err)
	}
	return c, reader
}

func TestWIMImageMetadataBoundedAcrossEditionTraversal(t *testing.T) {
	c, reader := boundedMetadataFixture(t)
	for i := range c.images {
		img := &c.images[i]
		if img.metadata != nil || cap(img.security[0]) > 16 || cap(img.root.taggedItems[0].data) > 16 {
			t.Fatal("small parsed records still pin a complete image metadata buffer")
		}
		children, err := c.readWIMDir(img, img.root)
		if err != nil || len(children) != 1 || children[0].name != "x" {
			t.Fatalf("children=%v err=%v", children, err)
		}
		data, err := c.imageMetadata(img)
		if err != nil {
			t.Fatal(err)
		}
		// Parsed tag and EA values must remain valid independently of eviction.
		data[152+126] = 0xff
		if children[0].extendedAttributes[0].Value[0] != 0x65 || children[0].taggedItems[0].data[6] != 0x65 {
			t.Fatal("parsed child aliases the decoded metadata cache")
		}
		if stats := c.cacheStore.Stats(); stats.Bytes > 512 {
			t.Fatalf("unbounded metadata: %+v", stats)
		}
	}
	reads := reader.reads
	// Image 1 was evicted by traversal of image 2, but still resolves correctly.
	data, err := c.imageMetadata(&c.images[0])
	if err != nil || data[152+126] != 0x65 || reader.reads <= reads {
		t.Fatalf("evicted metadata was not reopened exactly: %v", err)
	}
}

func TestWIMImageMetadataRejectsChangedReload(t *testing.T) {
	c, reader := boundedMetadataFixture(t)
	// Root/security records are detached from their original validated buffer.
	// A change to a not-yet-cached image cannot change the promised metadata.
	reader.data[16] = 9
	reader.data[24+118] = 9
	if !bytes.Equal(c.images[0].security[0], []byte{1, 2, 3, 4}) || c.images[0].root.extendedAttributes[0].Value[0] != 0x65 {
		t.Fatal("source mutation changed already validated security/root data")
	}
	if _, err := c.imageMetadata(&c.images[0]); err == nil || !strings.Contains(err.Error(), "changed after validation") {
		t.Fatalf("changed image accepted: %v", err)
	}
	if c.cacheStore.Stats().Bytes != 0 {
		t.Fatal("failed reload entered cache")
	}
}

func TestWIMImageMetadataConcurrentLoadSingleFlight(t *testing.T) {
	c, reader := boundedMetadataFixture(t)
	reads := reader.reads
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			data, err := c.imageMetadata(&c.images[0])
			if err != nil || len(data) != 512 {
				t.Errorf("metadata=%d err=%v", len(data), err)
			}
		}()
	}
	group.Wait()
	if reader.reads != reads+1 {
		t.Fatalf("concurrent metadata reloaded %d times", reader.reads-reads)
	}
}
