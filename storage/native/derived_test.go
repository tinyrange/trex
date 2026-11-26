package native

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestDerivedRecordReuseAndRepair(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "records")
	cache, err := NewDerivedCache(root)
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	key := sha256.Sum256([]byte("input"))
	record := []byte("compiled input")
	builds := 0
	build := func() ([]byte, error) {
		builds++
		return record, nil
	}
	get := func(cache *DerivedCache) {
		t.Helper()
		got, err := cache.GetOrBuild(ctx, key, 64, build)
		if err != nil || !bytes.Equal(got, record) {
			t.Fatalf("unexpected record %q, %v", got, err)
		}
	}
	get(cache)
	reopened, err := NewDerivedCache(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	get(reopened)
	if builds != 1 {
		t.Fatalf("derived record rebuilt on hit, builds = %d", builds)
	}
	shard := &cache.shards[key[0]]
	handle, err := os.OpenFile(filepath.Join(root, "records-v1", fmt.Sprintf("%02x.pack", key[0])), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handle.WriteAt([]byte{0}, shard.entries[key].offset); err != nil {
		t.Fatal(err)
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
	get(reopened)
	if builds != 2 {
		t.Fatalf("corrupt record was not rebuilt, builds = %d", builds)
	}
}

func TestDerivedRecordBuilderCanUseSameShard(t *testing.T) {
	cache, err := NewDerivedCache(filepath.Join(t.TempDir(), "records"))
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	ctx := context.Background()
	parent, child := [32]byte{1, 2}, [32]byte{1, 3}
	data, err := cache.GetOrBuild(ctx, parent, 64, func() ([]byte, error) {
		return cache.GetOrBuild(ctx, child, 64, func() ([]byte, error) { return []byte("child"), nil })
	})
	if err != nil || string(data) != "child" {
		t.Fatalf("nested same-shard record = %q, %v", data, err)
	}
}

func TestDerivedContentSeekAndCorruption(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "records")
	cache, err := NewDerivedCache(root)
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("verified Windows payload"), 8000)
	digest := sha256.Sum256(data)
	file, err := cache.GetOrBuildContent(ctx, digest, int64(len(data)), func() ([]byte, error) {
		return data, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	offset := int64(contentChunkBytes - 9)
	part := make([]byte, 41)
	if n, err := file.ReadAt(part, offset); n != len(part) || err != nil || !bytes.Equal(part, data[offset:offset+int64(len(part))]) {
		t.Fatalf("read across chunks: %d, %v", n, err)
	}

	reopened, err := NewDerivedCache(root)
	if err != nil {
		t.Fatal(err)
	}
	noBuild := func() ([]byte, error) { return nil, errors.New("loader ran on hit") }
	file, err = reopened.GetOrBuildContent(ctx, digest, int64(len(data)), noBuild)
	if err != nil {
		t.Fatal(err)
	}
	reader := file.(*contentReader)
	handle, err := os.OpenFile(reader.name, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	last := reader.chunks[len(reader.chunks)-1]
	var octet [1]byte
	if _, err := handle.ReadAt(octet[:], last.offset); err != nil {
		t.Fatal(err)
	}
	octet[0] ^= 1
	if _, err := handle.WriteAt(octet[:], last.offset); err != nil {
		t.Fatal(err)
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := file.ReadAt(part, int64(len(data)-len(part))); err == nil {
		t.Fatal("corrupt content passed verification")
	}
}

func TestDerivedContentRejectsWrongDigest(t *testing.T) {
	cache, err := NewDerivedCache(filepath.Join(t.TempDir(), "records"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("right"))
	if _, err := cache.GetOrBuildContent(context.Background(), digest, 5, func() ([]byte, error) {
		return []byte("wrong"), nil
	}); err == nil {
		t.Fatal("wrong content admitted")
	}
}
