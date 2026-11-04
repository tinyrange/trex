package native

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/tinyrange/trex/lifecycle"
	bytecache "github.com/tinyrange/trex/storage/cache"
	storagenative "github.com/tinyrange/trex/storage/native"
	windowsupdate "github.com/tinyrange/trex/windows/update"
)

func TestUUPPayloadCacheRetainsSourceAcrossRuns(t *testing.T) {
	payload := []byte("uup source media")
	digest := sha256.Sum256(payload)
	var requests atomic.Int32
	var resolutions atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		var start, end int
		if _, err := fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &start, &end); err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(payload)))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(payload[start : end+1])
	}))
	defer server.Close()
	root := t.TempDir()
	file := windowsupdate.File{Name: "payload.esd", Size: int64(len(payload)), DigestSHA256: hex.EncodeToString(digest[:])}
	for run := range 2 {
		resources := lifecycle.New()
		disk, err := storagenative.NewHTTPRangeDiskCache(root)
		if err != nil {
			t.Fatal(err)
		}
		resolve := payloadLocationResolver([]windowsupdate.File{file}, func(context.Context) ([]windowsupdate.File, error) {
			resolutions.Add(1)
			if run != 0 {
				return nil, fmt.Errorf("cached source must not resolve locations")
			}
			located := file
			located.DownloadURL = server.URL
			return []windowsupdate.File{located}, nil
		})
		pool, err := storagenative.NewPersistentHTTPRangePool(4, 4, server.Client(), resolve, disk)
		if err != nil {
			t.Fatal(err)
		}
		reader, err := openPayload(resources, pool, file, file.Size)
		if err != nil {
			t.Fatal(err)
		}
		data := make([]byte, len(payload))
		if _, err := reader.ReadAt(data, 0); err != nil || !bytes.Equal(data, payload) {
			t.Fatalf("run %d: got %q, err %v", run, data, err)
		}
		if err := resources.Close(); err != nil {
			t.Fatal(err)
		}
		server.Close()
	}
	if resolutions.Load() != 1 {
		t.Fatalf("location resolutions = %d, want one initial lookup only", resolutions.Load())
	}
	if requests.Load() != 4 {
		t.Fatalf("payload requests = %d, want four initial ranges only", requests.Load())
	}
}

func TestBaseWIMCacheRetainsAlternatingSolidChunksAndMetadata(t *testing.T) {
	// The Windows 11 UUP reference ESDs use 64 MiB solid chunks. Servicing
	// visits different base files between metadata lookups; those lookups
	// must not evict the entire decompression working set.
	const solidBytes = 64 << 20
	cache := bytecache.New(maximumWIMChunkCache)
	loads := 0
	read := func(source uint64, index, size int) {
		t.Helper()
		key := bytecache.Key{Source: source, Index: index}
		data, err := cache.Get(key, func() ([]byte, error) {
			loads++
			return make([]byte, size), nil
		})
		if err != nil || len(data) != size {
			t.Fatalf("read source %d chunk %d: size=%d err=%v", source, index, len(data), err)
		}
	}
	// The measured boot-font working set alone revisits eight solid chunks.
	// Two chunks would pass with the old generic 384 MiB cache and miss the
	// real regression: every second pass decompressing another half GiB.
	for range 2 {
		for index := range 8 {
			read(5, index, solidBytes)
			read(1, 0, 1024)
		}
	}
	if loads != 9 {
		t.Fatalf("alternating reads decompressed %d resources, want 9", loads)
	}
	if stats := cache.Stats(); stats.Bytes > maximumWIMChunkCache {
		t.Fatalf("cache exceeded bound: %+v", stats)
	}
}
