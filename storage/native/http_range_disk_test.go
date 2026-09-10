package native

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPersistentHTTPRangesSurviveEvictionReopenAndNewPool(t *testing.T) {
	payload := []byte("abcdefghijklmnopqrstuvwxyz123") // includes a short final range
	digest := sha256.Sum256(payload)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		var start, end int
		if _, err := fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &start, &end); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(payload)))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(payload[start : end+1])
	}))
	defer server.Close()
	root := t.TempDir()
	newPool := func() *HTTPRangePool {
		t.Helper()
		disk, err := NewHTTPRangeDiskCache(root)
		if err != nil {
			t.Fatal(err)
		}
		// Retain only one of four ranges in RAM, deliberately forcing eviction.
		pool, err := NewPersistentHTTPRangePool(8, 8, server.Client(), nil, disk)
		if err != nil {
			t.Fatal(err)
		}
		return pool
	}
	open := func(pool *HTTPRangePool, name, url string) *HTTPRangeFile {
		t.Helper()
		f, err := pool.OpenSHA256(context.Background(), name, []string{url}, int64(len(payload)), hex.EncodeToString(digest[:]))
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	pool := newPool()
	f := open(pool, "original", server.URL+"/original")
	read := func(f *HTTPRangeFile) {
		t.Helper()
		data := make([]byte, len(payload))
		if _, err := f.ReadAt(data, 0); err != nil || !bytes.Equal(data, payload) {
			t.Errorf("read = %q, %v", data, err)
		}
	}
	read(f)
	if requests.Load() != 4 {
		t.Fatalf("initial requests = %d", requests.Load())
	}
	if stats := pool.cache.Stats(); stats.Evictions == 0 {
		t.Fatal("test did not force RAM eviction")
	}
	server.Close() // All subsequent operations must work without the server.
	read(f)
	read(open(pool, "renamed", server.URL+"/expired"))
	read(open(newPool(), "next-run", server.URL+"/renewed"))
	if requests.Load() != 4 {
		t.Fatalf("repeated HTTP requests = %d", requests.Load())
	}
}

func TestPersistentHTTPRangesCoalesceIndependentPools(t *testing.T) {
	var requests atomic.Int32
	payload := []byte("abcdefgh")
	digest := sha256.Sum256(payload)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Range", "bytes 0-7/8")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(payload)
	}))
	defer server.Close()
	root := t.TempDir()
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 8 {
		wg.Go(func() {
			disk, _ := NewHTTPRangeDiskCache(root)
			pool, err := NewPersistentHTTPRangePool(8, 8, server.Client(), nil, disk)
			if err != nil {
				t.Error(err)
				return
			}
			f, err := pool.OpenSHA256(context.Background(), "same", []string{server.URL}, 8, hex.EncodeToString(digest[:]))
			if err != nil {
				t.Error(err)
				return
			}
			<-start
			data := make([]byte, 8)
			if _, err := f.ReadAt(data, 0); err != nil || !bytes.Equal(data, payload) {
				t.Errorf("concurrent read = %q, %v", data, err)
			}
		})
	}
	close(start)
	wg.Wait()
	if requests.Load() != 1 {
		t.Fatalf("same range fetched %d times", requests.Load())
	}
}

func TestPersistentHTTPRangeCacheRejectsDamageWithoutRefetch(t *testing.T) {
	for _, damage := range []string{"checksum", "truncated", "directory"} {
		t.Run(damage, func(t *testing.T) {
			disk, _ := NewHTTPRangeDiskCache(t.TempDir())
			digest := sha256.Sum256([]byte("payload"))
			loads := 0
			load := func() ([]byte, error) { loads++; return []byte("12345678"), nil }
			if _, err := disk.get(context.Background(), digest, 8, 0, 8, load); err != nil {
				t.Fatal(err)
			}
			name := disk.blockPath(digest, 8, 0, 8)
			switch damage {
			case "checksum":
				if err := os.WriteFile(name, make([]byte, 40), 0o600); err != nil {
					t.Fatal(err)
				}
			case "truncated":
				if err := os.Truncate(name, 10); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Remove(name); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(name, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := disk.get(context.Background(), digest, 8, 0, 8, load); err == nil {
				t.Fatal("accepted damaged range")
			}
			if loads != 1 {
				t.Fatalf("damage caused %d loads", loads)
			}
		})
	}
}

func TestPersistentHTTPRangeCacheIdentityAndInterruptedFetch(t *testing.T) {
	disk, _ := NewHTTPRangeDiskCache(t.TempDir())
	a, b := sha256.Sum256([]byte("a")), sha256.Sum256([]byte("b"))
	loads := 0
	load := func() ([]byte, error) { loads++; return []byte("12345678"), nil }
	for _, key := range []struct {
		digest       [32]byte
		size, offset int64
	}{{a, 16, 0}, {a, 16, 8}, {a, 8, 0}, {b, 8, 0}} {
		if _, err := disk.get(context.Background(), key.digest, key.size, key.offset, 8, load); err != nil {
			t.Fatal(err)
		}
	}
	if loads != 4 {
		t.Fatal("different identities or ranges aliased")
	}
	c := sha256.Sum256([]byte("interrupted"))
	if _, err := disk.get(context.Background(), c, 8, 0, 8, func() ([]byte, error) { return nil, context.Canceled }); err == nil {
		t.Fatal("accepted interrupted fetch")
	}
	if _, err := os.Stat(disk.blockPath(c, 8, 0, 8)); !os.IsNotExist(err) {
		t.Fatalf("published failed fetch: %v", err)
	}
	if _, err := disk.get(context.Background(), c, 8, 0, 8, load); err != nil {
		t.Fatal(err)
	}
	pool, _ := NewPersistentHTTPRangePool(8, 8, nil, nil, disk)
	if _, err := pool.Open(context.Background(), "missing identity", []string{"https://example.test/a"}, 8); err == nil {
		t.Fatal("accepted missing SHA-256")
	}
	if _, err := pool.OpenSHA256(context.Background(), "bad", []string{"https://example.test/a"}, 8, strings.Repeat("x", 64)); err == nil {
		t.Fatal("accepted malformed SHA-256")
	}
}

func TestHTTPRangeCacheLockCancellation(t *testing.T) {
	name := filepath.Join(t.TempDir(), "range.lock")
	first, err := lockHTTPRangeCache(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if second, err := lockHTTPRangeCache(ctx, name); err == nil {
		second.Close()
		t.Fatal("acquired held lock")
	}
	if ctx.Err() == nil {
		t.Fatal("lock failed before cancellation")
	}
}
