package native

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tinyrange/trex/storage"
)

// Real VS payloads exposed this: a complete, hash-correct partial rejected
// for stale size metadata must be recoverable without a Range beyond EOF.
func TestMirrorCacheRecoversHashVerifiedCompletePartial(t *testing.T) {
	for _, sizeKnown := range []bool{false, true} {
		t.Run(fmt.Sprint(sizeKnown), func(t *testing.T) {
			payload := []byte("complete immutable payload")
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Header.Get("Range") != "" {
					w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
					return
				}
				_, _ = w.Write(payload)
			}))
			defer server.Close()
			cache, err := NewMirrorCache(t.TempDir(), server.Client())
			if err != nil {
				t.Fatal(err)
			}
			req := MirrorRequest{URLs: []string{server.URL}, CacheKey: "complete", SHA256: mirrorDigest(payload), Size: int64(len(payload) + 7), MaximumBytes: 1024}
			if _, err := cache.Open(context.Background(), req); err == nil || !strings.Contains(err.Error(), "downloaded size") {
				t.Fatalf("initial error: %v", err)
			}
			req.Size = -1
			if sizeKnown {
				req.Size = int64(len(payload))
			}
			req.Validate = func(storage.Reader) error { return errors.New("semantic validation rejected") }
			if _, err := cache.Open(context.Background(), req); err == nil || !strings.Contains(err.Error(), "semantic validation rejected") {
				t.Fatalf("validator bypassed: %v", err)
			}
			req.Validate = nil
			file, err := cache.Open(context.Background(), req)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			if file.Size() != int64(len(payload)) {
				t.Fatalf("size: %d", file.Size())
			}
			if requests.Load() != 1 {
				t.Fatalf("complete partial caused %d requests", requests.Load())
			}
		})
	}
}

func TestMirrorCacheDoesNotTrustCompletePartialSize(t *testing.T) {
	payload := []byte("not the pinned contents")
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Range") != "" {
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}
		_, _ = w.Write(payload)
	}))
	defer server.Close()
	cache, err := NewMirrorCache(t.TempDir(), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	req := MirrorRequest{URLs: []string{server.URL}, CacheKey: "wrong", SHA256: mirrorDigest([]byte("different pinned contents")), Size: int64(len(payload) + 1), MaximumBytes: 1024}
	if _, err := cache.Open(context.Background(), req); err == nil {
		t.Fatal("accepted wrong size")
	}
	req.Size = int64(len(payload))
	if _, err := cache.Open(context.Background(), req); err == nil {
		t.Fatal("accepted complete partial without matching digest")
	}
	if requests.Load() != 2 {
		t.Fatalf("unverified partial did not require HTTP: %d", requests.Load())
	}
}
