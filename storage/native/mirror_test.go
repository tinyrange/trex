package native

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tinyrange/trex/lifecycle"
	"go.starlark.net/starlark"
)

func mirrorDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func TestMirrorCacheResumesVerifiesAndReuses(t *testing.T) {
	payload := []byte("immutable mirror payload")
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		call := requests.Add(1)
		rangeHeader := request.Header.Get("Range")
		if call == 1 {
			writer.Header().Set("Content-Length", fmt.Sprint(len(payload)))
			_, _ = writer.Write(payload[:7])
			return
		}
		if rangeHeader != "" {
			var start int
			if _, err := fmt.Sscanf(rangeHeader, "bytes=%d-", &start); err != nil {
				t.Errorf("Range = %q", rangeHeader)
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			writer.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, len(payload)-1, len(payload)))
			writer.Header().Set("Content-Length", fmt.Sprint(len(payload)-start))
			writer.WriteHeader(http.StatusPartialContent)
			_, _ = writer.Write(payload[start:])
			return
		}
		writer.Header().Set("Content-Length", fmt.Sprint(len(payload)))
		_, _ = writer.Write(payload)
	}))
	defer server.Close()

	cache, err := NewMirrorCache(t.TempDir(), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	request := MirrorRequest{
		URLs: []string{server.URL + "/object"}, CacheKey: "release/object",
		SHA256: mirrorDigest(payload), Size: int64(len(payload)), MaximumBytes: 1024,
	}
	if _, err := cache.Open(context.Background(), request); err == nil || !strings.Contains(err.Error(), "failed") {
		t.Fatalf("interrupted download error = %v", err)
	}
	file, err := cache.Open(context.Background(), request)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	data := make([]byte, file.Size())
	if _, err := file.ReadAt(data, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, payload) {
		t.Fatalf("data = %q", data)
	}
	name := file.Name()
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("requests after resume = %d", got)
	}

	file, err = cache.Open(context.Background(), request)
	if err != nil {
		t.Fatalf("cache hit: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("cache hit made request %d", got)
	}

	corrupt := append([]byte(nil), payload...)
	corrupt[0] ^= 0xff
	if err := os.WriteFile(name, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err = cache.Open(context.Background(), request)
	if err != nil {
		t.Fatalf("repair corrupt cache object: %v", err)
	}
	defer file.Close()
	if got := requests.Load(); got != 3 {
		t.Fatalf("repair requests = %d", got)
	}
}

func TestMirrorCacheFallsBackAndBoundsResponses(t *testing.T) {
	payload := []byte("fallback")
	bad := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, "unavailable", http.StatusServiceUnavailable)
	}))
	defer bad.Close()
	good := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write(payload)
	}))
	defer good.Close()
	cache, err := NewMirrorCache(t.TempDir(), good.Client())
	if err != nil {
		t.Fatal(err)
	}
	file, err := cache.Open(context.Background(), MirrorRequest{
		URLs: []string{bad.URL, good.URL}, CacheKey: "fallback", SHA256: mirrorDigest(payload),
		Size: int64(len(payload)), MaximumBytes: int64(len(payload)),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	_, err = cache.Open(context.Background(), MirrorRequest{
		URLs: []string{good.URL}, CacheKey: "too-small", Size: -1, MaximumBytes: 3,
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("maximum error = %v", err)
	}
}

func TestMirrorCacheRejectsBadInputsAndDigest(t *testing.T) {
	cache, err := NewMirrorCache(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range []MirrorRequest{
		{URLs: []string{"file:///tmp/x"}, CacheKey: "x", Size: -1, MaximumBytes: 1},
		{URLs: []string{"https://example.invalid"}, CacheKey: "", Size: -1, MaximumBytes: 1},
		{URLs: []string{"https://example.invalid"}, CacheKey: "x", SHA256: "bad", Size: -1, MaximumBytes: 1},
	} {
		if _, err := cache.Open(context.Background(), request); err == nil {
			t.Fatalf("accepted %#v", request)
		}
	}

	payload := []byte("wrong digest")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { _, _ = writer.Write(payload) }))
	defer server.Close()
	wrong := sha256.Sum256([]byte("different"))
	_, err = cache.Open(context.Background(), MirrorRequest{
		URLs: []string{server.URL}, CacheKey: "digest", SHA256: hex.EncodeToString(wrong[:]),
		Size: int64(len(payload)), MaximumBytes: 1024,
	})
	if err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("digest error = %v", err)
	}
}

func TestContentRangeStart(t *testing.T) {
	start, err := contentRangeStart("bytes 123-456/789")
	if err != nil || start != 123 {
		t.Fatalf("range = %d, %v", start, err)
	}
	for _, value := range []string{"", "items 1-2/3", "bytes x-2/3", "bytes 1/3"} {
		if _, err := contentRangeStart(value); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
}

func TestCachedFileReaderContract(t *testing.T) {
	payload := []byte("reader")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { _, _ = writer.Write(payload) }))
	defer server.Close()
	cache, _ := NewMirrorCache(t.TempDir(), server.Client())
	file, err := cache.Open(context.Background(), MirrorRequest{
		URLs: []string{server.URL}, CacheKey: "reader", Size: int64(len(payload)), MaximumBytes: 64,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.NewSectionReader(file, 0, file.Size()))
	if err != nil || !bytes.Equal(data, payload) {
		t.Fatalf("reader = %q, %v", data, err)
	}
}

func TestMirrorFileBuiltin(t *testing.T) {
	payload := []byte("starlark mirror")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { _, _ = writer.Write(payload) }))
	defer server.Close()
	thread := &starlark.Thread{Name: "mirror-test"}
	resources := lifecycle.Install(thread)
	defer resources.Close()
	value, err := mirrorFileBuiltin(thread, nil, starlark.Tuple{
		starlark.NewList([]starlark.Value{starlark.String(server.URL)}),
		starlark.String(t.TempDir()), starlark.String("starlark/object"),
	}, []starlark.Tuple{
		{starlark.String("sha256"), starlark.String(mirrorDigest(payload))},
		{starlark.String("size"), starlark.MakeInt(len(payload))},
		{starlark.String("maximum"), starlark.MakeInt(1024)},
	})
	if err != nil {
		t.Fatal(err)
	}
	file, ok := value.(*CachedFile)
	if !ok || file.Size() != int64(len(payload)) {
		t.Fatalf("value = %T, size %d", value, file.Size())
	}
}
