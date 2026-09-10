package native

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"go.starlark.net/starlark"
)

func TestHTTPRangeRefreshSharesRenewalAcrossConcurrentChunks(t *testing.T) {
	payload := []byte("abcdefghijklmnop")
	var forbidden, renewals atomic.Int32
	gate := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/expired" {
			if forbidden.Add(1) == 2 {
				close(gate)
			}
			select {
			case <-gate:
			case <-r.Context().Done():
				return
			}
			w.WriteHeader(http.StatusForbidden)
			return
		}
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
	pool, err := NewRefreshingHTTPRangePool(8, 16, server.Client(), func(ctx context.Context, name string, size int64, previous []string) ([]string, error) {
		renewals.Add(1)
		if name != "immutable" || size != 16 || len(previous) != 1 || previous[0] != server.URL+"/expired" {
			t.Error("resolver lost file identity")
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Error("refresh lacks fetch deadline")
		}
		return []string{server.URL + "/fresh"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	f, err := pool.Open(context.Background(), "immutable", []string{server.URL + "/expired"}, 16)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for _, off := range []int64{0, 8} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b := make([]byte, 8)
			if _, err := f.ReadAt(b, off); err != nil || string(b) != string(payload[off:off+8]) {
				t.Errorf("chunk %d: %q, %v", off, b, err)
			}
		}()
	}
	wg.Wait()
	if renewals.Load() != 1 {
		t.Fatalf("renewals = %d, want 1", renewals.Load())
	}
	b := make([]byte, 16)
	if _, err := f.ReadAt(b, 0); err != nil || string(b) != string(payload) {
		t.Fatalf("cached file = %q, %v", b, err)
	}
}

func TestHTTPRangeRefreshIsBoundedAndKeepsRangeValidation(t *testing.T) {
	for _, kind := range []string{"still-forbidden", "wrong-size", "invalid-location", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			var requests, renewals atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.URL.Path == "/expired" || kind == "still-forbidden" {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				w.Header().Set("Content-Range", "bytes 0-7/9") // immutable size is8
				w.WriteHeader(http.StatusPartialContent)
				_, _ = w.Write([]byte("abcdefgh"))
			}))
			defer server.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			pool, err := NewRefreshingHTTPRangePool(8, 8, server.Client(), func(ctx context.Context, _ string, _ int64, _ []string) ([]string, error) {
				renewals.Add(1)
				if kind == "cancelled" {
					cancel()
					<-ctx.Done()
					return nil, ctx.Err()
				}
				if kind == "invalid-location" {
					return []string{"file:///invalid"}, nil
				}
				return []string{server.URL + "/fresh"}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			f, err := pool.Open(ctx, "bounded", []string{server.URL + "/expired"}, 8)
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.ReadAt(make([]byte, 8), 0)
			if err == nil || !strings.Contains(err.Error(), "bounded") {
				t.Fatalf("expected named failure: %v", err)
			}
			if renewals.Load() != 1 || requests.Load() > httpRangeAttempts {
				t.Fatalf("requests=%d renewals=%d", requests.Load(), renewals.Load())
			}
		})
	}
}

func TestHTTPRangeFileReadsAcrossChunks(t *testing.T) {
	payload := []byte("abcdefghijklmnopqrstuvwxyz")
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		var start, end int
		if _, err := fmt.Sscanf(request.Header.Get("Range"), "bytes=%d-%d", &start, &end); err != nil {
			t.Error(err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(payload)))
		writer.WriteHeader(http.StatusPartialContent)
		_, _ = writer.Write(payload[start : end+1])
	}))
	defer server.Close()
	file, err := NewHTTPRangeFile("fixture", []string{server.URL}, int64(len(payload)), 8, 16, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 12)
	if _, err := file.ReadAt(buffer, 6); err != nil || string(buffer) != "ghijklmnopqr" {
		t.Fatalf("read = %q, %v", buffer, err)
	}
	if _, err := file.ReadAt(buffer[:4], 8); err != nil || string(buffer[:4]) != "ijkl" {
		t.Fatalf("cached read = %q, %v", buffer[:4], err)
	}
	if requests != 3 {
		t.Fatalf("requests = %d, want 3 chunks", requests)
	}
}

func TestHTTPFileBuiltinUsesBoundedMemoryReader(t *testing.T) {
	payload := []byte("bounded HTTP input")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var start, end int
		if _, err := fmt.Sscanf(request.Header.Get("Range"), "bytes=%d-%d", &start, &end); err != nil {
			t.Error(err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(payload)))
		writer.WriteHeader(http.StatusPartialContent)
		_, _ = writer.Write(payload[start : end+1])
	}))
	defer server.Close()
	value, err := httpFileBuiltin(&starlark.Thread{Name: "http-file-test"}, nil, nil, []starlark.Tuple{
		{starlark.String("urls"), starlark.NewList([]starlark.Value{starlark.String(server.URL)})},
		{starlark.String("size"), starlark.MakeInt(len(payload))},
		{starlark.String("chunk_bytes"), starlark.MakeInt(8)},
		{starlark.String("cache_bytes"), starlark.MakeInt(16)},
	})
	if err != nil {
		t.Fatal(err)
	}
	file := value.(*HTTPRangeFile)
	got, err := io.ReadAll(io.NewSectionReader(file, 0, file.Size()))
	if err != nil || string(got) != string(payload) {
		t.Fatalf("read = %q, %v", got, err)
	}
}

func TestHTTPFileDiscoversSizeWithoutDownloadingBody(t *testing.T) {
	payload := []byte("discovered range input")
	heads, gets := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			heads++
			if r.Header.Get("Accept-Encoding") != "identity" {
				t.Error("discovery did not request identity encoding")
			}
			w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
			return
		}
		gets++
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
	v, err := httpFileBuiltin(&starlark.Thread{Name: "discover"}, nil,
		starlark.Tuple{starlark.NewList([]starlark.Value{starlark.String(server.URL)})},
		[]starlark.Tuple{{starlark.String("chunk_bytes"), starlark.MakeInt(8)}, {starlark.String("cache_bytes"), starlark.MakeInt(16)}})
	if err != nil {
		t.Fatal(err)
	}
	f := v.(*HTTPRangeFile)
	if heads != 1 || gets != 0 || f.Size() != int64(len(payload)) {
		t.Fatalf("discovery: HEAD=%d GET=%d size=%d", heads, gets, f.Size())
	}
	buf := make([]byte, 4)
	if _, err := f.ReadAt(buf, 1); err != nil || !bytes.Equal(buf, payload[1:5]) {
		t.Fatalf("range: %q %v", buf, err)
	}
	if gets != 1 {
		t.Fatalf("range requests=%d", gets)
	}
}

func TestHTTPRangeDiscoveryRejectsInvalidMetadata(t *testing.T) {
	for _, tc := range []struct {
		name, length, encoding string
		status                 int
	}{
		{"missing-size", "", "", 200}, {"empty", "0", "", 200},
		{"encoded", "10", "gzip", 200}, {"error", "10", "", 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.length != "" {
					w.Header().Set("Content-Length", tc.length)
				}
				if tc.encoding != "" {
					w.Header().Set("Content-Encoding", tc.encoding)
				}
				w.WriteHeader(tc.status)
			}))
			defer server.Close()
			pool, err := NewHTTPRangePool(8, 16, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Discover(context.Background(), "fixture", []string{server.URL}); err == nil {
				t.Fatal("accepted invalid discovery response")
			}
		})
	}
}

func TestParseHTTPContentRange(t *testing.T) {
	start, end, size, err := parseHTTPContentRange("bytes 4-7/12")
	if err != nil || start != 4 || end != 7 || size != 12 {
		t.Fatalf("range = %d-%d/%d, %v", start, end, size, err)
	}
	for _, value := range []string{"", "bytes 7-4/12", "bytes 4-12/12"} {
		if _, _, _, err := parseHTTPContentRange(value); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
}

func TestHTTPRangeFileRetriesTransientResponse(t *testing.T) {
	payload := []byte("abcdefgh")
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if requests < httpRangeAttempts {
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		writer.Header().Set("Content-Range", fmt.Sprintf("bytes 0-7/%d", len(payload)))
		writer.WriteHeader(http.StatusPartialContent)
		_, _ = writer.Write(payload)
	}))
	defer server.Close()
	file, err := NewHTTPRangeFile("retry", []string{server.URL}, int64(len(payload)), 8, 8, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len(payload))
	if _, err := file.ReadAt(buffer, 0); err != nil {
		t.Fatal(err)
	}
	if string(buffer) != string(payload) || requests != httpRangeAttempts {
		t.Fatalf("read %q after %d requests", buffer, requests)
	}
}
