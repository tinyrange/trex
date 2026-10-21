package native

import (
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPGetBoundedSequentialAndEncoded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.Header.Get("Range") != "" {
			t.Error("not a sequential GET")
		}
		switch r.URL.Path {
		case "/gzip":
			w.Header().Set("Content-Encoding", "gzip")
			z := gzip.NewWriter(w)
			_, _ = z.Write([]byte(strings.Repeat("x", 100)))
			_ = z.Close()
		case "/chunked":
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			_, _ = w.Write([]byte(strings.Repeat("x", 100)))
		case "/bad":
			http.Error(w, "unavailable", 503)
		default:
			_, _ = w.Write([]byte("metadata"))
		}
	}))
	defer server.Close()
	for _, path := range []string{"/", "/gzip", "/chunked"} {
		file, err := HTTPGet(context.Background(), server.Client(), server.URL+path, 100)
		if err != nil {
			t.Fatal(err)
		}
		want := int64(100)
		if path == "/" {
			want = 8
		}
		if file.Size() != want {
			t.Fatalf("%s: %d bytes", path, file.Size())
		}
	}
	for _, path := range []string{"/", "/gzip", "/chunked", "/bad"} {
		if _, err := HTTPGet(context.Background(), server.Client(), server.URL+path, 7); err == nil {
			t.Fatalf("accepted %s beyond limit or status", path)
		}
	}
	for _, url := range []string{"file:///etc/passwd", "https://", "not-a-url"} {
		if _, err := HTTPGet(context.Background(), server.Client(), url, 100); err == nil {
			t.Fatal("accepted invalid URL")
		}
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if _, err := HTTPGet(ctx, server.Client(), server.URL, 100); err == nil {
		t.Fatal("ignored cancelled context")
	}
}
