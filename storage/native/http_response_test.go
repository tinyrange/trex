package native

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func responseValue(t *testing.T, d *starlark.Dict, name string) starlark.Value {
	t.Helper()
	v, found, err := d.Get(starlark.String(name))
	if err != nil || !found {
		t.Fatalf("missing %s: %v", name, err)
	}
	return v
}

func TestHTTPPostResponseStatusFramingAndTrailers(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "POST" || r.Header.Get("Content-Type") != "application/json" {
			t.Error("incorrect request")
		}
		w.Header().Add("X-Request-Id", "one")
		w.Header().Add("X-Request-Id", "two")
		switch r.URL.Path {
		case "/empty":
			w.Header().Set("Content-Length", "0")
			w.WriteHeader(500)
		case "/gzip":
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Trailer", "X-Error-Detail")
			w.WriteHeader(500)
			z := gzip.NewWriter(w)
			_, _ = z.Write([]byte("server diagnostic"))
			_ = z.Close()
			w.Header().Set("X-Error-Detail", "complete")
		case "/redirect":
			http.Redirect(w, r, "/empty", 307)
		case "/short":
			w.Header().Set("Content-Length", "30")
			w.WriteHeader(500)
			_, _ = w.Write([]byte("partial"))
		default:
			w.WriteHeader(500)
			_, _ = w.Write([]byte(strings.Repeat("x", 100)))
		}
	}))
	defer server.Close()
	for _, path := range []string{"/empty", "/gzip", "/redirect", "/short", "/large"} {
		before := calls
		limit := int64(64)
		if path == "/large" {
			limit = 7
		}
		d, err := httpPostJSONResponse(context.Background(), server.Client(), server.URL+path, []byte("{}"), limit)
		if err != nil {
			t.Fatal(err)
		}
		if calls != before+1 {
			t.Fatal("retried or followed redirect")
		}
		wantStatus := "500"
		if path == "/redirect" {
			wantStatus = "307"
		}
		if got := responseValue(t, d, "status_code").String(); got != wantStatus {
			t.Fatalf("status %s", got)
		}
		headers := responseValue(t, d, "headers").(*starlark.Dict)
		ids := responseValue(t, headers, "X-Request-Id").(*starlark.List)
		if ids.Len() != 2 {
			t.Fatal("lost repeated header values")
		}
		body := responseValue(t, d, "body").(*starfile.Bytes)
		switch path {
		case "/empty":
			if len(body.Data) != 0 || responseValue(t, d, "content_length").String() != "0" || responseValue(t, d, "complete") != starlark.True {
				t.Fatal("empty response not observed")
			}
		case "/gzip":
			if string(body.Data) != "server diagnostic" || responseValue(t, d, "uncompressed") != starlark.True {
				t.Fatal("gzip diagnostic lost")
			}
			trailers := responseValue(t, d, "trailers").(*starlark.Dict)
			if responseValue(t, trailers, "X-Error-Detail").(*starlark.List).Index(0) != starlark.String("complete") {
				t.Fatal("missing trailer")
			}
		case "/short":
			if string(body.Data) != "partial" || responseValue(t, d, "read_error") == starlark.String("") || responseValue(t, d, "complete") != starlark.False {
				t.Fatal("read error/partial data lost")
			}
		case "/large":
			if len(body.Data) != 7 || responseValue(t, d, "body_truncated") != starlark.True || responseValue(t, d, "complete") != starlark.False {
				t.Fatal("unbounded or hidden truncation")
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := calls
	if _, err := httpPostJSONResponse(ctx, server.Client(), server.URL, nil, 32); err == nil {
		t.Fatal("ignored cancellation")
	}
	if _, err := httpPostJSONResponse(context.Background(), server.Client(), server.URL, make([]byte, (1<<20)+1), 32); err == nil {
		t.Fatal("oversized request")
	}
	if calls != before {
		t.Fatal("sent rejected request")
	}
}

func TestHTTPPostResponseBuiltinOptInAndReadBound(t *testing.T) {
	b := &countedErrorBody{}
	client := &http.Client{Transport: errorBodyTransport{b}}
	d, err := httpPostJSONResponse(context.Background(), client, "https://example.invalid", nil, 7)
	if err != nil || b.reads != 8 || !b.closed {
		t.Fatalf("read bounds/close: %v %d %v", err, b.reads, b.closed)
	}
	if responseValue(t, d, "body_truncated") != starlark.True {
		t.Fatal("missing truncation")
	}
	if err := d.SetKey(starlark.String("status_code"), starlark.MakeInt(200)); err == nil {
		t.Fatal("mutable observation")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500); _, _ = io.WriteString(w, "detail") }))
	defer server.Close()
	args := starlark.Tuple{starlark.String(server.URL), starlark.String("{}")}
	kwargs := []starlark.Tuple{{starlark.String("response"), starlark.True}}
	v, err := starlark.Call(&starlark.Thread{Name: "http-response-test"}, Builtins()["http_post_json"], args, kwargs)
	if err != nil {
		t.Fatal(err)
	}
	if got := responseValue(t, v.(*starlark.Dict), "body").(*starfile.Bytes); string(got.Data) != "detail" {
		t.Fatal("missing diagnostic")
	}
	_, err = starlark.Call(&starlark.Thread{Name: "strict-http-test"}, Builtins()["http_post_json"], args, nil)
	if err == nil || !strings.Contains(fmt.Sprint(err), "HTTP status 500") {
		t.Fatal("default no longer strict")
	}
}
