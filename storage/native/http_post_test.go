package native

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPPostJSON(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "POST" || r.Header.Get("Content-Type") != "application/json" {
			t.Error("incorrect request")
		}
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"TargetingAttributes":{}}` {
			t.Errorf("body: %s", body)
		}
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/target", 307)
		case "/large":
			w.Write([]byte(strings.Repeat("x", 100)))
		case "/chunked":
			w.(http.Flusher).Flush()
			w.Write([]byte(strings.Repeat("x", 100)))
		default:
			w.Write([]byte(`{"ok":true}`))
		}
	}))
	defer server.Close()
	body := []byte(`{"TargetingAttributes":{}}`)
	f, err := HTTPPostJSON(context.Background(), server.Client(), server.URL, body, 32)
	if err != nil || string(f.Data) != `{"ok":true}` {
		t.Fatalf("response: %v %v", f, err)
	}
	for _, path := range []string{"/redirect", "/large", "/chunked"} {
		before := calls
		if _, err := HTTPPostJSON(context.Background(), server.Client(), server.URL+path, body, 32); err == nil {
			t.Fatal("accepted redirect or oversized response")
		}
		if calls != before+1 {
			t.Fatal("retried/followed redirect")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := HTTPPostJSON(ctx, server.Client(), server.URL, body, 32); err == nil {
		t.Fatal("ignored cancellation")
	}
	if _, err := HTTPPostJSON(context.Background(), server.Client(), server.URL, make([]byte, (1<<20)+1), 32); err == nil {
		t.Fatal("accepted oversized body")
	}
}
