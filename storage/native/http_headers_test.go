package native

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.starlark.net/starlark"
)

func TestHTTPHeadersOnWire(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		name := "http1"
		if h2 {
			name = "http2"
		}
		t.Run(name, func(t *testing.T) {
			seen := make(chan http.Header, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				seen <- r.Header.Clone()
				_, _ = w.Write([]byte("{}"))
			}))
			server.EnableHTTP2 = h2
			if h2 {
				server.StartTLS()
			} else {
				server.Start()
			}
			defer server.Close()
			values := starlark.NewDict(2)
			_ = values.SetKey(starlark.String("Accept"), starlark.String("*/*"))
			_ = values.SetKey(starlark.String("User-Agent"), starlark.String(""))
			headers, err := requestHeaders(values)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := httpPostJSONResponseHeaders(context.Background(), server.Client(), server.URL, []byte("{}"), 64, headers); err != nil {
				t.Fatal(err)
			}
			wire := <-seen
			if wire.Get("Accept") != "*/*" || wire.Get("Content-Type") != "application/json" {
				t.Fatalf("headers: %v", wire)
			}
			if _, exists := wire["User-Agent"]; exists {
				t.Fatal("empty UA should suppress default without sending an empty header")
			}
			if headers.Get("Content-Type") != "" {
				t.Fatal("mutated caller headers")
			}
			if !h2 {
				_, err := starlark.Call(&starlark.Thread{Name: "headers-test"}, Builtins()["http_post_json"], starlark.Tuple{starlark.String(server.URL), starlark.String("{}")}, []starlark.Tuple{{starlark.String("headers"), values}})
				if err != nil {
					t.Fatal(err)
				}
				wire = <-seen
				if wire.Get("Accept") != "*/*" {
					t.Fatal("builtin dropped caller header")
				}
				if _, exists := wire["User-Agent"]; exists {
					t.Fatal("builtin did not suppress UA")
				}
			}
		})
	}
}

func TestHTTPRequestHeaderValidation(t *testing.T) {
	for _, pair := range [][2]string{{"Bad Name", "x"}, {"X-Test", "a\r\nb"}, {"Host", "example.invalid"}, {"Content-Length", "0"}, {"Transfer-Encoding", "chunked"}, {"Connection", "close"}, {"Idempotency-Key", "x"}, {"X-Idempotency-Key", "x"}, {"Content-Type", "text/plain"}, {"", "x"}, {"X-Test", strings.Repeat("x", 64<<10)}} {
		d := starlark.NewDict(1)
		_ = d.SetKey(starlark.String(pair[0]), starlark.String(pair[1]))
		if _, err := requestHeaders(d); err == nil {
			t.Fatalf("accepted invalid header %q", pair[0])
		}
	}
	duplicates := starlark.NewDict(2)
	_ = duplicates.SetKey(starlark.String("Accept"), starlark.String("*/*"))
	_ = duplicates.SetKey(starlark.String("accept"), starlark.String("application/json"))
	if _, err := requestHeaders(duplicates); err == nil {
		t.Fatal("accepted duplicate field names")
	}
	wrong := starlark.NewDict(1)
	_ = wrong.SetKey(starlark.String("Accept"), starlark.None)
	if _, err := requestHeaders(wrong); err == nil {
		t.Fatal("accepted null value")
	}
	oversized := starlark.NewDict(65)
	for i := 0; i < 65; i++ {
		_ = oversized.SetKey(starlark.String(strings.Repeat("X", i+1)), starlark.String("v"))
	}
	if _, err := requestHeaders(oversized); err == nil {
		t.Fatal("unbounded field count")
	}
}
