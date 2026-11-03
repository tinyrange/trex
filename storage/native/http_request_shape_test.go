package native

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	starjson "github.com/tinyrange/trex/script/json"
	"go.starlark.net/starlark"
)

// Exercise the actual Starlark encoder and HTTP sender together. In particular,
// absent, null and empty-string properties must never be conflated or injected.
func TestHTTPJSONRequestShapePreserved(t *testing.T) {
	for _, http2 := range []bool{false, true} {
		name := "http1"
		if http2 {
			name = "http2"
		}
		t.Run(name, func(t *testing.T) {
			type received struct {
				data        []byte
				length      int64
				protocol    int
				contentType string
			}
			seen := make(chan received, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				seen <- received{body, r.ContentLength, r.ProtoMajor, r.Header.Get("Content-Type")}
				_, _ = w.Write([]byte("{}"))
			}))
			server.EnableHTTP2 = http2
			if http2 {
				server.StartTLS()
			} else {
				server.Start()
			}
			defer server.Close()
			for _, variant := range []string{"absent", "empty", "null"} {
				input := starlark.NewDict(3)
				_ = input.SetKey(starlark.String("Products"), starlark.String("PN=Example.Client&V=1.2.3.4"))
				_ = input.SetKey(starlark.String("DeviceAttributes"), starlark.String("App=Setup360;OSArchitecture=amd64"))
				if variant == "empty" {
					_ = input.SetKey(starlark.String("Optional"), starlark.String(""))
				}
				if variant == "null" {
					_ = input.SetKey(starlark.String("Optional"), starlark.None)
				}
				encoded, err := starlark.Call(&starlark.Thread{Name: "request-shape"}, starjson.Builtins()["encode"], starlark.Tuple{input}, nil)
				if err != nil {
					t.Fatal(err)
				}
				body := string(encoded.(starlark.String))
				if _, err := httpPostJSONResponse(context.Background(), server.Client(), server.URL, []byte(body), 64); err != nil {
					t.Fatal(err)
				}
				got := <-seen
				wantProtocol := 1
				if http2 {
					wantProtocol = 2
				}
				if string(got.data) != body || got.length != int64(len(body)) || got.protocol != wantProtocol || got.contentType != "application/json" {
					t.Fatalf("wire mismatch: %+v", got)
				}
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(got.data, &fields); err != nil {
					t.Fatal(err)
				}
				optional, present := fields["Optional"]
				if variant == "absent" && (present || len(fields) != 2) {
					t.Fatal("absent property was injected")
				}
				if variant == "empty" && string(optional) != `""` {
					t.Fatal("empty property changed")
				}
				if variant == "null" && string(optional) != "null" {
					t.Fatal("null property changed")
				}
				var attributes string
				if err := json.Unmarshal(fields["DeviceAttributes"], &attributes); err != nil || attributes != "App=Setup360;OSArchitecture=amd64" {
					t.Fatal("nested attribute string changed")
				}
			}
		})
	}
}
