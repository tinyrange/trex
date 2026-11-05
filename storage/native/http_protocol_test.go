package native

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestHTTPVersionPinningPreservesTLSAndDefaults(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if string(body) != "{}" {
			t.Error("request body changed")
		}
		_, _ = w.Write([]byte("{}"))
	}))
	server.EnableHTTP2 = true
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	original := server.Client()
	// Initialize the standard transport before checking that our pin leaves
	// its established HTTP/2 configuration intact (Clone may initialize it).
	initial, err := httpPostJSONResponse(context.Background(), original, server.URL, []byte("{}"), 64)
	if err != nil || responseValue(t, initial, "protocol").String() != `"HTTP/2.0"` {
		t.Fatalf("HTTP/2 control failed: %v", err)
	}
	base := original.Transport.(*http.Transport)
	beforeALPN := append([]string(nil), base.TLSClientConfig.NextProtos...)
	forced, err := httpClientVersion(original, "1.1")
	if err != nil {
		t.Fatal(err)
	}
	defer forced.CloseIdleConnections()
	pinned := forced.Transport.(*http.Transport)
	if pinned == base || pinned.TLSClientConfig == base.TLSClientConfig || pinned.TLSClientConfig.RootCAs != base.TLSClientConfig.RootCAs || pinned.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("pin mutated/shared TLS configuration or bypassed trust")
	}
	if !reflect.DeepEqual(base.TLSClientConfig.NextProtos, beforeALPN) {
		t.Fatal("mutated original ALPN")
	}
	for _, tc := range []struct {
		client         *http.Client
		protocol, alpn string
	}{
		{forced, "HTTP/1.1", "http/1.1"}, {original, "HTTP/2.0", "h2"},
	} {
		d, err := httpPostJSONResponse(context.Background(), tc.client, server.URL, []byte("{}"), 64)
		if err != nil {
			t.Fatal(err)
		}
		if responseValue(t, d, "protocol").String() != `"`+tc.protocol+`"` || (responseValue(t, d, "tls_alpn").String() != `"`+tc.alpn+`"` && !(tc.protocol == "HTTP/1.1" && responseValue(t, d, "tls_alpn").String() == `""`)) {
			t.Fatalf("did not select %s: %v", tc.protocol, d)
		}
	}
	untrusted, err := httpClientVersion(&http.Client{}, "1.1")
	if err != nil {
		t.Fatal(err)
	}
	defer untrusted.CloseIdleConnections()
	if _, err := httpPostJSONResponse(context.Background(), untrusted, server.URL, []byte("{}"), 64); err == nil {
		t.Fatal("pin bypassed certificate verification")
	}
	if _, err := httpClientVersion(original, "2"); err == nil {
		t.Fatal("accepted unsupported version")
	}
	auto, err := httpClientVersion(original, "auto")
	if err != nil || auto != original {
		t.Fatal("changed default transport")
	}
}
