package labfrontend

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tinyrange/trex/frontend/lab/ui"
	"github.com/tinyrange/trex/lab"
)

type testWebTransport func(*http.Request) (*http.Response, error)

func (t testWebTransport) RoundTrip(r *http.Request) (*http.Response, error) { return t(r) }

type testWebGuest struct{ surface lab.Surface }

const guestWebHost = "10.20.0.40:8080"

func (*testWebGuest) Close() error              { return nil }
func (g *testWebGuest) Surfaces() []lab.Surface { return []lab.Surface{g.surface} }

type testWebFactory struct{ transport http.RoundTripper }

func (f testWebFactory) Start(_ context.Context, r lab.StartRequest) (lab.Guest, error) {
	return &testWebGuest{surface: lab.Surface{ID: "web", Kind: "web", Web: &lab.WebSurface{
		Key: "key-" + r.Node.ID, Host: guestWebHost, Transport: f.transport,
	}}}, nil
}

func TestGuestWebProxyScopesRequestsToRunningSurface(t *testing.T) {
	var upstreamCalls int
	transport := testWebTransport(func(r *http.Request) (*http.Response, error) {
		upstreamCalls++
		if r.URL.Host != guestWebHost || r.URL.Scheme != "http" || r.Host != guestWebHost ||
			r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" ||
			r.Header.Get("X-TinyRangeX") != "" || r.Header.Get("Tailscale-User-Login") != "" {
			return nil, fmt.Errorf("unexpected guest request URL or headers")
		}
		h := http.Header{"Content-Type": {"text/html"}, "Set-Cookie": {"guest=1"}, "Content-Security-Policy": {"sandbox"}}
		var body string
		status := http.StatusOK
		switch r.URL.Path {
		case "/styles/v1/":
			body = `<link rel="stylesheet" href="/style.css"><a href="../hello?q=2#heading">Hello</a><form method="post" action="/send"></form>`
		case "/redirect":
			h.Set("Location", "/styles/v1/?from=guest")
			status = http.StatusFound
		case "/send":
			request, _ := io.ReadAll(r.Body)
			if r.Method != http.MethodPost || string(request) != "input=value" {
				return nil, fmt.Errorf("unexpected web form submission")
			}
			body = "Saved"
		default:
			return nil, fmt.Errorf("unexpected guest request path %q", r.URL.Path)
		}
		return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body))}, nil
	})
	definition := lab.Blank()
	definition.Nodes = []lab.Node{{ID: "one", Name: "One", Recipe: "web-server"}, {ID: "two", Name: "Two", Recipe: "web-server"}}
	manager := lab.NewManager(t.Context(), lab.Blank(), lab.Catalog(), testWebFactory{transport}, nil, nil)
	t.Cleanup(manager.Shutdown)
	if _, err := manager.Apply(definition); err != nil {
		t.Fatal(err)
	}
	wait := func(state string) {
		t.Helper()
		deadline := time.After(time.Second)
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for manager.View().State != state {
			select {
			case <-deadline:
				t.Fatalf("lab did not reach %s: %+v", state, manager.View())
			case <-tick.C:
			}
		}
	}
	wait("running")
	const origin = "https://lab.test:9444"
	app := httpApp{manager: manager, localHost: "127.0.0.1:7373", tailnetHost: "lab.test:9444", tailnetUser: "owner"}.handler(ui.Files)
	do := func(method, path, login, sourceOrigin, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, origin+path, strings.NewReader(body))
		r.Header.Set("Tailscale-User-Login", login)
		r.Header.Set("Origin", sourceOrigin)
		r.Header.Set("Cookie", "private=1")
		r.Header.Set("Authorization", "Bearer private")
		w := httptest.NewRecorder()
		app.ServeHTTP(w, r)
		return w
	}
	const launch = "/api/nodes/one/surfaces/web/browse/"
	const entry = launch + "key-one/"
	const session = "/api/nodes/one/surfaces/web/browse-session"
	if w := do("GET", session, "owner", origin, ""); w.Code != http.StatusOK ||
		!strings.Contains(w.Body.String(), `"base":"`+entry+`"`) ||
		!strings.Contains(w.Body.String(), `"address":"http://`+guestWebHost+`/"`) {
		t.Fatalf("guest session: %d %q", w.Code, w.Body.String())
	}
	if w := do("GET", launch, "owner", "", ""); w.Code != http.StatusTemporaryRedirect || w.Header().Get("Location") != entry {
		t.Fatalf("guest launch: %d, %q", w.Code, w.Header().Get("Location"))
	}
	w := do("GET", entry+"styles/v1/", "owner", "null", "")
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, entry+"style.css") || !strings.Contains(body, entry+"styles/hello?q=2#heading") ||
		!strings.Contains(body, entry+"send") || !strings.Contains(body, `report("lab-web-location", location)`) ||
		w.Header().Get("Set-Cookie") != "" || w.Header().Get("Access-Control-Allow-Origin") != "null" ||
		!strings.Contains(w.Header().Get("Content-Security-Policy"), "sandbox allow-scripts allow-forms") ||
		strings.Contains(w.Header().Get("Content-Security-Policy"), "allow-same-origin") {
		t.Fatalf("guest response: %d %v %q", w.Code, w.Header(), body)
	}
	if w := do("GET", entry+"redirect", "owner", "", ""); w.Code != http.StatusFound || w.Header().Get("Location") != entry+"styles/v1/?from=guest" {
		t.Fatalf("guest redirect: %d %v", w.Code, w.Header())
	}
	if w := do("POST", entry+"send", "owner", "null", "input=value"); w.Code != http.StatusOK || !strings.HasPrefix(w.Body.String(), "Saved<script>") {
		t.Fatalf("opaque-frame form: %d %q", w.Code, w.Body.String())
	}
	for _, check := range []struct {
		method, path, login, origin string
		status                      int
	}{
		{"GET", strings.Replace(entry, "/one/", "/two/", 1), "owner", "", http.StatusNotFound},
		{"GET", entry, "other", "", http.StatusForbidden},
		{"GET", entry, "owner", "https://other.test", http.StatusForbidden},
		{"GET", session, "owner", "null", http.StatusForbidden},
		{"GET", session, "other", "", http.StatusForbidden},
		{"POST", "/api/stop", "owner", "null", http.StatusForbidden},
	} {
		if w := do(check.method, check.path, check.login, check.origin, ""); w.Code != check.status {
			t.Errorf("%s %s: got %d, want %d", check.method, check.path, w.Code, check.status)
		}
	}
	manager.Stop()
	wait("idle")
	if w := do("GET", session, "owner", origin, ""); w.Code != http.StatusNotFound {
		t.Fatalf("stopped surface session: got %d", w.Code)
	}
	if w := do("GET", entry, "owner", "", ""); w.Code != http.StatusNotFound || upstreamCalls != 3 {
		t.Fatalf("stopped surface: got %d and %d upstream calls", w.Code, upstreamCalls)
	}
}
