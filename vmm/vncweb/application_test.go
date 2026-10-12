package vncweb

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestScriptedApplicationAuthenticationAndProxyOrigin(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(202) })
	app, err := NewApplication(singleWorkspace{displayStub{}}, handler, []string{"/", "/app.js"}, "")
	if err != nil {
		t.Fatal(err)
	}
	request := func(app *Application, method, path, token, origin string, forwarded bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://local.test"+path, nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if forwarded {
			r.Header.Set("X-Forwarded-Proto", "https")
			r.Header.Set("X-Forwarded-Host", "desktop.example.ts.net")
		}
		rec := httptest.NewRecorder()
		app.ServeHTTP(rec, r)
		return rec
	}
	for _, tc := range []struct {
		method, path, token, origin string
		code                        int
	}{
		{"GET", "/", "", "", 202},
		{"GET", "/app.js", "", "", 202},
		{"POST", "/", "", "http://local.test", 403},
		{"GET", "/api/archive/?token=" + app.Console.Token, "", "", 403},
		{"GET", "/api/os", "wrong", "", 403},
		{"GET", "/api/os", app.Console.Token, "", 202},
		{"GET", "/api/os", app.Console.Token, "http://evil.test", 403},
		{"POST", "/api/os/test/start", app.Console.Token, "", 403},
		{"POST", "/api/os/test/start", app.Console.Token, "http://local.test", 202},
		{"GET", "/console/client.js", "", "", 200},
		{"GET", "/console/rfb?vm=1", "", "http://local.test", 403},
		{"GET", "/console/rfb?vm=1&token=" + app.Console.Token, "", "http://local.test", 400},
	} {
		if got := request(app, tc.method, tc.path, tc.token, tc.origin, false).Code; got != tc.code {
			t.Fatalf("%s %s: %d, want %d", tc.method, tc.path, got, tc.code)
		}
	}
	external := "https://desktop.example.ts.net"
	if got := request(app, "POST", "/api/os/test/start", app.Console.Token, external, true).Code; got != 403 {
		t.Fatal("forwarded headers bypassed same-origin checks")
	}
	proxy, err := NewApplication(singleWorkspace{displayStub{}}, handler, []string{"/"}, external)
	if err != nil {
		t.Fatal(err)
	}
	if got := request(proxy, "POST", "/api/os/test/start", proxy.Console.Token, external, true).Code; got != 202 {
		t.Fatal(got)
	}
	if got := request(proxy, "POST", "/api/os/test/start", proxy.Console.Token, "http://desktop.example.ts.net", true).Code; got != 403 {
		t.Fatal(got)
	}
	// RFB validates the same explicitly configured origin after prefix routing.
	if got := request(proxy, "GET", "/console/rfb?vm=1&token="+proxy.Console.Token, "", external, true).Code; got != 400 {
		t.Fatal(got)
	}
	if body := request(app, "GET", "/console/client.js", "", "", false).Body.String(); !strings.Contains(body, "export class RFB") {
		t.Fatal("existing console client not mounted")
	}
	for _, origin := range []string{"http://desktop.example.ts.net", external + "/path", external + "?", external + "#x", "https://user@desktop.example.ts.net"} {
		if _, err := NewApplication(singleWorkspace{displayStub{}}, handler, nil, origin); err == nil {
			t.Fatalf("accepted bad external origin %q", origin)
		}
	}
	for _, public := range []string{"/api/../os", "/console/rfb", "//example.com", "/app?x"} {
		if _, err := NewApplication(singleWorkspace{displayStub{}}, handler, []string{public}, ""); err == nil {
			t.Fatalf("accepted unsafe public path %q", public)
		}
	}
}
