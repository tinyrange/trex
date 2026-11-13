package web3270

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeSystem struct {
	info    SystemInfo
	console http.Handler
	saved   bool
}

func (f *fakeSystem) Info() SystemInfo { return f.info }
func (f *fakeSystem) Start(string) error {
	f.info.State = "running"
	f.console = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "console "+r.URL.Path) })
	return nil
}
func (f *fakeSystem) Stop(save bool) error {
	f.info.State, f.console, f.saved = "stopped", nil, save
	return nil
}
func (f *fakeSystem) Consoles() http.Handler { return f.console }

func TestLauncherStartsStopsAndMountsConsoles(t *testing.T) {
	sys := &fakeSystem{info: SystemInfo{Name: "vm370", Title: "VM/370", State: "stopped"}}
	l, err := NewLauncher([]System{sys})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(l)
	defer srv.Close()
	do := func(method, path string, auth, origin bool) (*http.Response, string) {
		req, _ := http.NewRequest(method, srv.URL+path, nil)
		if auth {
			req.Header.Set("Authorization", "Bearer "+l.Token)
		}
		if origin {
			req.Header.Set("Origin", srv.URL)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, string(b)
	}
	if resp, body := do("GET", "/", false, false); resp.StatusCode != 200 || !strings.Contains(body, "launcher.js") {
		t.Fatalf("page %d", resp.StatusCode)
	}
	if resp, _ := do("GET", "/api/systems", false, false); resp.StatusCode != 403 {
		t.Fatalf("unauthenticated list %d", resp.StatusCode)
	}
	resp, body := do("GET", "/api/systems", true, false)
	var list struct{ Systems []SystemInfo }
	json.Unmarshal([]byte(body), &list)
	if resp.StatusCode != 200 || len(list.Systems) != 1 || list.Systems[0].State != "stopped" {
		t.Fatalf("list %d %s", resp.StatusCode, body)
	}
	if resp, _ := do("GET", "/s/vm370/", false, false); resp.StatusCode != 503 {
		t.Fatalf("consoles of a stopped system: %d", resp.StatusCode)
	}
	if resp, _ := do("POST", "/api/systems/vm370/start", true, false); resp.StatusCode != 403 {
		t.Fatalf("start without origin: %d", resp.StatusCode)
	}
	if resp, _ := do("POST", "/api/systems/vm370/start", true, true); resp.StatusCode != 200 || sys.info.State != "running" {
		t.Fatalf("start %d", resp.StatusCode)
	}
	if _, body := do("GET", "/s/vm370/ws?x=1", false, false); body != "console /ws" {
		t.Fatalf("mounted console saw %q", body)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	r, _ := client.Get(srv.URL + "/s/vm370")
	if r.StatusCode != http.StatusFound || r.Header.Get("Location") != "/s/vm370/" {
		t.Fatalf("redirect %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	if resp, _ := do("POST", "/api/systems/vm370/stop?save=1", true, true); resp.StatusCode != 200 || !sys.saved || sys.info.State != "stopped" {
		t.Fatalf("stop %d saved %v", resp.StatusCode, sys.saved)
	}
	if resp, _ := do("POST", "/api/systems/nope/start", true, true); resp.StatusCode != 404 {
		t.Fatalf("unknown system %d", resp.StatusCode)
	}
}
