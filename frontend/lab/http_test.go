package labfrontend

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tinyrange/trex/frontend/lab/ui"
	"github.com/tinyrange/trex/lab"
)

func TestBlankEditorAndTailnetAuthorization(t *testing.T) {
	extension := Extension{
		Recipes: []lab.Recipe{{ID: "example", Title: "Example OS", Module: "//example.star", Function: "start",
			Fields: []lab.Field{{Key: "software", Options: []lab.Option{{Value: "bundle", Label: "Bundle"}}}}}},
		SoftwareAliases:    []lab.SoftwareAlias{{ID: "editor", Title: "Editor", Package: "bundle"}},
		SoftwareReferences: []lab.SoftwareTitle{{ID: "other", Title: "Other", Targets: []lab.SoftwareTarget{{OS: "Example OS", Availability: "smoke"}}}},
	}
	r, err := extension.catalog()
	if err != nil {
		t.Fatal(err)
	}
	m := lab.NewManager(t.Context(), lab.Blank(), r, nil, nil, nil)
	app := httpApp{manager: m, catalog: r, software: lab.SoftwareLibrary(r, extension.SoftwareAliases, extension.SoftwareReferences), localHost: "127.0.0.1:7373", tailnetHost: "lab.test:9444", tailnetUser: "owner"}.handler(ui.Files)
	request := func(method, target, login, origin, body string, mutate bool) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req.Header.Set("Tailscale-User-Login", login)
		req.Header.Set("Origin", origin)
		if mutate {
			req.Header.Set("X-TinyRangeX", "lab")
		}
		w := httptest.NewRecorder()
		app.ServeHTTP(w, req)
		return w
	}
	for _, login := range []string{"", "another member"} {
		if w := request("GET", "https://lab.test:9444/api/lab", login, "", "", false); w.Code != http.StatusForbidden {
			t.Fatalf("unexpected unauthorized response: %d", w.Code)
		}
	}
	if w := request("GET", "https://lab.test:9444/", "owner", "", "", false); w.Code != 200 || !strings.Contains(w.Body.String(), "Virtual Lab Editor") {
		t.Fatal("the authorized proxy did not serve the editor")
	}
	software := request("GET", "https://lab.test:9444/api/software", "owner", "", "", false)
	var library struct {
		Software []lab.SoftwareTitle `json:"software"`
	}
	if err := json.NewDecoder(software.Body).Decode(&library); err != nil || software.Code != http.StatusOK {
		t.Fatalf("could not read the software library: %d %v", software.Code, err)
	}
	targets := make(map[string]lab.SoftwareTarget)
	for _, entry := range library.Software {
		if len(entry.Targets) == 1 {
			targets[entry.ID] = entry.Targets[0]
		}
	}
	if targets["editor"] != (lab.SoftwareTarget{OS: "Example OS", Availability: "lab", Via: "Bundle", Recipe: "example", Package: "bundle"}) ||
		targets["other"] != (lab.SoftwareTarget{OS: "Example OS", Availability: "smoke"}) {
		t.Fatalf("expected both preinstall and smoke targets: %+v", targets)
	}

	w := request("GET", "https://lab.test:9444/api/lab", "owner", "", "", false)
	var view lab.View
	if err := json.NewDecoder(w.Body).Decode(&view); err != nil || len(view.Definition.Nodes) != 0 || view.State != "idle" {
		t.Fatalf("expected a blank workspace: %+v %v", view, err)
	}
	for _, origin := range []string{"https://unexpected.test", "http://lab.test:9444"} {
		if w := request("POST", "https://lab.test:9444/api/stop", "owner", origin, "{}", true); w.Code != http.StatusForbidden {
			t.Fatalf("accepted changes from %s", origin)
		}
	}
	if w := request("POST", "https://lab.test:9444/api/stop", "owner", "https://lab.test:9444", "{}", false); w.Code != http.StatusForbidden {
		t.Fatal("accepted a request without the editor header")
	}
}

func TestMediaRootsRejectEscapes(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "private.iso")
	if err := os.WriteFile(outside, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "escape.iso")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	var library mediaLibrary
	if err := library.add("Original=" + dir); err != nil {
		t.Fatal(err)
	}
	defer library.close()
	for _, ref := range []string{"Original/escape.iso", "Original/../private.iso", outside} {
		if _, close, err := library.open(ref); err == nil {
			close()
			t.Fatalf("read escaped the media root: %q", ref)
		}
	}
}

func TestExtensionSpecializesGuestAndOwnsMediaDefaults(t *testing.T) {
	recipe := lab.Recipe{ID: "win101", Module: "//example.star", Function: "start",
		Media: []lab.Media{{Key: "system", Kind: "file"}}}
	extension := Extension{Recipes: []lab.Recipe{recipe}}
	catalog, err := extension.catalog()
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, entry := range catalog {
		if entry.ID != "win101" {
			continue
		}
		found++
		if entry.Module != recipe.Module || entry.Function != recipe.Function {
			t.Fatalf("unexpected implementation for Windows 1.01: %+v", entry)
		}
		entry.Media[0].Default = "Original/system.img"
	}
	if found != 1 || recipe.Media[0].Default != "" {
		t.Fatal("the extension must replace the built-in guest and keep caller-owned media unchanged")
	}
}
