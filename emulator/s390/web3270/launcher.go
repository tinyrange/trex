package web3270

import (
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
)

//go:embed launcher.html launcher.js launcher.css
var launcherAssets embed.FS

// SystemInfo describes one launchable system for the launcher page.
type SystemInfo struct {
	Name        string   `json:"name"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	State       string   `json:"state"` // stopped, starting, running, stopping, failed
	Error       string   `json:"error,omitempty"`
	Log         []string `json:"log"`
	TN3270      string   `json:"tn3270,omitempty"`
	Saves       bool     `json:"saves"`    // has a state file
	HasState    bool     `json:"hasState"` // a saved state exists
	Snapshots   []string `json:"snapshots,omitempty"`
	Since       string   `json:"since,omitempty"`
}

// System is a machine the launcher can start and stop. Implementations
// own process concerns (scripts, files, listeners); the launcher only
// serves the page and routes requests.
type System interface {
	Info() SystemInfo
	// Start starts the machine, from the named snapshot when snapshot is
	// not empty.
	Start(snapshot string) error
	// Stop stops the machine, saving its state first when save is set.
	Stop(save bool) error
	// Consoles serves the running machine's console page and API, or is
	// nil while it is not running.
	Consoles() http.Handler
}

// Launcher is an http.Handler for a page listing systems, with start and
// stop controls, and each running system's consoles under /s/NAME/.
type Launcher struct {
	systems []System
	// Token authenticates the API and every system's consoles.
	Token string
}

// NewLauncher returns a launcher for systems.
func NewLauncher(systems []System) (*Launcher, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return &Launcher{systems: systems, Token: base64.RawURLEncoding.EncodeToString(b)}, nil
}

func (l *Launcher) find(name string) System {
	for _, s := range l.systems {
		if s.Info().Name == name {
			return s
		}
	}
	return nil
}

func (l *Launcher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	if rest, ok := strings.CutPrefix(r.URL.Path, "/s/"); ok {
		name, _, _ := strings.Cut(rest, "/")
		sys := l.find(name)
		if sys == nil {
			http.NotFound(w, r)
			return
		}
		if !strings.HasPrefix(rest, name+"/") {
			http.Redirect(w, r, "/s/"+name+"/", http.StatusFound)
			return
		}
		consoles := sys.Consoles()
		if consoles == nil {
			http.Error(w, name+" is not running", http.StatusServiceUnavailable)
			return
		}
		http.StripPrefix("/s/"+name, consoles).ServeHTTP(w, r)
		return
	}
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	switch r.URL.Path {
	case "/", "/launcher.js", "/launcher.css":
		name, typ := "launcher.html", "text/html; charset=utf-8"
		switch r.URL.Path {
		case "/launcher.js":
			name, typ = "launcher.js", "text/javascript; charset=utf-8"
		case "/launcher.css":
			name, typ = "launcher.css", "text/css; charset=utf-8"
		}
		b, _ := launcherAssets.ReadFile(name)
		h.Set("Content-Type", typ)
		_, _ = w.Write(b)
		return
	}
	rest, ok := strings.CutPrefix(r.URL.Path, "/api/systems")
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !(&Server{Token: l.Token}).authorized(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")) {
		http.Error(w, "invalid session token", http.StatusForbidden)
		return
	}
	if rest == "" && r.Method == http.MethodGet {
		list := make([]SystemInfo, 0, len(l.systems))
		for _, s := range l.systems {
			list = append(list, s.Info())
		}
		h.Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"systems": list})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if !(&Server{}).validOrigin(r) {
		http.Error(w, "origin mismatch", http.StatusForbidden)
		return
	}
	name, action, _ := strings.Cut(strings.TrimPrefix(rest, "/"), "/")
	sys := l.find(name)
	if sys == nil {
		http.NotFound(w, r)
		return
	}
	var err error
	switch action {
	case "start":
		err = sys.Start(r.URL.Query().Get("snapshot"))
	case "stop":
		err = sys.Stop(r.URL.Query().Get("save") == "1")
	default:
		http.NotFound(w, r)
		return
	}
	h.Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(sys.Info())
}
