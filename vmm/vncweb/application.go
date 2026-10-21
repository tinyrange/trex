package vncweb

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/tinyrange/trex/vmm"
)

// Application attaches a console workspace to an authenticated scripted web app.
// UI assets and policy remain in the script, not in the embedded VM viewer.
type Application struct {
	Console *Server
	handler http.Handler
	public  map[string]bool
}

func NewApplication(workspace vmm.Workspace, handler http.Handler, public []string, origin string) (*Application, error) {
	console, err := NewWorkspace(workspace)
	if err != nil {
		return nil, err
	}
	if err := console.setPublicOrigin(origin); err != nil {
		return nil, err
	}
	app := &Application{Console: console, handler: handler, public: make(map[string]bool)}
	for _, name := range public {
		if !strings.HasPrefix(name, "/") || path.Clean(name) != name || strings.ContainsAny(name, "?#\\") || name == "/console" || strings.HasPrefix(name, "/console/") {
			return nil, fmt.Errorf("invalid public application path %q", name)
		}
		app.public[name] = true
	}
	return app, nil
}

func (s *Server) ValidOrigin(r *http.Request, allowMissing bool) bool {
	value := r.Header.Get("Origin")
	if value == "" {
		return allowMissing
	}
	u, err := url.Parse(value)
	if err != nil || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || u.Opaque != "" {
		return false
	}
	if s.publicOrigin != "" {
		return value == s.publicOrigin
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return u.Scheme == scheme && strings.EqualFold(u.Host, r.Host)
}
func (a *Application) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	// Only the reusable client and authenticated RFB endpoint are mounted.
	// The built-in viewer and factory API remain separate, backwards-compatible.
	if r.URL.Path == "/console/client.js" || r.URL.Path == "/console/rfb" {
		http.StripPrefix("/console", a.Console).ServeHTTP(w, r)
		return
	}
	if !a.public[r.URL.Path] || r.Method != "GET" && r.Method != "HEAD" {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(token), []byte(a.Console.Token)) != 1 {
			http.Error(w, "invalid session token", http.StatusForbidden)
			return
		}
		if !a.Console.ValidOrigin(r, r.Method == "GET" || r.Method == "HEAD") {
			http.Error(w, "origin mismatch", http.StatusForbidden)
			return
		}
	}
	a.handler.ServeHTTP(w, r)
}

func (s *Server) setPublicOrigin(origin string) error {
	if origin != "" {
		u, err := url.Parse(origin)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || u.Opaque != "" {
			return fmt.Errorf("console origin must be an HTTPS origin without path, credentials, query or fragment")
		}
		s.publicOrigin = origin
	}
	return nil
}
