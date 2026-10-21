package vncweb

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net/http"
	"sync"

	"github.com/tinyrange/trex/vmm"
)

// Desktop serves a password-authenticated, canvas-only console. Mount it at a
// trailing-slash URL, stripping any backend prefix. All browser URLs are relative
// so a reverse proxy may strip or preserve its external prefix. Close and join
// the handler before releasing the workspace's displays.
type Desktop struct {
	console  *Server
	password [32]byte
	cookie   string
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	closed   bool
	handlers sync.WaitGroup
}

// NewDesktop accepts an arbitrary nonempty password. origin is empty for direct
// same-origin HTTP(S), or an explicit external HTTPS origin behind a proxy.
// Forwarded headers are intentionally not trusted. Use HTTPS on untrusted links.
func NewDesktop(workspace vmm.Workspace, password, origin string) (*Desktop, error) {
	if password == "" {
		return nil, fmt.Errorf("desktop password is required")
	}
	console, err := NewWorkspace(workspace)
	if err != nil {
		return nil, err
	}
	if err := console.setPublicOrigin(origin); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Desktop{console: console, password: sha256.Sum256([]byte(password)), cookie: "trex-session-" + console.Token[:12], ctx: ctx, cancel: cancel}, nil
}

// Close cancels and joins all handlers, including hijacked WebSockets which
// net/http.Server.Shutdown does not own. Close the HTTP server first to unblock
// ordinary request-body reads. It is safe to call more than once.
func (d *Desktop) Close() error {
	d.mu.Lock()
	d.closed = true
	d.cancel()
	d.mu.Unlock()
	d.handlers.Wait()
	return nil
}

func (d *Desktop) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		http.Error(w, "session closed", http.StatusServiceUnavailable)
		return
	}
	d.handlers.Add(1)
	d.mu.Unlock()
	defer d.handlers.Done()
	ctx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(d.ctx, cancel)
	defer func() { stop(); cancel() }()
	r = r.WithContext(ctx)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'self'; base-uri 'none'; form-action 'self'")
	if r.URL.Path == "/login" {
		switch r.Method {
		case http.MethodGet:
			// Fetch serializes Origin as null for non-CORS form POSTs from a
			// no-referrer document. Preserve the origin for our same-origin
			// form without sending referrers to other origins. Never accept
			// Origin: null as a workaround: opaque origins are untrusted.
			w.Header().Set("Referrer-Policy", "same-origin")
			d.asset(w, "login.html", "text/html; charset=utf-8")
		case http.MethodPost:
			if !d.console.ValidOrigin(r, false) {
				http.Error(w, "origin mismatch", http.StatusForbidden)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
			if err := r.ParseForm(); err != nil {
				http.Error(w, "invalid login form", http.StatusBadRequest)
				return
			}
			password := sha256.Sum256([]byte(r.PostForm.Get("token")))
			if subtle.ConstantTimeCompare(password[:], d.password[:]) != 1 {
				http.Error(w, "invalid password", http.StatusForbidden)
				return
			}
			// Omitting Path scopes the cookie to the browser-visible login directory,
			// including a prefix stripped by a reverse proxy. No credential enters URLs.
			http.SetCookie(w, &http.Cookie{Name: d.cookie, Value: d.console.Token, HttpOnly: true, Secure: r.TLS != nil || d.console.publicOrigin != "", SameSite: http.SameSiteStrictMode})
			w.Header().Set("Location", "./")
			w.WriteHeader(http.StatusSeeOther)
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	cookie, err := r.Cookie(d.cookie)
	if err != nil || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(d.console.Token)) != 1 {
		if r.URL.Path == "/" {
			w.Header().Set("Location", "login")
			w.WriteHeader(http.StatusSeeOther)
		} else {
			http.Error(w, "authentication required", http.StatusForbidden)
		}
		return
	}
	switch r.URL.Path {
	case "/":
		d.asset(w, "desktop.html", "text/html; charset=utf-8")
	case "/desktop.js":
		d.asset(w, "desktop.js", "text/javascript; charset=utf-8")
	case "/client.js":
		d.asset(w, "client.js", "text/javascript; charset=utf-8")
	case "/rfb":
		// Authenticate only by the scoped HttpOnly cookie, never caller query tokens.
		// The reusable console still enforces Origin and one controller per VM.
		clone := r.Clone(ctx)
		query := clone.URL.Query()
		query.Set("token", d.console.Token)
		clone.URL.RawQuery = query.Encode()
		d.console.ServeHTTP(w, clone)
	default:
		http.NotFound(w, r)
	}
}
func (d *Desktop) asset(w http.ResponseWriter, name, contentType string) {
	w.Header().Set("Content-Type", contentType)
	data, _ := assets.ReadFile(name)
	_, _ = w.Write(data)
}
