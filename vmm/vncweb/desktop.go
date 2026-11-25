package vncweb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"html"
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
	app      http.Handler
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

// NewDesktopApplication serves an application behind the desktop login. The
// application owns "/" and additional routes, while the desktop retains
// "/login", "/console", "/rfb", "/desktop.js", and "/client.js".
func NewDesktopApplication(workspace vmm.Workspace, password, origin string, app http.Handler) (*Desktop, error) {
	desktop, err := NewDesktop(workspace, password, origin)
	if err != nil {
		return nil, err
	}
	desktop.app = app
	return desktop, nil
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
			d.login(w, http.StatusOK, "")
		case http.MethodPost:
			if !d.console.ValidOrigin(r, false) {
				http.Error(w, "Reopen the launcher from your session link and sign in there.", http.StatusForbidden)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
			if err := r.ParseForm(); err != nil {
				d.login(w, http.StatusBadRequest, "Enter the session token and try again.")
				return
			}
			password := sha256.Sum256([]byte(r.PostForm.Get("token")))
			if subtle.ConstantTimeCompare(password[:], d.password[:]) != 1 {
				d.login(w, http.StatusForbidden, "That token did not match. Try the token for this session.")
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
	if d.app == nil && r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	cookie, err := r.Cookie(d.cookie)
	if err != nil || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(d.console.Token)) != 1 {
		if r.Method == http.MethodGet && r.URL.Path == "/" {
			w.Header().Set("Location", "login")
			w.WriteHeader(http.StatusSeeOther)
		} else {
			http.Error(w, "authentication required", http.StatusForbidden)
		}
		return
	}
	switch r.URL.Path {
	case "/console":
		if d.app == nil {
			http.NotFound(w, r)
			return
		}
	case "/rfb", "/desktop.js", "/client.js":
	default:
		if d.app != nil {
			if r.Method != http.MethodGet && r.Method != http.MethodHead && !d.console.ValidOrigin(r, false) {
				http.Error(w, "Reopen the launcher from your session link and try again.", http.StatusForbidden)
				return
			}
			w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-src 'self'; frame-ancestors 'self'; base-uri 'none'; form-action 'self'")
			w.Header().Set("Referrer-Policy", "same-origin")
			d.app.ServeHTTP(w, r)
			return
		}
	}
	if r.Method != http.MethodGet {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	switch r.URL.Path {
	case "/", "/console":
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

func (d *Desktop) login(w http.ResponseWriter, status int, message string) {
	// An origin is required on same-origin form posts, including retries.
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data, _ := assets.ReadFile("login.html")
	if message != "" {
		data = bytes.Replace(data, []byte("<!-- login message -->"), []byte(`<p role="alert">`+html.EscapeString(message)+`</p>`), 1)
	}
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

func (d *Desktop) asset(w http.ResponseWriter, name, contentType string) {
	w.Header().Set("Content-Type", contentType)
	data, _ := assets.ReadFile(name)
	_, _ = w.Write(data)
}
