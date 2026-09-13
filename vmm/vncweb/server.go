package vncweb

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/tinyrange/trex/vmm"
	"github.com/tinyrange/trex/vmm/rfb"
)

//go:embed index.html client.js app.js
var assets embed.FS

// Server serves a self-contained client and one controlling RFB connection.
// Token is delivered in the page URL fragment, which HTTP requests omit.
type Server struct {
	display vmm.DisplaySource
	Token   string
	busy    atomic.Bool
}

func New(display vmm.DisplaySource) (*Server, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return &Server{display: display, Token: base64.RawURLEncoding.EncodeToString(b)}, nil
}
func tokenHeader(value, want string) bool {
	for _, part := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), want) {
			return true
		}
	}
	return false
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
	if r.Method != "GET" {
		http.Error(w, "GET required", 405)
		return
	}
	if r.URL.Path != "/rfb" {
		name := "index.html"
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		case "/client.js", "/app.js":
			name = strings.TrimPrefix(r.URL.Path, "/")
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		default:
			http.NotFound(w, r)
			return
		}
		b, _ := assets.ReadFile(name)
		_, _ = w.Write(b)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("token")), []byte(s.Token)) != 1 {
		http.Error(w, "invalid session token", 403)
		return
	}
	origin, err := url.Parse(r.Header.Get("Origin"))
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if err != nil || origin.Scheme != scheme || !strings.EqualFold(origin.Host, r.Host) || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" || origin.User != nil {
		http.Error(w, "origin mismatch", 403)
		return
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	decoded, err := base64.StdEncoding.DecodeString(key)
	if !tokenHeader(r.Header.Get("Connection"), "upgrade") || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || r.Header.Get("Sec-WebSocket-Version") != "13" || err != nil || len(decoded) != 16 {
		http.Error(w, "invalid WebSocket handshake", 400)
		return
	}
	if !s.busy.CompareAndSwap(false, true) {
		http.Error(w, "VM already has a controller", 409)
		return
	}
	defer s.busy.Store(false)
	h, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unavailable", 500)
		return
	}
	conn, rw, err := h.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if _, err = fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:])); err != nil {
		return
	}
	if err = rw.Flush(); err != nil {
		return
	}
	_ = rfb.Serve(r.Context(), &websocket{Conn: conn, r: rw.Reader}, s.display)
}
