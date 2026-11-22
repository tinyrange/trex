// Package web5250 serves a 5250 display to web browsers. The terminal model
// (package tn5250) stays owned by the caller's goroutine: the caller
// publishes screens with Publish and applies queued browser input with
// Apply, sending the returned bytes to the host. The package has no socket
// dependency; Server is an http.Handler.
//
// Protocol (JSON over HTTP; requests carry "Authorization: Bearer TOKEN"):
//
//	GET  /api/screen?after=V   waits up to 25 s for a screen newer than
//	                           version V and returns it
//	POST /api/input            {"records":N,"fields":{"3":"text"},
//	                            "row":R,"col":C,"key":"ENTER"}
//
// records names the screen the operator typed on; input for an older
// screen is discarded, as a locked keyboard would. Keys are ENTER, PF1 to
// PF24, ROLLUP, ROLLDOWN, HELP, PRINT, CLEAR, SYSREQ and ATTN.
package web5250

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tinyrange/trex/network/tn5250"
)

//go:embed index.html terminal.js terminal.css
var assets embed.FS

// Input is one operator action from a browser.
type Input struct {
	Records int            `json:"records"`
	Fields  map[int]string `json:"fields"`
	Row     int            `json:"row"`
	Col     int            `json:"col"`
	Key     string         `json:"key"`
}

// Server is the terminal page and its API for one display.
type Server struct {
	// Token authenticates API requests. The page receives it in the URL
	// fragment, which browsers do not send to the server.
	Token string
	// Notes is plain text shown beside the display (for example how to
	// sign on). It reaches the page only through the authenticated API.
	Notes   string
	mu      sync.Mutex
	screen  tn5250.Screen
	status  string
	version uint64
	changed chan struct{}
	inputs  []Input
	arrived chan struct{} // holds a token while input is queued
}

// New returns a server with a fresh random token.
func New() (*Server, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return &Server{Token: base64.RawURLEncoding.EncodeToString(b), changed: make(chan struct{}), arrived: make(chan struct{}, 1)}, nil
}

// Publish offers the current display and a short status line to viewers.
// Unchanged screens do not wake them.
func (s *Server) Publish(screen tn5250.Screen, status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.version != 0 && status == s.status && sameScreen(screen, s.screen) {
		return
	}
	s.screen, s.status = screen, status
	s.version++
	close(s.changed)
	s.changed = make(chan struct{})
}

func sameScreen(a, b tn5250.Screen) bool {
	return a.Records == b.Records && a.Inhibited == b.Inhibited && a.CursorRow == b.CursorRow && a.CursorColumn == b.CursorColumn &&
		slices.Equal(a.Rows, b.Rows) && slices.Equal(a.Attributes, b.Attributes) && slices.Equal(a.AttributeCell, b.AttributeCell) &&
		slices.Equal(a.Fields, b.Fields)
}

// Pending removes and returns the queued browser input, oldest first.
func (s *Server) Pending() []Input {
	s.mu.Lock()
	defer s.mu.Unlock()
	in := s.inputs
	s.inputs = nil
	select {
	case <-s.arrived:
	default:
	}
	return in
}

// Wait blocks for up to d or until browser input is queued, and reports
// whether input is pending. A machine loop uses it to let idle guest time
// pass in real time without delaying the operator.
func (s *Server) Wait(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-s.arrived:
		select { // keep the token for the next Wait until Pending drains
		case s.arrived <- struct{}{}:
		default:
		}
		return true
	case <-t.C:
		return false
	}
}

// AID bytes of the keys a viewer may press (SA21-9247).
var aids = map[string]byte{"ENTER": 0xf1, "ROLLDOWN": 0xf4, "ROLLUP": 0xf5, "HELP": 0xf3, "PRINT": 0xf6, "CLEAR": 0xbd}

func init() {
	for i := 1; i <= 12; i++ {
		aids["PF"+strconv.Itoa(i)] = 0x30 + byte(i)
		aids["PF"+strconv.Itoa(i+12)] = 0xb0 + byte(i)
	}
}

// Apply performs an input on the terminal and returns the bytes to send to
// the host (nil when the input was for an older screen or the host has
// cancelled input). Field text replaces the field as SetField does.
func Apply(t *tn5250.Terminal, in Input) ([]byte, error) {
	if in.Records != t.Records {
		return nil, nil
	}
	switch in.Key {
	case "SYSREQ":
		return t.SystemRequest(), nil
	case "ATTN":
		return t.Attention(), nil
	}
	aid, ok := aids[in.Key]
	if !ok {
		return nil, fmt.Errorf("web5250: unknown key %q", in.Key)
	}
	indexes := make([]int, 0, len(in.Fields))
	for i := range in.Fields {
		indexes = append(indexes, i)
	}
	slices.Sort(indexes)
	for _, i := range indexes {
		if err := t.SetField(i, in.Fields[i]); err != nil {
			return nil, err
		}
	}
	if in.Row != 0 || in.Col != 0 {
		if err := t.SetCursor(in.Row, in.Col); err != nil {
			return nil, err
		}
	}
	return t.Key(aid), nil
}

func (s *Server) authorized(r *http.Request) bool {
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	return got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(s.Token)) == 1
}

// sameOrigin rejects cross-site writes: a browser always sends Origin on
// POST, and it must name this server.
func sameOrigin(r *http.Request) bool {
	u, err := url.Parse(r.Header.Get("Origin"))
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

type screenJSON struct {
	Version   uint64      `json:"version"`
	Status    string      `json:"status"`
	Rows      []string    `json:"rows"`
	Attrs     string      `json:"attrs"` // hex, one byte per cell
	Cells     string      `json:"cells"` // '1' where a cell holds an attribute byte
	Fields    []fieldJSON `json:"fields"`
	Row       int         `json:"row"`
	Col       int         `json:"col"`
	Records   int         `json:"records"`
	Inhibited bool        `json:"inhibited"`
	Notes     string      `json:"notes"`
}

type fieldJSON struct {
	Index    int    `json:"index"`
	Row      int    `json:"row"`
	Col      int    `json:"col"`
	Length   int    `json:"length"`
	Attr     int    `json:"attr"`
	Text     string `json:"text"`
	Hidden   bool   `json:"hidden"`
	Bypass   bool   `json:"bypass"`
	Monocase bool   `json:"monocase"`
}

func (s *Server) snapshot() screenJSON {
	cells := make([]byte, len(s.screen.AttributeCell))
	for i, c := range s.screen.AttributeCell {
		cells[i] = '0'
		if c {
			cells[i] = '1'
		}
	}
	out := screenJSON{Version: s.version, Status: s.status, Rows: s.screen.Rows, Attrs: hex.EncodeToString(s.screen.Attributes),
		Cells: string(cells), Row: s.screen.CursorRow, Col: s.screen.CursorColumn, Records: s.screen.Records, Inhibited: s.screen.Inhibited,
		Fields: []fieldJSON{}, // a list even without input fields
		Notes:  s.Notes}
	for _, f := range s.screen.Fields {
		out.Fields = append(out.Fields, fieldJSON{f.Index, f.Row, f.Column, f.Length, int(f.Attribute), f.Text, f.Hidden, f.Bypass, f.Monocase})
	}
	return out
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	switch r.URL.Path {
	case "/", "/terminal.js", "/terminal.css":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "GET required", http.StatusMethodNotAllowed)
			return
		}
		name, typ := "index.html", "text/html; charset=utf-8"
		switch r.URL.Path {
		case "/terminal.js":
			name, typ = "terminal.js", "text/javascript; charset=utf-8"
		case "/terminal.css":
			name, typ = "terminal.css", "text/css; charset=utf-8"
		}
		b, _ := assets.ReadFile(name)
		h.Set("Content-Type", typ)
		_, _ = w.Write(b)
	case "/api/screen":
		if !s.authorized(r) {
			http.Error(w, "invalid session token", http.StatusForbidden)
			return
		}
		after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
		timeout := time.NewTimer(25 * time.Second)
		defer timeout.Stop()
		for {
			s.mu.Lock()
			if s.version > after {
				out := s.snapshot()
				s.mu.Unlock()
				h.Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(out)
				return
			}
			changed := s.changed
			s.mu.Unlock()
			select {
			case <-changed:
			case <-timeout.C:
				w.WriteHeader(http.StatusNoContent)
				return
			case <-r.Context().Done():
				return
			}
		}
	case "/api/input":
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		if !s.authorized(r) || !sameOrigin(r) {
			http.Error(w, "invalid session token or origin", http.StatusForbidden)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		var in Input
		if err == nil {
			err = json.Unmarshal(body, &in)
		}
		if err == nil {
			_, known := aids[in.Key]
			if !known && in.Key != "SYSREQ" && in.Key != "ATTN" {
				err = fmt.Errorf("unknown key %q", in.Key)
			}
		}
		if err != nil || len(in.Fields) > 256 {
			http.Error(w, "invalid input", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		if len(s.inputs) < 64 {
			s.inputs = append(s.inputs, in)
		}
		s.mu.Unlock()
		select {
		case s.arrived <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusAccepted)
	default:
		http.NotFound(w, r)
	}
}
