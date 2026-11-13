// Package web3270 serves the consoles of a running ESA/390 or System/370
// machine to web browsers: 3270 display stations and line-mode consoles
// (3215 printer-keyboards and the hardware system console). Each console is
// streamed over a WebSocket as JSON messages; the browser sends input back
// and the device models in package s390 remain the only console state. It
// is independent of the RFB display server.
//
// Protocol (text messages, JSON). For a 3270 display station:
//
//	server → client
//	  {"type":"screen","name":"0701","rows":24,"cols":80,"cursor":N,
//	   "locked":bool,"insert":bool,"status":"running",
//	   "text":"…","attr":"…","color":"…","hilite":"…"}
//	  {"type":"inhibit","reason":"protected"}
//	client → server
//	  {"type":"text","text":"LOGON IBMUSER"}
//	  {"type":"key","key":"ENTER"}          (see keys)
//	  {"type":"cursor","row":R,"col":C}
//	  {"type":"model","model":4}            (3278 model 2-5: alternate size)
//
// text, attr, color and hilite are described by s390.Screen3270. Input that
// arrives while the keyboard is inhibited is held and applied in order once
// the program restores the keyboard (type-ahead); RESET is applied at once.
//
// For a line-mode console:
//
//	server → client
//	  {"type":"lines","first":F,"lines":["…"],"partial":"…",
//	   "waiting":bool,"status":"running"}
//	client → server
//	  {"type":"line","text":"IPL 190"}
//
// lines continues the transcript at absolute line index first; the first
// message carries the retained tail of the transcript.
package web3270

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/tinyrange/trex/emulator/s390"
)

//go:embed index.html terminal.js terminal.css
var assets embed.FS

// Server is an http.Handler for the terminal page, its terminal list and
// one WebSocket per viewer. Several viewers may share a console.
type Server struct {
	live  *s390.Live
	terms []s390.WebTerminal
	// Token authenticates API and WebSocket requests. The page receives it
	// in the URL fragment, which browsers do not send to the server.
	Token string
	// Save, when set, checkpoints the machine on request (POST
	// /api/checkpoint) and describes where the state went.
	Save   func() (string, error)
	saving atomic.Bool
	xfer   transfers
	// Snaps, when set, keeps named snapshots (/api/snapshots).
	Snaps Snapshots
}

// New returns a server for consoles of the machine run by live.
func New(live *s390.Live, terms []s390.WebTerminal) (*Server, error) {
	if len(terms) == 0 {
		return nil, fmt.Errorf("web3270: no terminals")
	}
	for _, t := range terms {
		n := 0
		for _, set := range []bool{t.Display != nil, t.Line != nil, t.Reader != nil} {
			if set {
				n++
			}
		}
		if n != 1 {
			return nil, fmt.Errorf("web3270: terminal %s needs exactly one of Display, Line and Reader", t.Name)
		}
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return &Server{live: live, terms: terms, Token: base64.RawURLEncoding.EncodeToString(b)}, nil
}

var keys = map[string]bool{"ENTER": true, "CLEAR": true, "PA1": true, "PA2": true, "PA3": true,
	"TAB": true, "BACKTAB": true, "HOME": true, "NEWLINE": true, "LEFT": true, "RIGHT": true, "UP": true, "DOWN": true,
	"BACKSPACE": true, "DELETE": true, "INSERT": true, "RESET": true, "ERASEEOF": true, "ERASEINPUT": true}

func init() {
	for i := 1; i <= 24; i++ {
		keys["PF"+strconv.Itoa(i)] = true
	}
}

func (s *Server) validOrigin(r *http.Request) bool {
	value := r.Header.Get("Origin")
	if value == "" {
		return false
	}
	u, err := url.Parse(value)
	if err != nil || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return u.Scheme == scheme && strings.EqualFold(u.Host, r.Host)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	if r.URL.Path == "/api/checkpoint" {
		s.checkpoint(w, r)
		return
	}
	if rest, ok := strings.CutPrefix(r.URL.Path, "/api/snapshots"); ok {
		s.snapshots(w, r, rest)
		return
	}
	if rest, ok := strings.CutPrefix(r.URL.Path, "/api/transfer"); ok {
		s.transfer(w, r, rest)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "GET required", http.StatusMethodNotAllowed)
		return
	}
	switch r.URL.Path {
	case "/", "/terminal.js", "/terminal.css":
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
		return
	case "/api/terminals":
		if !s.authorized(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")) {
			http.Error(w, "invalid session token", http.StatusForbidden)
			return
		}
		type info struct {
			Name string `json:"name"`
			Kind string `json:"kind"`
			Rows int    `json:"rows,omitempty"`
			Cols int    `json:"cols,omitempty"`
		}
		list := []info{}
		s.live.Do(func(*s390.Machine) {
			for _, t := range s.terms {
				switch {
				case t.Display != nil:
					list = append(list, info{t.Name, "3270", t.Display.Rows, t.Display.Cols})
				case t.Reader != nil:
					list = append(list, info{Name: t.Name, Kind: "reader"})
				case t.ReadOnly:
					list = append(list, info{Name: t.Name, Kind: "printer"})
				default:
					list = append(list, info{Name: t.Name, Kind: "line"})
				}
			}
		})
		h.Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"terminals": list, "status": s.live.Status(), "canSave": s.Save != nil, "snapshots": s.Snaps != nil})
		return
	case "/ws":
		if !s.authorized(r.URL.Query().Get("token")) {
			http.Error(w, "invalid session token", http.StatusForbidden)
			return
		}
		if !s.validOrigin(r) {
			http.Error(w, "origin mismatch", http.StatusForbidden)
			return
		}
		var term *s390.WebTerminal
		for i := range s.terms {
			if strings.EqualFold(s.terms[i].Name, r.URL.Query().Get("terminal")) {
				term = &s.terms[i]
			}
		}
		if term == nil {
			http.Error(w, "unknown terminal", http.StatusNotFound)
			return
		}
		c, err := upgrade(w, r)
		if err != nil {
			return
		}
		defer c.Close()
		switch {
		case term.Display != nil:
			s.displaySession(r.Context(), c, *term)
		case term.Reader != nil:
			s.readerSession(r.Context(), c, *term)
		default:
			s.lineSession(r.Context(), c, *term)
		}
		return
	case "/api/output":
		if !s.authorized(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")) {
			http.Error(w, "invalid session token", http.StatusForbidden)
			return
		}
		for _, t := range s.terms {
			if strings.EqualFold(t.Name, r.URL.Query().Get("terminal")) && t.Line != nil {
				var lines []string
				var partial string
				s.live.Do(func(*s390.Machine) { _, lines, partial = t.Line.Transcript(0) })
				if partial != "" {
					lines = append(lines, partial)
				}
				h.Set("Content-Type", "text/plain; charset=utf-8")
				_, _ = io.WriteString(w, strings.Join(lines, "\n")+"\n")
				return
			}
		}
		http.Error(w, "unknown line console", http.StatusNotFound)
		return
	}
	http.NotFound(w, r)
}

func (s *Server) checkpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if !s.authorized(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")) {
		http.Error(w, "invalid session token", http.StatusForbidden)
		return
	}
	if !s.validOrigin(r) {
		http.Error(w, "origin mismatch", http.StatusForbidden)
		return
	}
	if s.Save == nil {
		http.Error(w, "this server has no state file", http.StatusNotFound)
		return
	}
	if !s.saving.CompareAndSwap(false, true) {
		http.Error(w, "a checkpoint is already being written", http.StatusConflict)
		return
	}
	defer s.saving.Store(false)
	began := time.Now()
	where, err := s.Save()
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"saved": where, "seconds": time.Since(began).Seconds()})
}

func (s *Server) authorized(token string) bool {
	return subtle.ConstantTimeCompare([]byte(token), []byte(s.Token)) == 1
}

// input is one client message.
type input struct {
	Type  string `json:"type"`
	Text  string `json:"text"`
	Key   string `json:"key"`
	Row   int    `json:"row"`
	Col   int    `json:"col"`
	Model int    `json:"model"`
}

type screenMessage struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	Rows   int    `json:"rows"`
	Cols   int    `json:"cols"`
	Cursor int    `json:"cursor"`
	Locked bool   `json:"locked"`
	Insert bool   `json:"insert"`
	Status string `json:"status"`
	Text   string `json:"text"`
	Attr   string `json:"attr"`
	Color  string `json:"color"`
	Hilite string `json:"hilite"`
	Model  int    `json:"model"`
	Alarms uint64 `json:"alarms"`
}

// apply performs one input on the display. It reports false, with the
// reason, when the terminal inhibits the input.
func apply(t *s390.Console3270, in input) (bool, string) {
	switch in.Type {
	case "text":
		if err := t.Type(in.Text); err != nil {
			if strings.Contains(err.Error(), "full") {
				return false, "field full"
			}
			return false, "protected"
		}
	case "key":
		k := strings.ToUpper(in.Key)
		if !keys[k] {
			return false, "unknown key"
		}
		if err := t.Key(k); err != nil {
			return false, err.Error()
		}
	case "cursor":
		if in.Row < 0 || in.Row >= t.Rows || in.Col < 0 || in.Col >= t.Cols {
			return false, "cursor outside screen"
		}
		t.SetCursor(in.Row, in.Col)
	case "model":
		if err := t.SetModel(in.Model); err != nil {
			return false, err.Error()
		}
	default:
		return false, "unknown message"
	}
	return true, ""
}

// reader delivers client messages until the connection fails, then
// cancels the session.
func reader(ctx context.Context, cancel context.CancelFunc, c *conn) <-chan input {
	inputs := make(chan input, 256)
	go func() {
		defer cancel()
		for {
			b, err := c.ReadText()
			if err != nil {
				return
			}
			var in input
			if json.Unmarshal(b, &in) != nil {
				return
			}
			select {
			case inputs <- in:
			case <-ctx.Done():
				return
			}
		}
	}()
	return inputs
}

func (s *Server) displaySession(ctx context.Context, c *conn, term s390.WebTerminal) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	inputs := reader(ctx, cancel, c)
	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()
	var queue []input
	var last []byte
	for {
		changed := s.live.Changed()
		var msg screenMessage
		var inhibit string
		s.live.Do(func(*s390.Machine) {
			t := term.Display
			// Type-ahead: hold input while the keyboard is inhibited.
			for len(queue) > 0 {
				in := queue[0]
				reset := in.Type == "key" && strings.EqualFold(in.Key, "RESET")
				if t.Locked() && !reset {
					break
				}
				queue = queue[1:]
				if ok, reason := apply(t, in); !ok {
					inhibit = reason
					queue = nil
				}
			}
			scr := t.Screen()
			msg = screenMessage{Type: "screen", Name: term.Name, Rows: scr.Rows, Cols: scr.Cols,
				Cursor: scr.Cursor, Locked: scr.Locked, Insert: scr.Insert, Text: scr.Text, Attr: scr.Attr,
				Color: scr.Color, Hilite: scr.Hilite, Model: t.Model(), Alarms: scr.Alarms}
		})
		msg.Status = s.live.Status()
		if inhibit != "" {
			b, _ := json.Marshal(map[string]string{"type": "inhibit", "reason": inhibit})
			if c.WriteText(b) != nil {
				return
			}
		}
		b, _ := json.Marshal(msg)
		if string(b) != string(last) {
			if c.WriteText(b) != nil {
				return
			}
			last = b
		}
		select {
		case <-ctx.Done():
			return
		case <-changed:
		case in := <-inputs:
			queue = append(queue, in)
			// Take everything that has already arrived in one pass.
			for more := true; more; {
				select {
				case in := <-inputs:
					queue = append(queue, in)
				default:
					more = false
				}
			}
			if len(queue) > 4096 {
				// A wedged program never restores the keyboard.
				queue = queue[len(queue)-4096:]
			}
		case <-ping.C:
			if c.Ping() != nil {
				return
			}
		}
	}
}

type linesMessage struct {
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	First   int      `json:"first"`
	Lines   []string `json:"lines"`
	Partial string   `json:"partial"`
	Waiting bool     `json:"waiting"`
	Status  string   `json:"status"`
}

// lineTail is how much transcript a new viewer receives.
const lineTail = 2000

func (s *Server) lineSession(ctx context.Context, c *conn, term s390.WebTerminal) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	inputs := reader(ctx, cancel, c)
	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()
	next := -1 // absolute index of the next line to send
	var lastPartial, lastStatus string
	lastWaiting := false
	for {
		changed := s.live.Changed()
		var msg linesMessage
		s.live.Do(func(*s390.Machine) {
			from := next
			if from < 0 {
				first, lines, _ := term.Line.Transcript(0)
				from = max(first, first+len(lines)-lineTail)
			}
			msg.First, msg.Lines, msg.Partial = term.Line.Transcript(from)
			msg.Waiting = term.Line.Waiting()
		})
		msg.Type, msg.Name, msg.Status = "lines", term.Name, s.live.Status()
		if next < 0 || len(msg.Lines) > 0 || msg.Partial != lastPartial || msg.Waiting != lastWaiting || msg.Status != lastStatus {
			if msg.Lines == nil {
				msg.Lines = []string{}
			}
			b, _ := json.Marshal(msg)
			if c.WriteText(b) != nil {
				return
			}
			next = msg.First + len(msg.Lines)
			lastPartial, lastWaiting, lastStatus = msg.Partial, msg.Waiting, msg.Status
		}
		select {
		case <-ctx.Done():
			return
		case <-changed:
		case in := <-inputs:
			if in.Type == "line" && !term.ReadOnly {
				text := strings.TrimRight(in.Text, "\r\n")
				s.live.Do(func(*s390.Machine) { term.Line.Enter(text) })
			}
		case <-ping.C:
			if c.Ping() != nil {
				return
			}
		}
	}
}

// readerSession shows a card reader's hopper and accepts decks:
//
//	server → client  {"type":"reader","name":"000C","queued":N,"status":"running"}
//	client → server  {"type":"deck","text":"//JOB ...\n..."}
func (s *Server) readerSession(ctx context.Context, c *conn, term s390.WebTerminal) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	inputs := reader(ctx, cancel, c)
	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()
	last := -1
	lastStatus := ""
	for {
		changed := s.live.Changed()
		var queued int
		s.live.Do(func(*s390.Machine) { queued = term.Reader.Queued() })
		status := s.live.Status()
		if queued != last || status != lastStatus {
			b, _ := json.Marshal(map[string]any{"type": "reader", "name": term.Name, "queued": queued, "status": status})
			if c.WriteText(b) != nil {
				return
			}
			last, lastStatus = queued, status
		}
		select {
		case <-ctx.Done():
			return
		case <-changed:
		case in := <-inputs:
			if in.Type == "deck" {
				lines := strings.Split(strings.ReplaceAll(strings.TrimRight(in.Text, "\r\n"), "\r", ""), "\n")
				if len(lines) > 20000 {
					lines = lines[:20000]
				}
				s.live.Do(func(*s390.Machine) { term.Reader.Submit(lines) })
			}
		case <-ping.C:
			if c.Ping() != nil {
				return
			}
		}
	}
}
