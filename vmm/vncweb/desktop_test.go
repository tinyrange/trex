package vncweb

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/tinyrange/trex/vmm"
)

func desktopLogin(t *testing.T, app *Desktop, password, origin string) *http.Cookie {
	t.Helper()
	r := httptest.NewRequest("POST", "/login", strings.NewReader(url.Values{"token": {password}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", origin)
	r.Host = strings.TrimPrefix(origin, "http://")
	w := httptest.NewRecorder()
	app.ServeHTTP(w, r)
	if w.Code != 303 || w.Header().Get("Location") != "./" {
		t.Fatalf("login: %d %s %s", w.Code, w.Header(), w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("missing cookie")
	}
	return cookies[0]
}

func TestDesktopAuthenticationAndProxy(t *testing.T) {
	const password = "a password with spaces : & + / ? # = 日本語"
	app, err := NewDesktop(singleWorkspace{displayStub{}}, password, "https://ood.example")
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	cookie := desktopLogin(t, app, password, "https://ood.example")
	if !cookie.HttpOnly || !cookie.Secure || cookie.Path != "" || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("unsafe cookie: %+v", cookie)
	}
	for _, prefix := range []string{"/", "/node/compute.example/8080/"} {
		handler := http.StripPrefix(strings.TrimSuffix(prefix, "/"), app)
		for _, tc := range []struct {
			path string
			auth bool
			code int
		}{
			{"login", false, 200}, {"", false, 303}, {"", true, 200}, {"desktop.js", false, 403},
			{"desktop.js", true, 200}, {"client.js", true, 200}, {"api/vms", true, 404},
			{"rfb?token=" + app.console.Token, false, 403},
		} {
			r := httptest.NewRequest("GET", prefix+tc.path, nil)
			if tc.auth {
				r.AddCookie(cookie)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != tc.code {
				t.Fatalf("%s: %d", tc.path, w.Code)
			}
			if tc.path == "login" && w.Header().Get("Referrer-Policy") != "same-origin" {
				t.Fatal("login form must preserve its same-origin POST Origin, not serialize it as null")
			}
			if tc.code == 303 && w.Header().Get("Location") != "login" {
				t.Fatal("absolute redirect loses proxy prefix")
			}
			if tc.path == "" && tc.auth {
				body := w.Body.String()
				if !strings.Contains(body, "<canvas ") || strings.Contains(body, "<button") || strings.Contains(body, "<form") || strings.Contains(body, "<header") || !strings.Contains(body, `src="./desktop.js"`) {
					t.Fatal("not a canvas-only relative page")
				}
			}
		}
	}
	for _, tc := range []struct {
		password, origin string
		code             int
	}{
		{password, "", 403}, {password, "null", 403}, {password, "https://evil.example", 403}, {"wrong", "https://ood.example", 403},
		{strings.Repeat("x", 70<<10), "https://ood.example", 400},
	} {
		r := httptest.NewRequest("POST", "/login", strings.NewReader(url.Values{"token": {tc.password}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", tc.origin)
		r.Header.Set("X-Forwarded-Host", "ood.example")
		r.Header.Set("X-Forwarded-Proto", "https")
		w := httptest.NewRecorder()
		app.ServeHTTP(w, r)
		if w.Code != tc.code || len(w.Result().Cookies()) != 0 {
			t.Fatalf("bad login accepted: %d", w.Code)
		}
	}
	for _, origin := range []string{"", "null", "https://evil.example", "http://ood.example"} {
		r := httptest.NewRequest("GET", "/rfb", nil)
		r.AddCookie(cookie)
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		app.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("bad websocket origin accepted: %q %d", origin, w.Code)
		}
	}
}

type desktopInputDisplay struct {
	displayStub
	inputs chan vmm.Input
}

func (d desktopInputDisplay) Input(_ context.Context, input vmm.Input) error {
	d.inputs <- input
	return nil
}

func TestDesktopWebSocketInputAndClose(t *testing.T) {
	display := desktopInputDisplay{inputs: make(chan vmm.Input, 16)}
	app, err := NewDesktop(singleWorkspace{display}, "password", "")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(app)
	defer server.Close()
	defer app.Close()
	cookie := desktopLogin(t, app, "password", server.URL)
	host := strings.TrimPrefix(server.URL, "http://")
	conn, err := net.Dial("tcp", host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "GET /rfb HTTP/1.1\r\nHost: %s\r\nOrigin: %s\r\nCookie: %s=%s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", host, server.URL, cookie.Name, cookie.Value)
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 101 {
		t.Fatal(response.Status)
	}
	frame := func() []byte {
		t.Helper()
		h := make([]byte, 2)
		if _, err := io.ReadFull(reader, h); err != nil {
			t.Fatal(err)
		}
		if h[0] != 0x82 {
			t.Fatal(h)
		}
		n := int(h[1])
		if n == 126 {
			if _, err := io.ReadFull(reader, h); err != nil {
				t.Fatal(err)
			}
			n = int(binary.BigEndian.Uint16(h))
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(reader, b); err != nil {
			t.Fatal(err)
		}
		return b
	}
	if string(frame()) != "RFB 003.008\n" {
		t.Fatal("RFB version")
	}
	conn.Write(masked(0x82, []byte("RFB 003.008\n")))
	frame()
	conn.Write(masked(0x82, []byte{1}))
	frame()
	conn.Write(masked(0x82, []byte{1}))
	frame()
	conn.Write(masked(0x82, []byte{3, 0, 0, 0, 0, 0, 0, 2, 0, 2}))
	if len(frame()) != 32 {
		t.Fatal("framebuffer not delivered")
	}
	conn.Write(masked(0x82, []byte{4, 1, 0, 0, 0, 0, 0, 97}))
	select {
	case input := <-display.inputs:
		if input.Kind != "key" || !input.Down {
			t.Fatalf("key: %+v", input)
		}
	case <-time.After(time.Second):
		t.Fatal("no key input")
	}
	conn.Write(masked(0x82, []byte{5, 1, 0, 1, 0, 1}))
	select {
	case input := <-display.inputs:
		if input.Kind != "pointer" || len(input.Buttons) != 1 {
			t.Fatalf("mouse: %+v", input)
		}
	case <-time.After(time.Second):
		t.Fatal("no mouse input")
	}
	// A second controller cannot steal held input.
	req, _ := http.NewRequest("GET", server.URL+"/rfb", nil)
	req.AddCookie(cookie)
	req.Header.Set("Origin", server.URL)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	res, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 409 {
		t.Fatal(res.Status)
	}
	closed := make(chan struct{})
	go func() { app.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not join hijacked connection")
	}
	keyUp, mouseUp := <-display.inputs, <-display.inputs
	if keyUp.Kind != "key" || keyUp.Down || mouseUp.Kind != "pointer" || len(mouseUp.Buttons) != 0 {
		t.Fatalf("input not released: %+v %+v", keyUp, mouseUp)
	}
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("websocket still open")
	}
	w := httptest.NewRecorder()
	app.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 503 {
		t.Fatal("closed handler accepted request")
	}
}

func TestDesktopOptions(t *testing.T) {
	for _, tc := range []struct{ password, origin string }{{"", ""}, {"p", "http://example.org"}, {"p", "https://example.org/path"}, {"p", "https://user@example.org"}} {
		if app, err := NewDesktop(singleWorkspace{displayStub{}}, tc.password, tc.origin); err == nil {
			app.Close()
			t.Fatal("invalid options accepted")
		}
	}
}

func TestBrowserClients(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, "--test", "client_test.mjs", "app_test.mjs", "desktop_test.mjs")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("browser tests: %v\n%s", err, output)
	}
}
