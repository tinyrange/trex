package web3270

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tinyrange/trex/emulator/s390"
)

type client struct {
	c net.Conn
	r *bufio.Reader
}

func dial(t *testing.T, srv *httptest.Server, path, origin string) (*client, string) {
	t.Helper()
	c, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	host := strings.TrimPrefix(srv.URL, "http://")
	fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: %s\r\nOrigin: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"+
		"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", path, host, origin)
	r := bufio.NewReader(c)
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, resp.Status
	}
	if got := resp.Header.Get("Sec-WebSocket-Accept"); got != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("accept %q", got)
	}
	return &client{c, r}, resp.Status
}

// send writes one masked text message split into two fragments.
func (c *client) send(t *testing.T, v any) {
	t.Helper()
	b, _ := json.Marshal(v)
	half := len(b) / 2
	for i, part := range [][]byte{b[:half], b[half:]} {
		op := byte(1)
		if i == 1 {
			op = 0x80
		}
		mask := []byte{1, 2, 3, 4}
		frame := []byte{op, 0x80 | byte(len(part))}
		frame = append(frame, mask...)
		for k, x := range part {
			frame = append(frame, x^mask[k%4])
		}
		if _, err := c.c.Write(frame); err != nil {
			t.Fatal(err)
		}
	}
}

func (c *client) read(t *testing.T) map[string]any {
	t.Helper()
	c.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var h [2]byte
	if _, err := io.ReadFull(c.r, h[:]); err != nil {
		t.Fatal(err)
	}
	n := int(h[1] & 0x7f)
	if n == 126 {
		var b [2]byte
		io.ReadFull(c.r, b[:])
		n = int(binary.BigEndian.Uint16(b[:]))
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(c.r, b); err != nil {
		t.Fatal(err)
	}
	if h[0] != 0x81 {
		return c.read(t) // skip control frames
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// readScreen returns the next screen message satisfying ok.
func (c *client) readScreen(t *testing.T, ok func(map[string]any) bool) map[string]any {
	t.Helper()
	for i := 0; i < 20; i++ {
		m := c.read(t)
		if m["type"] == "screen" && ok(m) {
			return m
		}
	}
	t.Fatal("no matching screen")
	return nil
}

func TestTerminalSessionStreamsScreenAndTypeAhead(t *testing.T) {
	m := s390.NewMachine(s390.Config{Memory: 1 << 20, CPUs: 1, MIPS: 50})
	con := s390.NewConsole3270(24, 80)
	if err := m.CSS.AttachConsole(0x0701, con); err != nil {
		t.Fatal(err)
	}
	live := s390.NewLive(m, con)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go live.Run(ctx)
	srv0, err := New(live, []s390.WebTerminal{{Name: "0701", Device: 0x0701, Display: con}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(srv0)
	defer srv.Close()

	// The page is public; the API and WebSocket require the token.
	if resp, err := http.Get(srv.URL + "/"); err != nil || resp.StatusCode != 200 {
		t.Fatalf("page %v %v", resp, err)
	}
	if _, status := dial(t, srv, "/ws?token=wrong&terminal=0701", srv.URL); !strings.HasPrefix(status, "403") {
		t.Fatalf("bad token: %s", status)
	}
	if _, status := dial(t, srv, "/ws?token="+srv0.Token+"&terminal=0701", "http://evil.example"); !strings.HasPrefix(status, "403") {
		t.Fatalf("foreign origin: %s", status)
	}
	req, _ := http.NewRequest("GET", srv.URL+"/api/terminals", nil)
	req.Header.Set("Authorization", "Bearer "+srv0.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var list struct {
		Terminals []struct {
			Name string `json:"name"`
			Kind string `json:"kind"`
			Rows int    `json:"rows"`
		} `json:"terminals"`
	}
	json.NewDecoder(resp.Body).Decode(&list)
	if len(list.Terminals) != 1 || list.Terminals[0].Name != "0701" || list.Terminals[0].Kind != "3270" || list.Terminals[0].Rows != 24 {
		t.Fatalf("terminals %+v", list)
	}

	c, status := dial(t, srv, "/ws?token="+srv0.Token+"&terminal=0701", srv.URL)
	if c == nil {
		t.Fatal(status)
	}
	first := c.readScreen(t, func(map[string]any) bool { return true })
	if first["name"] != "0701" || first["rows"].(float64) != 24 || len(first["text"].(string)) != 1920 {
		t.Fatalf("first screen %v", first["name"])
	}
	c.send(t, map[string]any{"type": "text", "text": "LOGON"})
	c.send(t, map[string]any{"type": "key", "key": "ENTER"})
	locked := c.readScreen(t, func(m map[string]any) bool { return m["locked"] == true })
	if !strings.HasPrefix(locked["text"].(string), "LOGON") {
		t.Fatalf("typed text missing: %q", locked["text"].(string)[:10])
	}
	// Typed while inhibited: held until the program restores the keyboard.
	c.send(t, map[string]any{"type": "text", "text": "X"})
	time.Sleep(50 * time.Millisecond)
	live.Do(func(*s390.Machine) {
		if strings.Contains(con.Screen().Text, "LOGONX") {
			t.Error("input applied while inhibited")
		}
		// WRITE with WCC keyboard restore, SBA to row 2.
		con.Exec(0x01, []byte{0xc2, 0x11, 0x40, 0x50}, false)
	})
	c.readScreen(t, func(m map[string]any) bool {
		return m["locked"] == false && strings.Contains(m["text"].(string), "LOGONX")
	})
	c.send(t, map[string]any{"type": "key", "key": "BOGUS"})
	for i := 0; ; i++ {
		if m := c.read(t); m["type"] == "inhibit" {
			if m["reason"] != "unknown key" {
				t.Fatalf("inhibit %v", m)
			}
			break
		}
		if i > 10 {
			t.Fatal("no inhibit message")
		}
	}
}

func TestLineConsoleSessionStreamsTranscriptAndInput(t *testing.T) {
	m := s390.NewMachine(s390.Config{Memory: 1 << 20, CPUs: 1, MIPS: 50})
	con := s390.NewConsole3215()
	if err := m.CSS.AttachLineConsole(0x0009, con); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		con.Exec(0x09, s390.EncodeEBCDIC(fmt.Sprintf("LINE %d", i)), false)
	}
	con.Exec(0x01, s390.EncodeEBCDIC("PROMPT"), false)
	live := s390.NewLive(m, con)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go live.Run(ctx)
	srv0, err := New(live, []s390.WebTerminal{{Name: "0009", Device: 9, Line: con}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(srv0)
	defer srv.Close()
	c, status := dial(t, srv, "/ws?token="+srv0.Token+"&terminal=0009", srv.URL)
	if c == nil {
		t.Fatal(status)
	}
	first := c.read(t)
	if first["type"] != "lines" || first["first"].(float64) != 0 || len(first["lines"].([]any)) != 3 || first["partial"] != "PROMPT" {
		t.Fatalf("first %v", first)
	}
	live.Do(func(*s390.Machine) { con.Exec(0x09, s390.EncodeEBCDIC("NEXT"), false) })
	next := c.read(t)
	if next["first"].(float64) != 3 || next["lines"].([]any)[0] != "PROMPTNEXT" || next["partial"] != "" {
		t.Fatalf("next %v", next)
	}
	c.send(t, map[string]any{"type": "line", "text": "CP QUERY TIME"})
	deadline := time.Now().Add(5 * time.Second)
	for {
		var got []byte
		live.Do(func(*s390.Machine) {
			if !con.Blocked(0x0a) {
				got, _, _ = con.Exec(0x0a, nil, false)
			}
		})
		if got != nil {
			if s390.EBCDICString(got) != "CP QUERY TIME" {
				t.Fatalf("read %q", s390.EBCDICString(got))
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("input not delivered")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
