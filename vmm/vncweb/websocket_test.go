package vncweb

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func masked(op byte, p []byte) []byte {
	b := []byte{op, 128 | byte(len(p)), 1, 2, 3, 4}
	for i, v := range p {
		b = append(b, v^byte(i%4+1))
	}
	return b
}
func TestFragmentedBinary(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	a.SetDeadline(time.Now().Add(time.Second))
	b.SetDeadline(time.Now().Add(time.Second))
	w := &websocket{Conn: a, r: bufio.NewReader(a)}
	go func() {
		b.Write(masked(2, []byte("ab")))
		b.Write(masked(0x89, []byte("ping")))
		p := make([]byte, 6)
		io.ReadFull(b, p)
		b.Write(masked(0x80, []byte("cd")))
	}()
	p := make([]byte, 4)
	if _, err := io.ReadFull(w, p); err != nil {
		t.Fatal(err)
	}
	if string(p) != "abcd" {
		t.Fatal(string(p))
	}
}
func TestRejectUnmaskedAndText(t *testing.T) {
	for _, data := range [][]byte{{0x82, 0}, masked(0x81, []byte("text")), masked(0x80, nil)} {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		w := &websocket{Conn: a, r: bufio.NewReader(bytes.NewReader(data))}
		if _, err := w.Read(make([]byte, 1)); err == nil {
			t.Fatal("accepted invalid frame")
		}
	}
}
func TestHTTPGuards(t *testing.T) {
	s, _ := New(nil)
	for _, test := range []struct {
		path, origin string
		status       int
	}{{"/", "", 200}, {"/client.js", "", 200}, {"/rfb", "", 403}, {"/rfb?token=" + s.Token, "http://evil.invalid", 403}, {"/rfb?token=" + s.Token, "http://example.com", 400}} {
		r := httptest.NewRequest(http.MethodGet, "http://example.com"+test.path, nil)
		r.Header.Set("Origin", test.origin)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != test.status {
			t.Fatalf("%s: %d", test.path, w.Code)
		}
	}
}
