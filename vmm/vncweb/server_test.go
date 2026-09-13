package vncweb

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/vmm"
	"image"
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type displayStub struct{}

func (displayStub) Capture(context.Context) (*image.RGBA, error) {
	return image.NewRGBA(image.Rect(0, 0, 2, 2)), nil
}
func (displayStub) Input(context.Context, vmm.Input) error { return nil }
func TestWebSocketRFBUpgrade(t *testing.T) {
	app, _ := New(displayStub{})
	server := httptest.NewServer(app)
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "http://")
	conn, err := net.Dial("tcp", host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReader(conn)
	fmt.Fprintf(conn, "GET /rfb?token=%s HTTP/1.1\r\nHost: %s\r\nOrigin: %s\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", app.Token, host, server.URL)
	line, _ := reader.ReadString('\n')
	if !strings.Contains(line, "101") {
		t.Fatal(line)
	}
	var headers string
	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
		headers += line
	}
	if !strings.Contains(headers, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") {
		t.Fatal(headers)
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
			io.ReadFull(reader, h)
			n = int(binary.BigEndian.Uint16(h))
		}
		p := make([]byte, n)
		if _, err := io.ReadFull(reader, p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if got := string(frame()); got != "RFB 003.008\n" {
		t.Fatal(got)
	}
	conn.Write(masked(0x82, []byte("RFB 003.008\n")))
	if p := frame(); len(p) != 2 || p[1] != 1 {
		t.Fatal(p)
	}
	conn.Write(masked(0x82, []byte{1}))
	frame()
	conn.Write(masked(0x82, []byte{1}))
	if p := frame(); binary.BigEndian.Uint16(p) != 2 {
		t.Fatal(p)
	}
	conn.Write(masked(0x82, []byte{3, 0, 0, 0, 0, 0, 0, 2, 0, 2}))
	if p := frame(); len(p) != 32 || p[3] != 1 {
		t.Fatal(p)
	}
}
