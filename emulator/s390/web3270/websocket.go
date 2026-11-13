package web3270

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// conn is a server-side RFC 6455 connection carrying whole text messages.
// Client frames must be masked; fragmented messages and control frames
// between fragments are handled.
type conn struct {
	c  net.Conn
	r  *bufio.Reader
	mu sync.Mutex // serializes frame writes
}

const (
	maxMessage  = 2 << 20 // a card deck pasted into a reader
	readTimeout = 90 * time.Second
	opText      = 1
	opClose     = 8
	opPing      = 9
	opPong      = 10
)

var errClosed = errors.New("websocket closed")

func headerHas(value, want string) bool {
	for _, part := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), want) {
			return true
		}
	}
	return false
}

// upgrade completes the opening handshake and takes over the connection.
func upgrade(w http.ResponseWriter, r *http.Request) (*conn, error) {
	key := r.Header.Get("Sec-WebSocket-Key")
	decoded, err := base64.StdEncoding.DecodeString(key)
	if !headerHas(r.Header.Get("Connection"), "upgrade") || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
		r.Header.Get("Sec-WebSocket-Version") != "13" || err != nil || len(decoded) != 16 {
		http.Error(w, "invalid WebSocket handshake", http.StatusBadRequest)
		return nil, fmt.Errorf("invalid WebSocket handshake")
	}
	h, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unavailable", http.StatusInternalServerError)
		return nil, fmt.Errorf("hijacking unavailable")
	}
	c, rw, err := h.Hijack()
	if err != nil {
		return nil, err
	}
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if _, err := fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
		base64.StdEncoding.EncodeToString(sum[:])); err != nil {
		c.Close()
		return nil, err
	}
	if err := rw.Flush(); err != nil {
		c.Close()
		return nil, err
	}
	return &conn{c: c, r: rw.Reader}, nil
}

func (w *conn) Close() error { return w.c.Close() }

func (w *conn) frame(op byte, p []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.c.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	h := []byte{0x80 | op}
	switch {
	case len(p) < 126:
		h = append(h, byte(len(p)))
	case len(p) <= 65535:
		h = append(h, 126, byte(len(p)>>8), byte(len(p)))
	default:
		h = append(h, 127)
		h = binary.BigEndian.AppendUint64(h, uint64(len(p)))
	}
	if _, err := w.c.Write(append(h, p...)); err != nil {
		return err
	}
	return nil
}

// WriteText sends one text message.
func (w *conn) WriteText(p []byte) error { return w.frame(opText, p) }

// Ping sends a ping; browsers answer automatically, which keeps the read
// deadline from expiring on an idle terminal.
func (w *conn) Ping() error { return w.frame(opPing, nil) }

// ReadText returns the next whole text message.
func (w *conn) ReadText() ([]byte, error) {
	var msg []byte
	started := false
	for {
		if err := w.c.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
			return nil, err
		}
		var h [2]byte
		if _, err := io.ReadFull(w.r, h[:]); err != nil {
			return nil, err
		}
		fin, op := h[0]&0x80 != 0, h[0]&0x0f
		if h[0]&0x70 != 0 || h[1]&0x80 == 0 {
			return nil, fmt.Errorf("invalid WebSocket flags or unmasked client frame")
		}
		n := uint64(h[1] & 0x7f)
		switch n {
		case 126:
			var b [2]byte
			if _, err := io.ReadFull(w.r, b[:]); err != nil {
				return nil, err
			}
			n = uint64(binary.BigEndian.Uint16(b[:]))
		case 127:
			var b [8]byte
			if _, err := io.ReadFull(w.r, b[:]); err != nil {
				return nil, err
			}
			n = binary.BigEndian.Uint64(b[:])
		}
		if op >= 8 && (!fin || n > 125) || n > maxMessage || uint64(len(msg))+n > maxMessage {
			return nil, fmt.Errorf("invalid WebSocket frame length")
		}
		var mask [4]byte
		if _, err := io.ReadFull(w.r, mask[:]); err != nil {
			return nil, err
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(w.r, b); err != nil {
			return nil, err
		}
		for i := range b {
			b[i] ^= mask[i%4]
		}
		switch op {
		case opClose:
			_ = w.frame(opClose, nil)
			return nil, errClosed
		case opPing:
			if err := w.frame(opPong, b); err != nil {
				return nil, err
			}
			continue
		case opPong:
			continue
		case opText:
			if started {
				return nil, fmt.Errorf("nested fragmented message")
			}
			started = true
		case 0:
			if !started {
				return nil, fmt.Errorf("unexpected continuation")
			}
		default:
			return nil, fmt.Errorf("text WebSocket messages required")
		}
		msg = append(msg, b...)
		if fin {
			return msg, nil
		}
	}
}
