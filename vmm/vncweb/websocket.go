// Package vncweb is the native HTTP/WebSocket adapter for the portable RFB server.
package vncweb

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/tinyrange/trex/channel"
)

// websocket presents binary messages as one byte stream. Client frames must be
// masked; fragmentation and interleaved control frames are handled here.
type websocket struct {
	net.Conn
	r            *bufio.Reader
	mu           sync.Mutex
	pending      []byte
	fragment     bool
	messageBytes uint64
}

const maxMessage = 1 << 20

func (w *websocket) frame(op byte, p []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
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
	if err := channel.WriteAll(w.Conn, h); err != nil {
		return err
	}
	return channel.WriteAll(w.Conn, p)
}
func (w *websocket) Write(p []byte) (int, error) {
	if err := w.frame(2, p); err != nil {
		return 0, err
	}
	return len(p), nil
}
func (w *websocket) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for len(w.pending) == 0 {
		if err := w.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
			return 0, err
		}
		h := make([]byte, 2)
		if _, err := io.ReadFull(w.r, h); err != nil {
			return 0, err
		}
		fin := h[0]&128 != 0
		op := h[0] & 15
		if h[0]&0x70 != 0 || h[1]&128 == 0 {
			return 0, fmt.Errorf("invalid WebSocket flags or unmasked client frame")
		}
		n := uint64(h[1] & 127)
		if n == 126 {
			b := make([]byte, 2)
			if _, err := io.ReadFull(w.r, b); err != nil {
				return 0, err
			}
			n = uint64(binary.BigEndian.Uint16(b))
			if n < 126 {
				return 0, fmt.Errorf("noncanonical frame length")
			}
		} else if n == 127 {
			b := make([]byte, 8)
			if _, err := io.ReadFull(w.r, b); err != nil {
				return 0, err
			}
			n = binary.BigEndian.Uint64(b)
			if n < 65536 {
				return 0, fmt.Errorf("noncanonical frame length")
			}
		}
		if n > maxMessage || op >= 8 && (!fin || n > 125) {
			return 0, fmt.Errorf("invalid WebSocket frame length")
		}
		mask := make([]byte, 4)
		if _, err := io.ReadFull(w.r, mask); err != nil {
			return 0, err
		}
		b := make([]byte, int(n))
		if _, err := io.ReadFull(w.r, b); err != nil {
			return 0, err
		}
		for i := range b {
			b[i] ^= mask[i%4]
		}
		switch op {
		case 8:
			if len(b) == 1 {
				return 0, fmt.Errorf("invalid close frame")
			}
			_ = w.frame(8, nil)
			return 0, io.EOF
		case 9:
			if err := w.frame(10, b); err != nil {
				return 0, err
			}
			continue
		case 10:
			continue
		case 2:
			if w.fragment {
				return 0, fmt.Errorf("nested fragmented message")
			}
			w.messageBytes = 0
		case 0:
			if !w.fragment {
				return 0, fmt.Errorf("unexpected continuation")
			}
		default:
			return 0, fmt.Errorf("binary WebSocket messages required")
		}
		w.messageBytes += n
		if w.messageBytes > maxMessage {
			return 0, fmt.Errorf("WebSocket message too large")
		}
		w.fragment = !fin
		w.pending = b
	}
	n := copy(p, w.pending)
	w.pending = w.pending[n:]
	return n, nil
}
