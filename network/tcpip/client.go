// Package tcpip provides a bounded packet-driven IPv4 TCP client. Transport
// and clock advancement are supplied by the caller, without host sockets.
package tcpip

import (
	"encoding/binary"
	"fmt"
	"slices"
	"time"
)

const (
	fin = 1
	syn = 2
	rst = 4
	psh = 8
	ack = 16
)
const bufferLimit = 65535

type Config struct {
	Local, Remote         [4]byte
	LocalPort, RemotePort uint16
	Sequence              uint32
	MTU                   int
}

// Client keeps one outstanding segment and at most64KiB in either direction.
// It supports active open, in-order delivery, duplicate trimming, window
// updates, retransmission and orderly close. IPv4 fragments are dropped;
// out-of-order data is cumulatively acknowledged and left for retransmission.
type Client struct {
	c                           Config
	state                       string
	sendNext, sendUna, recvNext uint32
	sendWL1, sendWL2            uint32
	peerWindow, peerMSS         int
	input, output               []byte
	pending                     []byte
	pendingSeq                  uint32
	pendingFlags                byte
	lastSent, lastNow           time.Duration
	timeWaitUntil               time.Duration
	retries                     int
	closing, eof                bool
	started, windowUpdate       bool
	err                         string
}

// checkpointCopy includes unconsumed input, partial records and protocol state.
func (c *Client) checkpointCopy() Client {
	copy := *c
	copy.input = slices.Clone(c.input)
	copy.output = slices.Clone(c.output)
	copy.pending = slices.Clone(c.pending)
	return copy
}

// CaptureCheckpoint returns a reusable rewind for this protocol endpoint.
func (c *Client) CaptureCheckpoint() (func() error, error) {
	saved := c.checkpointCopy()
	return func() error {
		*c = saved.checkpointCopy()
		return nil
	}, nil
}

func NewClient(c Config) (*Client, error) {
	if c.MTU == 0 {
		c.MTU = 1024
	}
	if c.LocalPort == 0 || c.RemotePort == 0 || c.MTU < 64 || c.MTU > 65535 || c.Local == c.Remote {
		return nil, fmt.Errorf("tcpip: invalid endpoint/MTU")
	}
	return &Client{c: c, state: "closed", sendNext: c.Sequence, sendUna: c.Sequence, peerMSS: min(536, c.MTU-40)}, nil
}
func (c *Client) State() string { return c.state }
func (c *Client) Error() string { return c.err }
func (c *Client) EOF() bool     { return c.eof && len(c.input) == 0 }
func (c *Client) tick(now time.Duration) error {
	if now < c.lastNow {
		return fmt.Errorf("tcpip: clock moved backwards")
	}
	c.lastNow = now
	return nil
}
func (c *Client) Start(now time.Duration) ([]byte, error) {
	if err := c.tick(now); err != nil {
		return nil, err
	}
	if c.started || c.closing {
		return nil, fmt.Errorf("tcpip: connection already started")
	}
	c.started = true
	c.state = "syn-sent"
	return c.queue(syn, nil, now), nil
}
func (c *Client) Write(data []byte) error {
	if c.closing || c.eof || c.err != "" || (c.state != "established" && c.state != "syn-sent") {
		return fmt.Errorf("tcpip: connection is not writable")
	}
	if len(data) > bufferLimit-len(c.output)-len(c.pending) {
		return fmt.Errorf("tcpip: send buffer full")
	}
	c.output = append(c.output, data...)
	return nil
}
func (c *Client) Read(maximum int) ([]byte, error) {
	if maximum < 1 || maximum > bufferLimit {
		return nil, fmt.Errorf("tcpip: invalid read size")
	}
	n := min(maximum, len(c.input))
	b := append([]byte(nil), c.input[:n]...)
	c.input = c.input[n:]
	if n > 0 {
		c.windowUpdate = true
	}
	return b, nil
}
func (c *Client) Close() {
	c.closing = true
	if c.state == "syn-sent" || c.state == "closed" {
		c.state = "closed"
		c.pendingFlags = 0
		c.eof = true
	}
}
func checksum(b []byte, s uint32) uint16 {
	for len(b) >= 2 {
		s += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) > 0 {
		s += uint32(b[0]) << 8
	}
	for s>>16 != 0 {
		s = (s & 65535) + (s >> 16)
	}
	return ^uint16(s)
}
func (c *Client) segment(seq uint32, flags byte, data []byte) []byte {
	h := 20
	if flags&syn != 0 {
		h = 24
	}
	b := make([]byte, 20+h+len(data))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	b[8] = 64
	b[9] = 6
	copy(b[12:16], c.c.Local[:])
	copy(b[16:20], c.c.Remote[:])
	binary.BigEndian.PutUint16(b[10:], checksum(b[:20], 0))
	t := b[20:]
	binary.BigEndian.PutUint16(t, c.c.LocalPort)
	binary.BigEndian.PutUint16(t[2:], c.c.RemotePort)
	binary.BigEndian.PutUint32(t[4:], seq)
	binary.BigEndian.PutUint32(t[8:], c.recvNext)
	t[12], t[13] = byte(h/4)<<4, flags
	c.windowUpdate = false
	binary.BigEndian.PutUint16(t[14:], uint16(bufferLimit-len(c.input)))
	if h == 24 {
		t[20], t[21] = 2, 4
		binary.BigEndian.PutUint16(t[22:], uint16(c.c.MTU-40))
	}
	copy(t[h:], data)
	s := uint32(6 + len(t))
	for i := 12; i < 20; i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	binary.BigEndian.PutUint16(t[16:], checksum(t, s))
	return b
}
func (c *Client) queue(flags byte, data []byte, now time.Duration) []byte {
	c.pendingSeq, c.pendingFlags = c.sendNext, flags
	c.pending = append([]byte(nil), data...)
	c.sendNext += uint32(len(data))
	if flags&(syn|fin) != 0 {
		c.sendNext++
	}
	c.lastSent, c.retries = now, 0
	return c.segment(c.pendingSeq, flags, data)
}
func (c *Client) fail(reason string) {
	c.err = reason
	c.state = "closed"
	c.pendingFlags = 0
	c.eof = true
}

// Input consumes a raw IPv4 packet. Invalid checksums, fragments and unrelated
// traffic are dropped without changing connection state. The returned packet
// (if any) must be sent by the caller. Call Poll even in the absence of input.
func (c *Client) Input(b []byte, now time.Duration) ([]byte, error) {
	if err := c.tick(now); err != nil {
		return nil, err
	}
	if len(b) < 20 || b[0]>>4 != 4 {
		return nil, nil
	}
	h := int(b[0]&15) * 4
	n := int(binary.BigEndian.Uint16(b[2:]))
	if h < 20 || h > len(b) || n < h+20 || n > len(b) || b[9] != 6 || binary.BigEndian.Uint16(b[6:])&0x3fff != 0 || checksum(b[:h], 0) != 0 {
		return nil, nil
	}
	var src, dst [4]byte
	copy(src[:], b[12:16])
	copy(dst[:], b[16:20])
	if src != c.c.Remote || dst != c.c.Local {
		return nil, nil
	}
	t := b[h:n]
	th := int(t[12]>>4) * 4
	if th < 20 || th > len(t) || binary.BigEndian.Uint16(t) != c.c.RemotePort || binary.BigEndian.Uint16(t[2:]) != c.c.LocalPort {
		return nil, nil
	}
	s := uint32(6 + len(t))
	for i := 12; i < 20; i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if checksum(t, s) != 0 {
		return nil, nil
	}
	seq, a := binary.BigEndian.Uint32(t[4:]), binary.BigEndian.Uint32(t[8:])
	flags := t[13]
	if c.state == "closed" {
		return nil, nil
	}
	if c.state == "syn-sent" {
		if flags&ack != 0 && a != c.sendNext {
			return nil, nil
		}
		if flags&rst != 0 {
			if flags&ack != 0 {
				c.fail("connection refused")
			}
			return nil, nil
		}
		if flags&(syn|ack) != (syn | ack) {
			return nil, nil
		}
		mss := 536
		for i := 20; i < th; {
			kind := t[i]
			if kind == 0 {
				break
			}
			if kind == 1 {
				i++
				continue
			}
			if i+1 >= th || t[i+1] < 2 || i+int(t[i+1]) > th {
				return nil, nil
			}
			if kind == 2 {
				if t[i+1] != 4 {
					return nil, nil
				}
				mss = int(binary.BigEndian.Uint16(t[i+2:]))
				if mss == 0 {
					return nil, nil
				}
			}
			i += int(t[i+1])
		}
		c.peerMSS = min(mss, c.c.MTU-40)
		c.peerWindow = int(binary.BigEndian.Uint16(t[14:]))
		c.recvNext = seq + 1
		c.sendUna = a
		c.sendWL1, c.sendWL2 = seq, a
		c.pendingFlags = 0
		c.pending = nil
		c.state = "established"
		return c.segment(c.sendNext, ack, nil), nil
	}
	if flags&rst != 0 {
		if seq == c.recvNext {
			c.fail("peer reset")
		}
		return nil, nil
	}
	if flags&syn != 0 || flags&ack == 0 || int32(a-c.sendNext) > 0 {
		return c.segment(c.sendNext, ack, nil), nil
	}
	wireSeq := seq
	data := t[th:]
	duplicate := false
	if int32(seq-c.recvNext) < 0 {
		skip := c.recvNext - seq
		if skip <= uint32(len(data)) {
			data = data[skip:]
			seq = c.recvNext
			duplicate = true
		}
	}
	if seq != c.recvNext {
		return c.segment(c.sendNext, ack, nil), nil
	}
	if int32(a-c.sendUna) >= 0 {
		if int32(wireSeq-c.sendWL1) > 0 || wireSeq == c.sendWL1 && int32(a-c.sendWL2) >= 0 {
			c.peerWindow = int(binary.BigEndian.Uint16(t[14:]))
			c.sendWL1, c.sendWL2 = wireSeq, a
		}
		if int32(a-c.sendUna) > 0 {
			c.sendUna = a
			if a == c.sendNext {
				wasFin := c.pendingFlags&fin != 0
				c.pendingFlags = 0
				c.pending = nil
				if wasFin {
					if c.state == "last-ack" {
						c.state = "closed"
					} else if c.eof {
						c.state = "time-wait"
						c.timeWaitUntil = now + 120*time.Second
					} else {
						c.state = "fin-wait-2"
					}
				}
			} else if c.pendingFlags&(syn|fin) == 0 && a-c.pendingSeq <= uint32(len(c.pending)) {
				c.pending = c.pending[a-c.pendingSeq:]
				c.pendingSeq = a
				c.lastSent = now
				c.retries = 0
			}
		}
	}
	nread := min(len(data), bufferLimit-len(c.input))
	if c.eof {
		nread = 0
	}
	c.input = append(c.input, data[:nread]...)
	c.recvNext += uint32(nread)
	gotFin := flags&fin != 0 && nread == len(data) && !c.eof
	if gotFin {
		c.recvNext++
		c.eof = true
		if c.state == "established" {
			c.state = "close-wait"
		} else if c.pendingFlags&fin == 0 {
			c.state = "time-wait"
			c.timeWaitUntil = now + 120*time.Second
		}
	}
	if len(data) > 0 || flags&fin != 0 || duplicate {
		return c.segment(c.sendNext, ack, nil), nil
	}
	return nil, nil
}

// Poll advances retransmission with a supplied monotonic clock. A single
// outstanding segment bounds congestion; six retries terminate a failed link.
func (c *Client) Poll(now time.Duration) ([]byte, error) {
	if err := c.tick(now); err != nil {
		return nil, err
	}
	if c.state == "time-wait" && now >= c.timeWaitUntil {
		c.state = "closed"
	}
	if c.pendingFlags != 0 {
		if now-c.lastSent < time.Second<<min(c.retries, 3) {
			return nil, nil
		}
		if c.retries == 6 {
			c.fail("retransmission timeout")
			return nil, nil
		}
		c.lastSent = now
		c.retries++
		return c.segment(c.pendingSeq, c.pendingFlags, c.pending), nil
	}
	if c.state != "established" && c.state != "close-wait" {
		return nil, nil
	}
	if len(c.output) > 0 && c.peerWindow > 0 {
		n := min(len(c.output), min(c.peerMSS, c.peerWindow))
		data := c.output[:n]
		packet := c.queue(ack|psh, data, now)
		c.output = c.output[n:]
		return packet, nil
	}
	if c.closing && len(c.output) == 0 {
		if c.eof {
			c.state = "last-ack"
		} else {
			c.state = "fin-wait-1"
		}
		return c.queue(fin|ack, nil, now), nil
	}
	if c.windowUpdate {
		return c.segment(c.sendNext, ack, nil), nil
	}
	return nil, nil
}
