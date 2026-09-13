// Package ethernet provides an isolated, in-memory Ethernet broadcast domain.
// Frames exclude the preamble and FCS. Ports own their receive buffers.
package ethernet

import (
	"errors"
	"sync"
)

const MaxFrame = 1518

var ErrClosed = errors.New("Ethernet port closed")

// Endpoint is a nonblocking packet interface. An empty receive queue returns nil.
// Send copies the frame before returning; implementations may drop on congestion.
type Endpoint interface {
	Send([]byte) error
	Receive() []byte
	Close() error
}

// Switch learns source MACs and floods broadcasts, multicasts and unknown peers.
// Its bounded per-port queues prevent a stopped guest from blocking other guests.
type Switch struct {
	mu      sync.Mutex
	ports   map[*Port]bool
	learned map[[6]byte]*Port
}

func NewSwitch() *Switch {
	return &Switch{ports: make(map[*Port]bool), learned: make(map[[6]byte]*Port)}
}

type Port struct {
	switcher *Switch
	queue    [][]byte
	closed   bool
}

func (s *Switch) Connect() *Port {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := &Port{switcher: s}
	s.ports[p] = true
	return p
}

func (p *Port) Send(frame []byte) error {
	if len(frame) < 14 || len(frame) > MaxFrame {
		return errors.New("invalid Ethernet frame length")
	}
	s := p.switcher
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.closed {
		return ErrClosed
	}
	source, destination := [6]byte(frame[6:12]), [6]byte(frame[:6])
	if source[0]&1 == 0 {
		// Bound learned addresses even if a guest spoofs many source MACs.
		if len(s.learned) < 1024 || s.learned[source] != nil {
			s.learned[source] = p
		}
	}
	target := s.learned[destination]
	for peer := range s.ports {
		if peer == p || destination[0]&1 == 0 && target != nil && peer != target {
			continue
		}
		if len(peer.queue) < 256 {
			peer.queue = append(peer.queue, append([]byte(nil), frame...))
		}
	}
	return nil
}

func (p *Port) Receive() []byte {
	s := p.switcher
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(p.queue) == 0 {
		return nil
	}
	frame := p.queue[0]
	p.queue[0] = nil
	p.queue = p.queue[1:]
	return frame
}

func (p *Port) Close() error {
	s := p.switcher
	s.mu.Lock()
	defer s.mu.Unlock()
	p.closed = true
	p.queue = nil
	delete(s.ports, p)
	for mac, port := range s.learned {
		if port == p {
			delete(s.learned, mac)
		}
	}
	return nil
}
