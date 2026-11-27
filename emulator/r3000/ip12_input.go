package r3000

import (
	"fmt"

	"github.com/tinyrange/trex/channel"
)

const (
	ip12KeyboardFrame = 36_000_000 * 11 / 600
	ip12MouseFrame    = 36_000_000 * 10 / 4800
)

// ip12Input carries a peripheral's already-framed serial bytes between
// the host event API and the on-board SCC, paced by the CPU clock.
type ip12Input struct {
	queue      [256]byte
	head, size uint16
	next       uint64
}

func (p *ip12Input) push(data []byte, cycles, interval uint64) error {
	if len(data) > len(p.queue)-int(p.size) {
		return channel.ErrWouldBlock
	}
	if p.size == 0 {
		p.next = max(p.next, cycles+interval)
	}
	for _, value := range data {
		p.queue[(p.head+p.size)&255] = value
		p.size++
	}
	return nil
}

func (p *ip12Input) deliver(port *ip12SCCPort, cycles, interval uint64) {
	if p.size == 0 || cycles < p.next || port.rxReady || port.wr[3]&1 == 0 {
		return
	}
	port.rx, port.rxReady = p.queue[p.head], true
	p.head = (p.head + 1) & 255
	p.size--
	p.next = cycles + interval
}

// KeyCode sends a press or release for a key from the SGI IRIS keyboard
// matrix. The caller identifies the physical key using its down code.
func (m *IP12) KeyCode(code byte, down bool) error {
	if m.closed {
		return fmt.Errorf("ip12: machine closed")
	}
	if code == 0 || code >= 110 {
		return fmt.Errorf("ip12: invalid SGI key code %d", code)
	}
	if !down {
		code |= 0x80
	}
	return m.keyboard.push([]byte{code}, m.cycles, ip12KeyboardFrame)
}

// Mouse sends one SGI serial mouse packet. Positive deltas move right
// and up. Bits 2, 1 and 0 indicate left, middle and right pressed.
func (m *IP12) Mouse(dx, dy int, buttons byte) error {
	if m.closed {
		return fmt.Errorf("ip12: machine closed")
	}
	if dx < -128 || dx > 127 || dy < -128 || dy > 127 || buttons > 7 {
		return fmt.Errorf("ip12: invalid SGI mouse deltas or buttons")
	}
	frame := [5]byte{0x87 ^ buttons, byte(dx), byte(dy), 0, 0}
	return m.mouse.push(frame[:], m.cycles, ip12MouseFrame)
}

func (m *IP12) keyboardCommand(value byte) {
	if value&0x11 == 0x10 {
		// The configuration response starts with 0x6e, followed by the
		// DIP switches. Zero selects the default (US) key layout.
		_ = m.keyboard.push([]byte{0x6e, 0}, m.cycles, ip12KeyboardFrame)
	}
}
