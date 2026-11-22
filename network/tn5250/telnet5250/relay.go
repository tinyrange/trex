// Package telnet5250 lets TN5250 clients (RFC 1205/2877 display emulators)
// share a 5250 session whose host connection is owned by a tn5250.Terminal.
// The relay is the Telnet server for each client: it negotiates terminal
// type, binary and end-of-record, starts the client from the current screen,
// forwards the host's display records and passes the client's AID input
// back. The terminal stays the session's protocol endpoint (query, save
// screen and negotiation replies to the host), so clients never answer the
// host twice. The package has no socket dependency: Serve takes any
// io.ReadWriteCloser, and Sync runs on the goroutine that owns the terminal.
package telnet5250

import (
	"bytes"
	"encoding/binary"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/tinyrange/trex/network/tn5250"
)

// Telnet commands and options (RFC 854, 856, 885, 1091).
const (
	iac  = 255
	dont = 254
	do   = 253
	wont = 252
	will = 251
	sb   = 250
	se   = 240
	eor  = 239

	optBinary   = 0
	optTermType = 24
	optEOR      = 25
)

// Relay shares one terminal's session with any number of TN5250 clients.
type Relay struct {
	mu       sync.Mutex
	sessions []*session
	input    [][]byte // client records for the host, unescaped
	trace    []TraceRecord
	traced   uint64
}

// TraceRecord is one record that crossed the relay, for diagnosing a
// client: FromClient records are the client's own (before filtering), the
// others what the relay sent it.
type TraceRecord struct {
	Seq        uint64
	FromClient bool
	Forwarded  bool // client records: passed to the host
	Record     []byte
}

const traceLimit = 64

func (r *Relay) note(fromClient, forwarded bool, rec []byte) {
	r.traced++
	if len(r.trace) == traceLimit {
		r.trace = r.trace[1:]
	}
	r.trace = append(r.trace, TraceRecord{r.traced, fromClient, forwarded, slices.Clone(rec)})
}

// Trace returns the records after sequence number after (at most the last
// 64), oldest first.
func (r *Relay) Trace(after uint64) []TraceRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []TraceRecord
	for _, t := range r.trace {
		if t.Seq > after {
			out = append(out, t)
		}
	}
	return out
}

type session struct {
	conn     io.ReadWriteCloser
	out      chan []byte
	ready    bool // negotiated; owed the current screen
	started  bool // has been sent the current screen
	closed   bool
	termType string
}

// New returns a relay with no clients.
func New() *Relay { return &Relay{} }

// Clients reports the terminal types of the connected, negotiated clients.
func (r *Relay) Clients() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var types []string
	for _, s := range r.sessions {
		if s.ready && !s.closed {
			types = append(types, s.termType)
		}
	}
	return types
}

// Serve runs one client until it disconnects; call it on its own goroutine.
func (r *Relay) Serve(conn io.ReadWriteCloser) {
	s := &session{conn: conn, out: make(chan []byte, 512)}
	r.mu.Lock()
	r.sessions = append(r.sessions, s)
	r.mu.Unlock()
	done := make(chan struct{})
	go func() { // writer
		defer close(done)
		for b := range s.out {
			if _, err := conn.Write(b); err != nil {
				return
			}
		}
	}()
	s.send([]byte{iac, do, optTermType})
	// A client that never answers the terminal-type question still gets
	// the session after a short wait.
	timer := time.AfterFunc(3*time.Second, func() { r.negotiated(s, "") })
	r.read(s)
	timer.Stop()
	r.mu.Lock()
	s.closed = true
	close(s.out)
	r.mu.Unlock()
	<-done
	conn.Close()
}

// send queues bytes for the client, dropping a client that falls too far
// behind rather than blocking the session's owner. Callers that are not
// the reader hold r.mu.
func (s *session) send(b []byte) {
	if s.closed {
		return
	}
	select {
	case s.out <- b:
	default:
		s.closed = true
		s.conn.Close()
	}
}

func (r *Relay) negotiated(s *session, termType string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.ready || s.closed {
		return
	}
	s.ready, s.termType = true, termType
	s.send([]byte{iac, do, optEOR, iac, will, optEOR, iac, do, optBinary, iac, will, optBinary})
}

// read parses the client's Telnet stream: option negotiation, the
// terminal type, and 5250 records ended by IAC EOR.
func (r *Relay) read(s *session) {
	buf := make([]byte, 4096)
	var record, sub []byte
	state, verb := 0, byte(0)
	for {
		n, err := s.conn.Read(buf)
		if err != nil {
			return
		}
		for _, v := range buf[:n] {
			switch state {
			case 0: // data
				if v == iac {
					state = 1
				} else if len(record) < 1<<16 {
					record = append(record, v)
				}
			case 1: // after IAC
				switch v {
				case iac:
					record = append(record, iac)
					state = 0
				case eor:
					r.clientRecord(record)
					record = nil
					state = 0
				case sb:
					sub, state = nil, 4
				case will, wont, do, dont:
					verb, state = v, 2
				default:
					state = 0
				}
			case 2: // option of WILL/WONT/DO/DONT
				r.option(s, verb, v)
				state = 0
			case 4: // subnegotiation
				if v == iac {
					state = 5
				} else if len(sub) < 1024 {
					sub = append(sub, v)
				}
			case 5:
				if v == se {
					// TERMINAL-TYPE IS name (RFC 1091).
					if len(sub) >= 2 && sub[0] == optTermType && sub[1] == 0 {
						r.negotiated(s, string(sub[2:]))
					}
					state = 0
				} else {
					if v == iac && len(sub) < 1024 {
						sub = append(sub, iac)
					}
					state = 4
				}
			}
		}
	}
}

func (r *Relay) option(s *session, verb, opt byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch verb {
	case will:
		switch opt {
		case optTermType:
			s.send([]byte{iac, sb, optTermType, 1, iac, se}) // SEND
		case optBinary, optEOR:
		default:
			s.send([]byte{iac, dont, opt})
		}
	case wont:
		if opt == optTermType {
			go r.negotiated(s, "")
		}
	case do:
		if opt != optBinary && opt != optEOR {
			s.send([]byte{iac, wont, opt})
		}
	}
}

// clientRecord passes a client's AID input (Put/Get records) and its
// System Request and Attention keys to the host. Replies to the host's
// queries and save requests come from the terminal, so the client's own
// replies are dropped.
func (r *Relay) clientRecord(rec []byte) {
	if len(rec) < 10 || rec[2] != 0x12 || rec[3] != 0xa0 {
		r.mu.Lock()
		r.note(true, false, rec)
		r.mu.Unlock()
		return
	}
	flags, opcode := rec[7], rec[9]
	forwarded := opcode == 3 || flags&0x44 != 0
	r.mu.Lock()
	defer r.mu.Unlock()
	r.note(true, forwarded, rec)
	if !forwarded {
		return
	}
	if len(r.input) < 256 {
		r.input = append(r.input, slices.Clone(rec))
	}
}

// Sync runs on the goroutine that owns the terminal, after host bytes have
// been fed to it: it starts newly connected clients from the current
// screen, forwards the host's display records, and returns client input
// (escaped, with IAC EOR) to send to the host. The terminal's record tap
// is switched on.
func (r *Relay) Sync(t *tn5250.Terminal) []byte {
	t.TapRecords(true)
	records := t.TakeRecords()
	var screen []byte
	r.mu.Lock()
	defer r.mu.Unlock()
	live := r.sessions[:0]
	for _, s := range r.sessions {
		if s.closed {
			continue
		}
		live = append(live, s)
		if !s.ready {
			continue
		}
		if !s.started {
			if screen == nil {
				screen = t.ScreenRecord()
			}
			s.send(screen)
			r.note(false, true, screen)
			s.started = true
			continue // the screen already includes these records
		}
		for _, rec := range records {
			if out := forward(t, rec, &screen); out != nil {
				s.send(out)
				r.note(false, true, out)
			}
		}
	}
	r.sessions = live
	var input []byte
	for _, rec := range r.input {
		rec = fieldAddresses(rec, t.Fields)
		input = append(input, bytes.ReplaceAll(rec, []byte{iac}, []byte{iac, iac})...)
		input = append(input, iac, eor)
	}
	r.input = nil
	return input
}

// fieldAddresses corrects input from clients that address a field from its
// attribute byte rather than its first position: a Set Buffer Address at a
// field's attribute (which is never field data) is moved to the field's
// first position, dropping the attribute cell's character. Input from
// other clients is unchanged.
func fieldAddresses(rec []byte, fields []tn5250.Field) []byte {
	if len(rec) < 13 || rec[9] != 3 || int(rec[6]) != 4 {
		return rec
	}
	attrs := map[int]tn5250.Field{}
	for _, f := range fields {
		attrs[(f.Row-1)*80+f.Column-2] = f
	}
	out := slices.Clone(rec[:13])
	changed := false
	for i := 13; i < len(rec); {
		if rec[i] == 0x11 && i+2 < len(rec) && rec[i+1] >= 1 && rec[i+2] >= 1 {
			addr := (int(rec[i+1])-1)*80 + int(rec[i+2]) - 1
			if f, ok := attrs[addr]; ok {
				out = append(out, 0x11, byte(f.Row), byte(f.Column))
				i += 3
				if i < len(rec) && rec[i] != 0x11 {
					i++ // the attribute cell's character
				}
				changed = true
				continue
			}
			out = append(out, rec[i:i+3]...)
			i += 3
			continue
		}
		out = append(out, rec[i])
		i++
	}
	if !changed {
		return rec
	}
	binary.BigEndian.PutUint16(out, uint16(len(out)))
	return out
}

// forward selects what a client sees of one host record: display
// operations as sent, and the redrawn screen in place of a Restore Screen
// (its saved data is in the terminal's own format). Save Screen and the
// read requests are answered by the terminal and not forwarded.
func forward(t *tn5250.Terminal, rec []byte, screen *[]byte) []byte {
	if len(rec) < 10 {
		return nil
	}
	switch rec[9] {
	case 1, 2, 3, 0x0a, 0x0b, 0x0c:
		return append(bytes.ReplaceAll(slices.Clone(rec), []byte{iac}, []byte{iac, iac}), iac, eor)
	case 5:
		if *screen == nil {
			*screen = t.ScreenRecord()
		}
		return *screen
	}
	return nil
}
