// Package tn3270 attaches remote tn3270 clients (RFC 1576 and TN3270E, RFC
// 2355) to the 3270 display stations of a running ESA/390 or System/370
// machine.
//
// The device model in package s390 stays authoritative: every write the
// program issues to a display is forwarded to the client as a data-stream
// record, and the client's inbound records (AID, cursor and modified
// fields) are applied to the model, which presents attention to the
// program. On connection the client receives a redraw of the current
// screen. A display can be held by one tn3270 client at a time; browser
// viewers (package web3270) may share it.
//
// A TN3270E client chooses a display with CONNECT, naming it by terminal
// name ("0701") or device number ("701", "LCL701"); other clients get the
// first free display of the pool.
package tn3270

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tinyrange/trex/emulator/s390"
)

// Telnet commands and options.
const (
	se       = 240
	nop      = 241
	sb       = 250
	will     = 251
	wont     = 252
	do       = 253
	dont     = 254
	iac      = 255
	eor      = 239
	optBin   = 0
	optTM    = 6
	optTType = 24
	optEOR   = 25
	optTN3E  = 40

	// TN3270E subnegotiation codes.
	e3Associate  = 0
	e3Connect    = 1
	e3DeviceType = 2
	e3Functions  = 3
	e3Is         = 4
	e3Reason     = 5
	e3Reject     = 6
	e3Request    = 7
	e3Send       = 8

	reasonInUse   = 1
	reasonInvName = 3
	reasonInvType = 4
)

// Server accepts tn3270 clients for a pool of displays.
type Server struct {
	live  *s390.Live
	terms []s390.WebTerminal
	// NegotiationTimeout bounds each step of option negotiation.
	NegotiationTimeout time.Duration
	// Log, when set, receives one line per connection event and inbound
	// record. Field contents are never logged, only their positions and
	// lengths, so passwords stay out of the log.
	Log func(string)

	mu   sync.Mutex
	held map[*s390.Console3270]bool
}

// New returns a server for the display stations among terms, offered in
// order to clients that do not name one.
func New(live *s390.Live, terms []s390.WebTerminal) (*Server, error) {
	var displays []s390.WebTerminal
	for _, t := range terms {
		if t.Display != nil {
			displays = append(displays, t)
		}
	}
	if len(displays) == 0 {
		return nil, fmt.Errorf("tn3270: no 3270 display stations")
	}
	return &Server{live: live, terms: displays, NegotiationTimeout: 10 * time.Second,
		held: map[*s390.Console3270]bool{}}, nil
}

// Serve accepts connections until l fails.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			err := s.serveConn(ctx, c, c.RemoteAddr().String())
			s.logf("%s: closed: %v", c.RemoteAddr(), err)
		}()
	}
}

// matches reports whether name selects terminal t: its name, or its device
// number in hexadecimal, optionally after a VTAM-style "LCL" or "L" prefix.
func matches(t s390.WebTerminal, name string) bool {
	name = strings.ToUpper(strings.TrimSpace(name))
	if strings.EqualFold(t.Name, name) {
		return true
	}
	for _, prefix := range []string{"LCL", "L", ""} {
		if rest, ok := strings.CutPrefix(name, prefix); ok && rest != "" {
			if d, err := strconv.ParseUint(rest, 16, 16); err == nil && uint16(d) == t.Device {
				return true
			}
		}
	}
	return false
}

// acquire holds the named display, or the first free one when name is
// empty. The reason is a TN3270E reject reason.
func (s *Server) acquire(name string) (s390.WebTerminal, byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	found := false
	for _, t := range s.terms {
		if name != "" && !matches(t, name) {
			continue
		}
		found = true
		if !s.held[t.Display] {
			s.held[t.Display] = true
			return t, 0, true
		}
	}
	if name != "" && !found {
		return s390.WebTerminal{}, reasonInvName, false
	}
	return s390.WebTerminal{}, reasonInUse, false
}

func (s *Server) release(t s390.WebTerminal) {
	s.mu.Lock()
	delete(s.held, t.Display)
	s.mu.Unlock()
}

// telnet reads a telnet byte stream, separating commands and
// subnegotiations from data records.
type telnet struct {
	r      *bufio.Reader
	w      io.Writer
	wmu    sync.Mutex
	record []byte
}

// event is one item read from the client: a negotiation command, a
// subnegotiation, or a complete data record.
type event struct {
	cmd, opt byte   // will/wont/do/dont and option
	sub      []byte // subnegotiation body (option first)
	record   []byte // data record ended by IAC EOR
}

func (t *telnet) send(b ...byte) error {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	_, err := t.w.Write(b)
	return err
}

func (t *telnet) next() (event, error) {
	for {
		b, err := t.r.ReadByte()
		if err != nil {
			return event{}, err
		}
		if b != iac {
			t.record = append(t.record, b)
			if len(t.record) > 1<<20 {
				return event{}, errors.New("tn3270: inbound record too long")
			}
			continue
		}
		c, err := t.r.ReadByte()
		if err != nil {
			return event{}, err
		}
		switch c {
		case iac:
			t.record = append(t.record, iac)
		case eor:
			rec := t.record
			t.record = nil
			return event{record: rec}, nil
		case will, wont, do, dont:
			o, err := t.r.ReadByte()
			if err != nil {
				return event{}, err
			}
			return event{cmd: c, opt: o}, nil
		case sb:
			var body []byte
			for {
				x, err := t.r.ReadByte()
				if err != nil {
					return event{}, err
				}
				if x == iac {
					y, err := t.r.ReadByte()
					if err != nil {
						return event{}, err
					}
					if y == se {
						break
					}
					x = y // IAC IAC within a subnegotiation
				}
				body = append(body, x)
				if len(body) > 4096 {
					return event{}, errors.New("tn3270: subnegotiation too long")
				}
			}
			return event{sub: body}, nil
		default:
			// NOP, GA, AYT and similar carry no data.
		}
	}
}

// session is one negotiated client.
type session struct {
	tn       *telnet
	tn3270e  bool
	devType  string
	extended bool
	seq      uint16
}

// writeRecord sends one data record, framed for the negotiated mode.
func (ss *session) writeRecord(rec []byte) error {
	out := make([]byte, 0, len(rec)+16)
	if ss.tn3270e {
		out = append(out, 0x00, 0x00, 0x00, byte(ss.seq>>8), byte(ss.seq)) // 3270-DATA
		ss.seq++
	}
	for _, b := range rec {
		out = append(out, b)
		if b == iac {
			out = append(out, iac)
		}
	}
	out = append(out, iac, eor)
	return ss.tn.send(out...)
}

// ServeConn negotiates with one client and runs its session until the
// connection ends or ctx is done.
func (s *Server) ServeConn(ctx context.Context, c io.ReadWriteCloser) error {
	return s.serveConn(ctx, c, "client")
}

func (s *Server) logf(format string, args ...any) {
	if s.Log != nil {
		s.Log(fmt.Sprintf(format, args...))
	}
}

// describe summarizes an inbound record without its field contents.
func describe(rec []byte) string {
	if len(rec) == 0 {
		return "empty"
	}
	out := fmt.Sprintf("AID %02X", rec[0])
	if len(rec) >= 3 {
		out += fmt.Sprintf(" cursor %02X%02X", rec[1], rec[2])
	}
	data, fields := rec[min(3, len(rec)):], 0
	for i := 0; i < len(data); {
		if data[i] == 0x11 && i+2 < len(data) {
			j := i + 3
			for j < len(data) && data[j] != 0x11 {
				j++
			}
			out += fmt.Sprintf(" field@%02X%02X len %d", data[i+1], data[i+2], j-i-3)
			fields++
			i = j
			continue
		}
		// Unformatted input: count the bytes.
		out += fmt.Sprintf(" %d bytes unformatted", len(data)-i)
		break
	}
	return out
}

func (s *Server) serveConn(ctx context.Context, c io.ReadWriteCloser, peer string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		c.Close()
	}()
	tn := &telnet{r: bufio.NewReader(c), w: c}
	events := make(chan event, 64)
	readErr := make(chan error, 1)
	go func() {
		for {
			ev, err := tn.next()
			if err != nil {
				readErr <- err
				close(events)
				return
			}
			select {
			case events <- ev:
			case <-ctx.Done():
				return
			}
		}
	}()
	ss, term, err := s.negotiate(ctx, tn, events)
	if err != nil {
		return err
	}
	defer s.release(term)
	mode := "tn3270"
	if ss.tn3270e {
		mode = "TN3270E"
	}
	s.logf("%s: %s %s on %s (extended attributes %v)", peer, mode, ss.devType, term.Name, ss.extended)
	return s.run(ctx, ss, term, events)
}

// await returns the next event, or an error after the negotiation timeout.
func (s *Server) await(ctx context.Context, events <-chan event) (event, error) {
	timer := time.NewTimer(s.NegotiationTimeout)
	defer timer.Stop()
	select {
	case ev, ok := <-events:
		if !ok {
			return event{}, io.EOF
		}
		return ev, nil
	case <-timer.C:
		return event{}, errTimeout
	case <-ctx.Done():
		return event{}, ctx.Err()
	}
}

var errTimeout = errors.New("tn3270: negotiation timed out")

// modelOf returns the model number of a terminal type such as
// IBM-3278-4-E, or 0 for a type that does not name one (IBM-DYNAMIC).
func modelOf(t string) int {
	parts := strings.Split(strings.ToUpper(t), "-")
	if len(parts) >= 3 && (parts[1] == "3278" || parts[1] == "3279") {
		if m, err := strconv.Atoi(parts[2]); err == nil {
			if _, _, ok := s390.ModelSize(m); ok {
				return m
			}
		}
	}
	return 0
}

func extendedType(t string) bool {
	t = strings.ToUpper(t)
	return strings.HasSuffix(t, "-E") || strings.Contains(t, "3279") || strings.Contains(t, "DYNAMIC")
}

// negotiate agrees TN3270E or, when the client refuses it, terminal type,
// binary and end-of-record, and assigns a display.
func (s *Server) negotiate(ctx context.Context, tn *telnet, events <-chan event) (*session, s390.WebTerminal, error) {
	ss := &session{tn: tn}
	if err := tn.send(iac, do, optTN3E); err != nil {
		return nil, s390.WebTerminal{}, err
	}
	for {
		ev, err := s.await(ctx, events)
		if err == errTimeout {
			break // no answer: try plain tn3270
		}
		if err != nil {
			return nil, s390.WebTerminal{}, err
		}
		if ev.opt == optTN3E && ev.cmd == will {
			return s.negotiateE(ctx, ss, events)
		}
		if ev.opt == optTN3E && ev.cmd == wont {
			break
		}
		s.refuse(tn, ev)
	}
	// RFC 1576: terminal type, then binary and EOR in both directions.
	if err := tn.send(iac, do, optTType); err != nil {
		return nil, s390.WebTerminal{}, err
	}
	agreed := map[[2]byte]bool{}
	asked := false
	for !(ss.devType != "" && agreed[[2]byte{will, optEOR}] && agreed[[2]byte{do, optEOR}] &&
		agreed[[2]byte{will, optBin}] && agreed[[2]byte{do, optBin}]) {
		ev, err := s.await(ctx, events)
		if err != nil {
			return nil, s390.WebTerminal{}, err
		}
		switch {
		case ev.cmd == will && ev.opt == optTType:
			if !asked {
				asked = true
				if err := tn.send(iac, sb, optTType, 1, iac, se); err != nil {
					return nil, s390.WebTerminal{}, err
				}
			}
		case ev.cmd == wont && ev.opt == optTType:
			return nil, s390.WebTerminal{}, errors.New("tn3270: client refused terminal type")
		case len(ev.sub) >= 2 && ev.sub[0] == optTType && ev.sub[1] == 0:
			ss.devType = string(ev.sub[2:])
			if !strings.HasPrefix(strings.ToUpper(ss.devType), "IBM-327") && !strings.EqualFold(ss.devType, "IBM-DYNAMIC") {
				return nil, s390.WebTerminal{}, fmt.Errorf("tn3270: terminal type %q is not a 3270", ss.devType)
			}
			if err := tn.send(iac, do, optEOR, iac, will, optEOR, iac, do, optBin, iac, will, optBin); err != nil {
				return nil, s390.WebTerminal{}, err
			}
		case ev.cmd == will && (ev.opt == optEOR || ev.opt == optBin):
			agreed[[2]byte{will, ev.opt}] = true
		case ev.cmd == do && (ev.opt == optEOR || ev.opt == optBin):
			agreed[[2]byte{do, ev.opt}] = true
		case (ev.cmd == wont || ev.cmd == dont) && (ev.opt == optEOR || ev.opt == optBin):
			return nil, s390.WebTerminal{}, errors.New("tn3270: client refused binary or end-of-record")
		default:
			s.refuse(tn, ev)
		}
	}
	ss.extended = extendedType(ss.devType)
	term, _, ok := s.acquire("")
	if !ok {
		// Tell a plain 3270 client why, then hang up.
		msg := append([]byte{0xf5, 0xc3, 0x11, 0x40, 0x40}, s390.EncodeEBCDIC("NO 3270 TERMINAL IS FREE")...)
		_ = ss.writeRecord(msg)
		return nil, s390.WebTerminal{}, errors.New("tn3270: no display free")
	}
	return ss, term, nil
}

// refuse declines options the server does not offer.
func (s *Server) refuse(tn *telnet, ev event) {
	switch ev.cmd {
	case will:
		_ = tn.send(iac, dont, ev.opt)
	case do:
		_ = tn.send(iac, wont, ev.opt)
	}
}

func (s *Server) negotiateE(ctx context.Context, ss *session, events <-chan event) (*session, s390.WebTerminal, error) {
	tn := ss.tn
	ss.tn3270e = true
	sub := func(body ...byte) error {
		out := append([]byte{iac, sb, optTN3E}, body...)
		return tn.send(append(out, iac, se)...)
	}
	if err := sub(e3Send, e3DeviceType); err != nil {
		return nil, s390.WebTerminal{}, err
	}
	var term s390.WebTerminal
	have := false
	for {
		ev, err := s.await(ctx, events)
		if err != nil {
			if have {
				s.release(term)
			}
			return nil, s390.WebTerminal{}, err
		}
		if len(ev.sub) < 3 || ev.sub[0] != optTN3E {
			s.refuse(tn, ev)
			continue
		}
		body := ev.sub[1:]
		switch {
		case body[0] == e3DeviceType && body[1] == e3Request:
			rest := body[2:]
			typ, name := string(rest), ""
			if i := indexAny(rest, e3Connect, e3Associate); i >= 0 {
				typ = string(rest[:i])
				if rest[i] == e3Associate {
					_ = sub(e3DeviceType, e3Reject, e3Reason, 7) // printers are not offered
					continue
				}
				name = string(rest[i+1:])
			}
			if !strings.HasPrefix(strings.ToUpper(typ), "IBM-327") && !strings.EqualFold(typ, "IBM-DYNAMIC") {
				_ = sub(e3DeviceType, e3Reject, e3Reason, reasonInvType)
				continue
			}
			if have {
				s.release(term)
				have = false
			}
			t, reason, ok := s.acquire(name)
			// A client reconnecting at once may find its previous session
			// still being released: wait briefly before refusing.
			for wait := 0; !ok && reason == reasonInUse && name != "" && wait < 20; wait++ {
				time.Sleep(100 * time.Millisecond)
				t, reason, ok = s.acquire(name)
			}
			if !ok {
				_ = sub(e3DeviceType, e3Reject, e3Reason, reason)
				continue
			}
			term, have = t, true
			ss.devType = typ
			ss.extended = extendedType(typ)
			out := append([]byte{e3DeviceType, e3Is}, typ...)
			out = append(out, e3Connect)
			out = append(out, term.Name...)
			if err := sub(out...); err != nil {
				s.release(term)
				return nil, s390.WebTerminal{}, err
			}
		case body[0] == e3Functions && body[1] == e3Request:
			if !have {
				continue
			}
			if len(body) > 2 {
				// None of BIND-IMAGE, RESPONSES, SYSREQ or
				// DATA-STREAM-CTL is offered: propose the empty set.
				if err := sub(e3Functions, e3Request); err != nil {
					s.release(term)
					return nil, s390.WebTerminal{}, err
				}
				continue
			}
			if err := sub(e3Functions, e3Is); err != nil {
				s.release(term)
				return nil, s390.WebTerminal{}, err
			}
			return ss, term, nil
		case body[0] == e3Functions && body[1] == e3Is:
			if have {
				return ss, term, nil
			}
		}
	}
}

func indexAny(b []byte, xs ...byte) int {
	for i, c := range b {
		for _, x := range xs {
			if c == x {
				return i
			}
		}
	}
	return -1
}

// run mirrors the display to the client and applies its input.
func (s *Server) run(ctx context.Context, ss *session, term s390.WebTerminal, events <-chan event) error {
	d := term.Display
	model := modelOf(ss.devType)
	if model == 0 {
		model = 2 // IBM-DYNAMIC: the size is not negotiated here
	}
	// The display takes the client's screen size; programs learn it from
	// the query reply when the user logs on.
	s.live.Do(func(*s390.Machine) { _ = d.SetModel(model) })
	var mu sync.Mutex
	var queue [][]byte
	queued, redraw := 0, true
	signal := make(chan struct{}, 1)
	var cancelObs func()
	s.live.Do(func(*s390.Machine) {
		cancelObs = d.Observe(func(rec []byte) {
			if rec[0] == 0x7e && d.Model() != model {
				// The client cannot show this alternate size (another
				// viewer changed the model): show it as the default.
				rec = append([]byte{0xf5}, rec[1:]...)
			} else {
				rec = append([]byte(nil), rec...)
			}
			mu.Lock()
			if queued += len(rec); queued > 1<<20 {
				queue, queued, redraw = nil, 0, true
			} else {
				queue = append(queue, rec)
			}
			mu.Unlock()
			select {
			case signal <- struct{}{}:
			default:
			}
		})
	})
	defer s.live.Do(func(*s390.Machine) { cancelObs() })
	keepalive := time.NewTicker(60 * time.Second)
	defer keepalive.Stop()
	for {
		mu.Lock()
		out, again := queue, redraw
		queue, queued, redraw = nil, 0, false
		mu.Unlock()
		if again {
			var rec []byte
			s.live.Do(func(*s390.Machine) { rec = d.DataStream(ss.extended) })
			out = append([][]byte{rec}, out...)
		}
		for _, rec := range out {
			if err := ss.writeRecord(rec); err != nil {
				return err
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-signal:
		case <-keepalive.C:
			if err := ss.tn.send(iac, nop); err != nil {
				return err
			}
		case ev, ok := <-events:
			if !ok {
				return io.EOF
			}
			switch {
			case ev.record != nil:
				rec := ev.record
				if ss.tn3270e {
					if len(rec) < 5 || rec[0] != 0x00 { // only 3270-DATA is accepted
						s.logf("%s <- ignored TN3270E record, header %X", term.Name, rec[:min(5, len(rec))])
						continue
					}
					rec = rec[5:]
				}
				if ss.tn3270e {
					s.logf("%s <- header %X %s", term.Name, ev.record[:5], describe(rec))
				} else {
					s.logf("%s <- %s", term.Name, describe(rec))
				}
				s.live.Do(func(*s390.Machine) { d.Inbound(rec) })
			case ev.cmd == do && ev.opt == optTM:
				_ = ss.tn.send(iac, will, optTM)
			case ev.cmd == will || ev.cmd == do:
				if ev.opt != optBin && ev.opt != optEOR && ev.opt != optTType && ev.opt != optTN3E {
					s.refuse(ss.tn, ev)
				}
			}
		}
	}
}
