package tn3270

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/tinyrange/trex/emulator/s390"
)

type fixture struct {
	live     *s390.Live
	console  *s390.Console3270
	tso      *s390.Console3270
	server   *Server
	ctx      context.Context
	cancel   func()
	field    int // address of the input field on 0701
	encodeTo func(int) []byte
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	m := s390.NewMachine(s390.Config{Memory: 1 << 20, CPUs: 1, MIPS: 50})
	console, tso := s390.NewConsole3270(24, 80), s390.NewConsole3270(24, 80)
	m.CSS.AttachConsole(0x0700, console)
	m.CSS.AttachConsole(0x0701, tso)
	// 0701: blue "HELLO" (SFE protected, color X'F1'), then an unprotected
	// field at address 81.
	data := []byte{0xc3, 0x29, 0x02, 0xc0, 0x60, 0x42, 0xf1}
	data = append(data, s390.EncodeEBCDIC("HELLO")...)
	data = append(data, 0x11, 0x41, 0x50, 0x1d, 0x40, 0x13) // SBA 80, SF unprotected, IC
	tso.Exec(0x05, data, false)
	live := s390.NewLive(m, console, tso)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go live.Run(ctx)
	srv, err := New(live, []s390.WebTerminal{
		{Name: "0701", Device: 0x0701, Display: tso},
		{Name: "0700", Device: 0x0700, Display: console},
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.NegotiationTimeout = 2 * time.Second
	return &fixture{live: live, console: console, tso: tso, server: srv, ctx: ctx, cancel: cancel, field: 81}
}

// client is the test's side of the connection.
type client struct {
	t  *testing.T
	c  net.Conn
	tn *telnet
}

func (f *fixture) dial(t *testing.T) *client {
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close() })
	go f.server.ServeConn(f.ctx, b)
	return &client{t: t, c: a, tn: &telnet{r: bufio.NewReader(a), w: a}}
}

func (c *client) next() event {
	c.t.Helper()
	c.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	ev, err := c.tn.next()
	if err != nil {
		c.t.Fatal(err)
	}
	return ev
}

func (c *client) expectCmd(cmd, opt byte) {
	c.t.Helper()
	if ev := c.next(); ev.cmd != cmd || ev.opt != opt {
		c.t.Fatalf("got %+v, want %d %d", ev, cmd, opt)
	}
}

func (c *client) expectSub(want ...byte) {
	c.t.Helper()
	if ev := c.next(); !bytes.Equal(ev.sub, want) {
		c.t.Fatalf("subnegotiation %X, want %X", ev.sub, want)
	}
}

func (c *client) send(b ...byte) {
	c.t.Helper()
	if _, err := c.c.Write(b); err != nil {
		c.t.Fatal(err)
	}
}

func (c *client) sub(body ...byte) {
	c.send(append(append([]byte{iac, sb}, body...), iac, se)...)
}

func (c *client) record() []byte {
	c.t.Helper()
	for {
		if ev := c.next(); ev.record != nil {
			return ev.record
		}
	}
}

func e(s string) []byte { return s390.EncodeEBCDIC(s) }

// connectE negotiates TN3270E the way c3270 and wc3270 do, naming a device.
func (c *client) connectE(name string) []byte {
	c.t.Helper()
	c.expectCmd(do, optTN3E)
	c.send(iac, will, optTN3E)
	c.expectSub(optTN3E, e3Send, e3DeviceType)
	req := append([]byte{optTN3E, e3DeviceType, e3Request}, "IBM-3278-2-E"...)
	if name != "" {
		req = append(append(req, e3Connect), name...)
	}
	c.sub(req...)
	ev := c.next()
	return ev.sub
}

func TestTN3270EConnectMirrorAndInbound(t *testing.T) {
	f := newFixture(t)
	c := f.dial(t)
	got := c.connectE("LCL701")
	want := append(append([]byte{optTN3E, e3DeviceType, e3Is}, "IBM-3278-2-E"...), e3Connect)
	if !bytes.Equal(got, append(want, "0701"...)) {
		t.Fatalf("device type reply %q", got)
	}
	c.sub(optTN3E, e3Functions, e3Request, 0, 2, 4) // BIND-IMAGE, RESPONSES, SYSREQ
	c.expectSub(optTN3E, e3Functions, e3Request)
	c.sub(optTN3E, e3Functions, e3Is)

	// The redraw: TN3270E header, ERASE/WRITE, the colored protected field.
	rec := c.record()
	if !bytes.Equal(rec[:5], []byte{0, 0, 0, 0, 0}) || rec[5] != 0xf5 {
		t.Fatalf("redraw header %X", rec[:8])
	}
	if !bytes.Contains(rec, []byte{0x29, 3, 0xc0, 0x60, 0x41, 0x00, 0x42, 0xf1}) || !bytes.Contains(rec, e("HELLO")) {
		t.Fatalf("redraw %X", rec)
	}

	// A program write is forwarded with IAC doubled; ERASE/WRITE
	// ALTERNATE reaches a client of the display's model unchanged.
	f.live.Do(func(*s390.Machine) {
		f.tso.Exec(0x01, append([]byte{0xc2, 0x11, 0x40, 0x40}, 0xff), false)
		f.tso.Exec(0x0d, []byte{0xc3}, false)
	})
	if rec := c.record(); !bytes.Equal(rec[5:], []byte{0xf1, 0xc2, 0x11, 0x40, 0x40, 0xff}) || rec[4] != 1 {
		t.Fatalf("write record %X", rec)
	}
	if rec := c.record(); !bytes.Equal(rec[5:], []byte{0x7e, 0xc3}) {
		t.Fatalf("EWA record %X", rec)
	}
	f.live.Do(func(*s390.Machine) {
		f.tso.Exec(0x05, append([]byte{0xc3, 0x1d, 0x60}, append(e("USERID"), 0x1d, 0x40, 0x13)...), false)
	})
	c.record()

	// ENTER with the modified field: the model holds the text, the MDT
	// and the AID, and the keyboard is inhibited.
	in := []byte{0, 0, 0, 0, 0, 0x7d, 0x40, 0xd1, 0x11, 0x40, 0xc8}
	in = append(in, e("IBMUSER")...)
	c.send(append(in, iac, eor)...)
	deadline := time.Now().Add(5 * time.Second)
	for {
		var text string
		var locked bool
		f.live.Do(func(*s390.Machine) { s := f.tso.Screen(); text, locked = s.Text, s.Locked })
		if locked {
			if text[8:15] != "IBMUSER" {
				t.Fatalf("field %q", text[:20])
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("inbound record not applied")
		}
		time.Sleep(10 * time.Millisecond)
	}
	var rm []byte
	f.live.Do(func(*s390.Machine) { rm, _, _ = f.tso.Exec(0x06, nil, false) })
	if !bytes.Equal(rm, append([]byte{0x7d, 0x40, 0xd1, 0x11, 0x40, 0xc8}, e("IBMUSER")...)) {
		t.Fatalf("read modified %X", rm)
	}

	// The display is held: a second client naming it is rejected, and
	// one naming no display gets the next in the pool.
	c2 := f.dial(t)
	if got := c2.connectE("0701"); !bytes.Equal(got, []byte{optTN3E, e3DeviceType, e3Reject, e3Reason, reasonInUse}) {
		t.Fatalf("in-use reply %X", got)
	}
	c3 := f.dial(t)
	if got := c3.connectE(""); !bytes.HasSuffix(got, append([]byte{e3Connect}, "0700"...)) {
		t.Fatalf("pool reply %q", got)
	}
	c4 := f.dial(t)
	if got := c4.connectE("0999"); !bytes.Equal(got, []byte{optTN3E, e3DeviceType, e3Reject, e3Reason, reasonInvName}) {
		t.Fatalf("unknown reply %X", got)
	}
}

func TestPlainTN3270Negotiation(t *testing.T) {
	f := newFixture(t)
	c := f.dial(t)
	c.expectCmd(do, optTN3E)
	c.send(iac, wont, optTN3E)
	c.expectCmd(do, optTType)
	c.send(iac, will, optTType)
	c.expectSub(optTType, 1)
	c.sub(append([]byte{optTType, 0}, "IBM-3278-2"...)...)
	c.expectCmd(do, optEOR)
	c.expectCmd(will, optEOR)
	c.expectCmd(do, optBin)
	c.expectCmd(will, optBin)
	c.send(iac, will, optEOR, iac, do, optEOR, iac, will, optBin, iac, do, optBin)
	rec := c.record()
	// No header, and a non-extended terminal gets only basic attributes.
	if rec[0] != 0xf5 || bytes.Contains(rec, []byte{0x29}) || !bytes.Contains(rec, append([]byte{0x1d, 0x60}, e("HELLO")...)) {
		t.Fatalf("plain redraw %X", rec)
	}
	// PA1 is a short read: AID only.
	c.send(0x6c, iac, eor)
	deadline := time.Now().Add(5 * time.Second)
	for {
		var locked bool
		f.live.Do(func(*s390.Machine) { locked = f.tso.Locked() })
		if locked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("PA1 not applied")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A model 4 client makes its display a model 4: the query reply offers
// 43x80 and the program's alternate screen reaches the client unchanged.
func TestTN3270ModelSetsAlternateSize(t *testing.T) {
	f := newFixture(t)
	c := f.dial(t)
	c.expectCmd(do, optTN3E)
	c.send(iac, will, optTN3E)
	c.expectSub(optTN3E, e3Send, e3DeviceType)
	c.sub(append(append([]byte{optTN3E, e3DeviceType, e3Request}, "IBM-3278-4-E"...), append([]byte{e3Connect}, "0701"...)...)...)
	c.next()
	c.sub(optTN3E, e3Functions, e3Request)
	c.next() // FUNCTIONS IS
	c.record()
	var model int
	var reply []byte
	f.live.Do(func(*s390.Machine) {
		model = f.tso.Model()
		f.tso.Exec(0x11, []byte{0, 5, 1, 0xff, 2}, false)
		reply, _, _ = f.tso.Exec(0x02, nil, false)
	})
	if model != 4 || !bytes.Contains(reply, []byte{0x81, 0x81, 0x01, 0x00, 0x00, 80, 0x00, 43}) {
		t.Fatalf("model %d query reply %X", model, reply)
	}
	f.live.Do(func(*s390.Machine) { f.tso.Exec(0x0d, []byte{0xc3, 0x11, 0x5f, 0x7f, 0xc1}, false) })
	rec := c.record()
	if rec[5] != 0x7e {
		t.Fatalf("EWA record %X", rec)
	}
	var rows int
	f.live.Do(func(*s390.Machine) { rows = f.tso.Screen().Rows })
	if rows != 43 {
		t.Fatalf("display rows %d after EWA", rows)
	}
}
