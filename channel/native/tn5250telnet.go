package native

import (
	"errors"
	"fmt"
	"net"
	"sync"

	channelstar "github.com/tinyrange/trex/channel/star"
	"github.com/tinyrange/trex/lifecycle"
	"github.com/tinyrange/trex/network/tn5250"
	"github.com/tinyrange/trex/network/tn5250/telnet5250"
	"go.starlark.net/starlark"
)

// ServeTN5250TelnetBuiltin lets TN5250 client programs share a
// channel.tn5250 terminal's session over a host TCP address. The script
// keeps owning the terminal: sync forwards the host's display to clients
// and returns their input for the host connection.
func ServeTN5250TelnetBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	address := "127.0.0.1:0"
	public := false
	if err := starlark.UnpackArgs("serve_tn5250_telnet", args, kwargs, "terminal", &value, "address?", &address, "public?", &public); err != nil {
		return nil, err
	}
	term, ok := channelstar.Terminal5250(value)
	if !ok {
		return nil, fmt.Errorf("serve_tn5250_telnet: terminal must be a channel.tn5250 value")
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("serve_tn5250_telnet: address: %w", err)
	}
	if ip := net.ParseIP(host); !public && (ip == nil || !ip.IsLoopback()) {
		return nil, fmt.Errorf("serve_tn5250_telnet: %s is not a loopback address; pass public=True to serve other hosts", address)
	}
	resources, err := lifecycle.ForThread(thread)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("serve_tn5250_telnet: %w", err)
	}
	s := &telnetTerminal{terminal: term, relay: telnet5250.New(), listener: listener}
	s.wg.Add(1)
	go s.accept()
	unregister, err := resources.Add(s)
	if err != nil {
		s.Close()
		return nil, err
	}
	s.unregister = unregister
	return s, nil
}

type telnetTerminal struct {
	terminal   *tn5250.Terminal
	relay      *telnet5250.Relay
	listener   net.Listener
	wg         sync.WaitGroup
	mu         sync.Mutex
	conns      map[net.Conn]bool
	closed     bool
	unregister func()
}

func (s *telnetTerminal) accept() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			conn.Close()
			return
		}
		if s.conns == nil {
			s.conns = map[net.Conn]bool{}
		}
		s.conns[conn] = true
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.relay.Serve(conn)
			s.mu.Lock()
			delete(s.conns, conn)
			s.mu.Unlock()
		}()
	}
}

// Close stops listening, disconnects clients and joins their workers.
func (s *telnetTerminal) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	err := s.listener.Close()
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	return err
}

func (s *telnetTerminal) String() string        { return fmt.Sprintf("<telnet_tn5250 %s>", s.listener.Addr()) }
func (s *telnetTerminal) Type() string          { return "telnet_tn5250" }
func (s *telnetTerminal) Freeze()               {}
func (s *telnetTerminal) Truth() starlark.Bool  { return starlark.True }
func (s *telnetTerminal) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: telnet_tn5250") }
func (s *telnetTerminal) AttrNames() []string {
	return []string{"address", "clients", "close", "sync", "trace"}
}
func (s *telnetTerminal) Attr(name string) (starlark.Value, error) {
	switch name {
	case "address":
		return starlark.String(s.listener.Addr().String()), nil
	case "clients":
		var out []starlark.Value
		for _, t := range s.relay.Clients() {
			out = append(out, starlark.String(t))
		}
		return starlark.NewList(out), nil
	case "trace":
		return starlark.NewBuiltin("trace", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			after := 0
			if err := starlark.UnpackArgs("trace", args, kwargs, "after?", &after); err != nil {
				return nil, err
			}
			var out []starlark.Value
			for _, t := range s.relay.Trace(uint64(max(after, 0))) {
				out = append(out, starlark.Tuple{starlark.MakeUint64(t.Seq), starlark.Bool(t.FromClient), starlark.Bool(t.Forwarded), starlark.Bytes(t.Record)})
			}
			return starlark.NewList(out), nil
		}), nil
	case "sync":
		return starlark.NewBuiltin("sync", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs("sync", args, kwargs); err != nil {
				return nil, err
			}
			return starlark.Bytes(s.relay.Sync(s.terminal)), nil
		}), nil
	case "close":
		return starlark.NewBuiltin("close", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs("close", args, kwargs); err != nil {
				return nil, err
			}
			err := s.Close()
			if s.unregister != nil {
				s.unregister()
			}
			return starlark.None, err
		}), nil
	}
	return nil, nil
}
