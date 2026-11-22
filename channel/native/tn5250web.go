package native

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	channelstar "github.com/tinyrange/trex/channel/star"
	"github.com/tinyrange/trex/lifecycle"
	"github.com/tinyrange/trex/network/tn5250"
	"github.com/tinyrange/trex/network/tn5250/web5250"
	"go.starlark.net/starlark"
)

// ServeTN5250Builtin serves a channel.tn5250 display to browsers on a host
// TCP address. The script keeps owning the terminal: sync publishes it and
// applies queued browser input.
func ServeTN5250Builtin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	address := "127.0.0.1:0"
	public := false
	notes := ""
	if err := starlark.UnpackArgs("serve_tn5250", args, kwargs, "terminal", &value, "address?", &address, "public?", &public, "notes?", &notes); err != nil {
		return nil, err
	}
	term, ok := channelstar.Terminal5250(value)
	if !ok {
		return nil, fmt.Errorf("serve_tn5250: terminal must be a channel.tn5250 value")
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("serve_tn5250: address: %w", err)
	}
	if ip := net.ParseIP(host); !public && (ip == nil || !ip.IsLoopback()) {
		return nil, fmt.Errorf("serve_tn5250: %s is not a loopback address; pass public=True to serve other hosts", address)
	}
	resources, err := lifecycle.ForThread(thread)
	if err != nil {
		return nil, err
	}
	server, err := web5250.New()
	if err != nil {
		return nil, err
	}
	if len(notes) > 16<<10 {
		return nil, fmt.Errorf("serve_tn5250: notes exceed 16 KiB")
	}
	server.Notes = notes
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("serve_tn5250: %w", err)
	}
	w := &webTerminal{terminal: term, server: server, listener: listener, http: &http.Server{Handler: server, ReadHeaderTimeout: 10 * time.Second}}
	go func() {
		if err := w.http.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			w.err.Store(&err)
		}
	}()
	unregister, err := resources.Add(w)
	if err != nil {
		w.Close()
		return nil, err
	}
	w.unregister = unregister
	return w, nil
}

type webTerminal struct {
	terminal   *tn5250.Terminal
	server     *web5250.Server
	listener   net.Listener
	http       *http.Server
	unregister func()
	err        atomic.Pointer[error] // set by the serving goroutine
	closed     bool
}

// Close stops serving; open viewers see the connection end.
func (w *webTerminal) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = w.http.Shutdown(ctx)
	return w.http.Close()
}

func (w *webTerminal) url() string {
	return fmt.Sprintf("http://%s/#%s", w.listener.Addr(), w.server.Token)
}

func (w *webTerminal) String() string        { return fmt.Sprintf("<web_tn5250 %s>", w.listener.Addr()) }
func (w *webTerminal) Type() string          { return "web_tn5250" }
func (w *webTerminal) Freeze()               {}
func (w *webTerminal) Truth() starlark.Bool  { return starlark.True }
func (w *webTerminal) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: web_tn5250") }
func (w *webTerminal) AttrNames() []string   { return []string{"close", "sync", "url", "wait"} }
func (w *webTerminal) Attr(name string) (starlark.Value, error) {
	switch name {
	case "url":
		return starlark.String(w.url()), nil
	case "sync":
		return starlark.NewBuiltin("sync", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			status := ""
			if err := starlark.UnpackArgs("sync", args, kwargs, "status?", &status); err != nil {
				return nil, err
			}
			if err := w.err.Load(); err != nil {
				return nil, fmt.Errorf("web_tn5250: %w", *err)
			}
			var out []byte
			for _, in := range w.server.Pending() {
				b, err := web5250.Apply(w.terminal, in)
				if err != nil {
					// A browser's malformed edit must not stop the
					// machine; report it on the page instead.
					status = "input rejected: " + err.Error()
					continue
				}
				out = append(out, b...)
			}
			w.server.Publish(w.terminal.Screen(), status)
			return starlark.Bytes(out), nil
		}), nil
	case "wait":
		return starlark.NewBuiltin("wait", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var seconds starlark.Value
			if err := starlark.UnpackArgs("wait", args, kwargs, "seconds", &seconds); err != nil {
				return nil, err
			}
			f, ok := starlark.AsFloat(seconds)
			if !ok || f < 0 || f > 1 {
				return nil, fmt.Errorf("wait: seconds must be a number from 0 to 1")
			}
			return starlark.Bool(w.server.Wait(time.Duration(f * float64(time.Second)))), nil
		}), nil
	case "close":
		return starlark.NewBuiltin("close", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs("close", args, kwargs); err != nil {
				return nil, err
			}
			err := w.Close()
			if w.unregister != nil {
				w.unregister()
			}
			return starlark.None, err
		}), nil
	}
	return nil, nil
}
