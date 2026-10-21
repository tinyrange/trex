package debug

import (
	"errors"
	"io"
	"testing"

	channelpkg "github.com/tinyrange/trex/channel"
	channelstar "github.com/tinyrange/trex/channel/star"
	"go.starlark.net/starlark"
)

func selectWithin(value starlark.Value, timeout int) (starlark.Value, error) {
	return SelectBuiltin(nil, nil, starlark.Tuple{starlark.NewList([]starlark.Value{value})},
		[]starlark.Tuple{{starlark.String("timeout"), starlark.MakeInt(timeout)}})
}

func TestSelectMemoryReadNotificationIsNotEOF(t *testing.T) {
	reader, writer, err := channelpkg.NewMemoryPair(16)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	value := channelstar.New("upload", reader)
	if got, err := selectWithin(value, 0); err != nil || got != starlark.None {
		t.Fatalf("empty open stream: %v, %v", got, err)
	}
	if _, err := writer.Write([]byte("profile")); err != nil {
		t.Fatal(err)
	}
	if got, err := selectWithin(value, 1); err != nil || got != value {
		t.Fatalf("queued bytes must be selectable, not EOF: %v, %v", got, err)
	}
	// Selection must not consume bytes or confuse a notification with a
	// read result. Draining the queue must restore non-readiness.
	buf := make([]byte, 16)
	if n, err := reader.Read(buf); err != nil || string(buf[:n]) != "profile" {
		t.Fatalf("queued bytes: %q, %v", buf[:n], err)
	}
	if got, err := selectWithin(value, 0); err != nil || got != starlark.None {
		t.Fatalf("drained open stream: %v, %v", got, err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if got, err := selectWithin(value, 1); err != nil || got != value {
		t.Fatalf("terminal read must be selectable: %v, %v", got, err)
	}
	if _, err := reader.Read(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("read owns EOF: %v", err)
	}
}

type closedDebugSession struct {
	starlark.Value
	ready <-chan struct{}
}

func (s *closedDebugSession) DebugReady() <-chan struct{} { return s.ready }

func TestSelectClosedDebugSessionStillReturnsEOF(t *testing.T) {
	ready := make(chan struct{})
	close(ready)
	value := &closedDebugSession{Value: starlark.String("session"), ready: ready}
	if _, err := selectWithin(value, 1); !errors.Is(err, io.EOF) {
		t.Fatalf("closed debugger session: %v", err)
	}
}
