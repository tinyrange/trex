package star

import (
	"math"
	"net"
	"testing"
	"time"

	channelpkg "github.com/tinyrange/trex/channel"
	"go.starlark.net/starlark"
)

func TestByteChannelReadSomeIsBoundedAndTimed(t *testing.T) {
	client, target := net.Pipe()
	defer client.Close()
	defer target.Close()
	value := New("test", client)
	go func() { _, _ = target.Write([]byte("hel")) }()
	result, err := value.readSomeBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("maximum"), starlark.MakeInt(3)},
		{starlark.String("timeout"), starlark.Float(1)},
	})
	if err != nil || result != starlark.Bytes("hel") {
		t.Fatalf("read_some = %v, %v", result, err)
	}
	started := time.Now()
	_, err = value.readSomeBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("maximum"), starlark.MakeInt(1)},
		{starlark.String("timeout"), starlark.Float(0.01)},
	})
	if err == nil || time.Since(started) > time.Second {
		t.Fatalf("timed read error/duration = %v, %s", err, time.Since(started))
	}
}

func TestReadyByteChannelIsSelectableAndBounded(t *testing.T) {
	client, target := net.Pipe()
	defer target.Close()
	buffered := channelpkg.NewReadyByteChannel(client, 4)
	defer buffered.Close()
	value := New("serial", buffered)
	if value.DebugReady() == nil {
		t.Fatal("buffered channel does not expose readiness")
	}
	go func() { _, _ = target.Write([]byte("test")) }()
	select {
	case <-value.DebugReady():
	case <-time.After(time.Second):
		t.Fatal("channel did not become readable")
	}
	result, err := value.readSomeBuiltin(nil, nil, nil, []starlark.Tuple{
		{starlark.String("maximum"), starlark.MakeInt(4)},
		{starlark.String("timeout"), starlark.Float(1)},
	})
	if err != nil || result != starlark.Bytes("test") {
		t.Fatalf("read_some = %v, %v", result, err)
	}
	select {
	case <-value.DebugReady():
		t.Fatal("readiness remained signaled after draining the channel")
	default:
	}
}

func TestStarlarkNumberAcceptsIntAndFloat(t *testing.T) {
	for _, value := range []starlark.Value{starlark.MakeInt(30), starlark.Float(0.25)} {
		var number starlarkNumber
		if err := number.Unpack(value); err != nil {
			t.Fatalf("unpack %s: %v", value, err)
		}
	}
	for _, value := range []starlark.Value{starlark.String("1"), starlark.Float(math.Inf(1))} {
		var number starlarkNumber
		if err := number.Unpack(value); err == nil {
			t.Fatalf("accepted %s", value)
		}
	}
}
