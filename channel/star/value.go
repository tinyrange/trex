package star

import (
	"fmt"
	"io"
	"math"
	"sync"
	"time"

	channelpkg "github.com/tinyrange/trex/channel"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

const defaultChannelReadLimit = 8 << 20

type starlarkNumber float64

func (n *starlarkNumber) Unpack(value starlark.Value) error {
	number, ok := starlark.AsFloat(value)
	if !ok || math.IsNaN(number) || math.IsInf(number, 0) {
		return fmt.Errorf("got %s, want finite int or float", value.Type())
	}
	*n = starlarkNumber(number)
	return nil
}

// ByteChannel is the stable duplex transport contract shared by VMM control,
// debugger, serial, display, and block protocols. Implementations may be local,
// embedded, remote, or browser-backed.
type ByteChannel = channelpkg.ByteChannel
type channelDeadlineSetter = channelpkg.DeadlineSetter
type channelReadNotifier = channelpkg.ReadNotifier

type Value struct {
	name    string
	channel ByteChannel
	readMu  sync.Mutex
	writeMu sync.Mutex
	close   sync.Once
	err     error
}

func New(name string, channel ByteChannel) *Value {
	return &Value{name: name, channel: channel}
}

func (c *Value) String() string { return fmt.Sprintf("<byte_channel %q>", c.name) }
func (c *Value) DebugReady() <-chan struct{} {
	if notifier, ok := c.channel.(channelReadNotifier); ok {
		return notifier.ReadReady()
	}
	return nil
}
func (c *Value) Type() string         { return "byte_channel" }
func (c *Value) Freeze()              {}
func (c *Value) Truth() starlark.Bool { return starlark.True }
func (c *Value) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", c.Type())
}
func (c *Value) Attr(name string) (starlark.Value, error) {
	switch name {
	case "read":
		return starlark.NewBuiltin("read", c.readBuiltin), nil
	case "read_some":
		return starlark.NewBuiltin("read_some", c.readSomeBuiltin), nil
	case "write":
		return starlark.NewBuiltin("write", c.writeBuiltin), nil
	case "close":
		return starlark.NewBuiltin("close", c.closeBuiltin), nil
	case "name":
		return starlark.String(c.name), nil
	}
	return nil, nil
}
func (c *Value) AttrNames() []string {
	return []string{"close", "name", "read", "read_some", "write"}
}

func (c *Value) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	return c.channel.Read(p)
}

func (c *Value) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.channel.Write(p)
}

func (c *Value) Close() error {
	c.close.Do(func() { c.err = c.channel.Close() })
	return c.err
}

func (c *Value) SetDeadline(deadline time.Time) error {
	setter, ok := c.channel.(channelDeadlineSetter)
	if !ok {
		return channelpkg.ErrDeadlinesUnsupported
	}
	return setter.SetDeadline(deadline)
}

func (c *Value) readBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	size := 0
	maximum := defaultChannelReadLimit
	if err := starlark.UnpackArgs("read", args, kwargs, "size", &size, "maximum?", &maximum); err != nil {
		return nil, err
	}
	if size < 0 || maximum < 0 || size > maximum || maximum > defaultChannelReadLimit {
		return nil, fmt.Errorf("read: invalid size or maximum")
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(c, data); err != nil {
		return nil, err
	}
	return starlark.Bytes(data), nil
}

func (c *Value) readSomeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	maximum := 64 << 10
	timeout := starlarkNumber(30)
	if err := starlark.UnpackArgs("read_some", args, kwargs, "maximum?", &maximum, "timeout?", &timeout); err != nil {
		return nil, err
	}
	if maximum <= 0 || maximum > defaultChannelReadLimit || timeout < 0 || timeout > 86400 {
		return nil, fmt.Errorf("read_some: invalid maximum or timeout")
	}
	setter, ok := c.channel.(channelDeadlineSetter)
	if !ok {
		return nil, fmt.Errorf("read_some: channel does not support bounded reads")
	}
	if err := setter.SetDeadline(time.Now().Add(time.Duration(float64(timeout) * float64(time.Second)))); err != nil {
		return nil, err
	}
	defer setter.SetDeadline(time.Time{})
	data := make([]byte, maximum)
	c.readMu.Lock()
	read, err := c.channel.Read(data)
	c.readMu.Unlock()
	if err != nil {
		return nil, err
	}
	return starlark.Bytes(data[:read]), nil
}

func (c *Value) writeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("write", args, kwargs, "value", &value); err != nil {
		return nil, err
	}
	data, err := starfile.BytesForValue(value, defaultChannelReadLimit)
	if err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}
	if _, err := c.Write(data); err != nil {
		return nil, err
	}
	return starlark.MakeInt(len(data)), nil
}

func (c *Value) closeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("close", args, kwargs); err != nil {
		return nil, err
	}
	if err := c.Close(); err != nil {
		return nil, err
	}
	return starlark.None, nil
}
