package star

import (
	"errors"
	"fmt"
	"io"
	"sync"

	channelpkg "github.com/tinyrange/trex/channel"
	"go.starlark.net/starlark"
)

func Builtins() starlark.StringDict {
	return starlark.StringDict{"memory_pair": starlark.NewBuiltin("memory_pair", memoryPairBuiltin)}
}

func memoryPairBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	maximum := 1 << 20
	if err := starlark.UnpackArgs("memory_pair", args, kwargs, "maximum?", &maximum); err != nil {
		return nil, err
	}
	if maximum > 64<<20 {
		return nil, fmt.Errorf("memory_pair: capacity exceeds 64 MiB")
	}
	a, b, err := channelpkg.NewMemoryPair(maximum)
	if err != nil {
		return nil, err
	}
	return starlark.Tuple{New("memory:a", a), New("memory:b", b)}, nil
}

func (c *Value) readAvailableBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	maximum := 64 << 10
	if err := starlark.UnpackArgs("read_available", args, kwargs, "maximum?", &maximum); err != nil {
		return nil, err
	}
	if maximum <= 0 || maximum > defaultChannelReadLimit {
		return nil, fmt.Errorf("read_available: invalid maximum")
	}
	reader, ok := c.channel.(channelpkg.AvailableReader)
	if !ok {
		return nil, fmt.Errorf("read_available: channel does not support cooperative reads")
	}
	data := make([]byte, maximum)
	n, err := reader.ReadAvailable(data)
	if errors.Is(err, channelpkg.ErrWouldBlock) {
		return starlark.None, nil
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return starlark.Bytes(data[:n]), nil
}

func (c *Value) CaptureCheckpoint() (func() error, error) {
	checkpointable, ok := c.channel.(interface{ CaptureCheckpoint() (func() error, error) })
	if !ok {
		return nil, fmt.Errorf("channel %q does not support checkpoints", c.name)
	}
	restore, err := checkpointable.CaptureCheckpoint()
	if err != nil {
		return nil, err
	}
	return func() error {
		c.close = sync.Once{}
		c.err = nil
		return restore()
	}, nil
}

func (c *Value) writeAvailableBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Bytes
	if err := starlark.UnpackArgs("write_available", args, kwargs, "value", &value); err != nil {
		return nil, err
	}
	writer, ok := c.channel.(channelpkg.AvailableWriter)
	if !ok {
		return nil, fmt.Errorf("write_available: channel does not support cooperative writes")
	}
	n, err := writer.WriteAvailable([]byte(value))
	if errors.Is(err, channelpkg.ErrWouldBlock) {
		return starlark.None, nil
	}
	if errors.Is(err, io.ErrClosedPipe) {
		return starlark.MakeInt(-1), nil
	}
	if err != nil {
		return nil, err
	}
	return starlark.MakeInt(n), nil
}
