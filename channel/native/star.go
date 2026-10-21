package native

import (
	"fmt"
	channelstar "github.com/tinyrange/trex/channel/star"
	"github.com/tinyrange/trex/lifecycle"
	"go.starlark.net/starlark"
)

func ExposeTCPBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var stream *channelstar.Value
	port := 0
	if err := starlark.UnpackArgs("expose_tcp", args, kwargs, "channel", &stream, "port?", &port); err != nil {
		return nil, err
	}
	resources, err := lifecycle.ForThread(thread)
	if err != nil {
		return nil, err
	}
	bridge, err := ExposeTCP(stream, port)
	if err != nil {
		return nil, err
	}
	unregister, err := resources.Add(bridge)
	if err != nil {
		bridge.Close()
		return nil, err
	}
	return &bridgeValue{bridge: bridge, unregister: unregister}, nil
}

type bridgeValue struct {
	bridge     *TCPBridge
	unregister func()
}

func (b *bridgeValue) String() string {
	return fmt.Sprintf("<tcp_bridge 127.0.0.1:%d>", b.bridge.Port())
}
func (b *bridgeValue) Type() string          { return "tcp_bridge" }
func (b *bridgeValue) Freeze()               {}
func (b *bridgeValue) Truth() starlark.Bool  { return starlark.True }
func (b *bridgeValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: tcp_bridge") }
func (b *bridgeValue) AttrNames() []string   { return []string{"close", "port"} }
func (b *bridgeValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "port":
		return starlark.MakeInt(b.bridge.Port()), nil
	case "close":
		return starlark.NewBuiltin("close", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs("close", args, kwargs); err != nil {
				return nil, err
			}
			err := b.bridge.Close()
			b.unregister()
			return starlark.None, err
		}), nil
	}
	return nil, nil
}
