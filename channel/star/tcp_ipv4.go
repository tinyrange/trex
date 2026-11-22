package star

import (
	"fmt"
	"github.com/tinyrange/trex/network/tcpip"
	"go.starlark.net/starlark"
	"net/netip"
	"time"
)

type packetTCP struct{ client *tcpip.Client }

func (v *packetTCP) CaptureCheckpoint() (func() error, error) { return v.client.CaptureCheckpoint() }

func (p *packetTCP) String() string      { return "<packet_tcp " + p.client.State() + ">" }
func (*packetTCP) Type() string          { return "packet_tcp" }
func (*packetTCP) Freeze()               {}
func (*packetTCP) Truth() starlark.Bool  { return starlark.True }
func (*packetTCP) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: packet_tcp") }
func (*packetTCP) AttrNames() []string {
	return []string{"start", "input", "poll", "write", "read", "close", "state", "error", "eof"}
}
func (p *packetTCP) Attr(name string) (starlark.Value, error) {
	switch name {
	case "state":
		return starlark.String(p.client.State()), nil
	case "error":
		return starlark.String(p.client.Error()), nil
	case "eof":
		return starlark.Bool(p.client.EOF()), nil
	case "start", "input", "poll", "write", "read", "close":
		return starlark.NewBuiltin(name, func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			return p.call(name, args, kwargs)
		}), nil
	}
	return nil, nil
}
func (p *packetTCP) call(name string, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var data starlark.Bytes
	var now starlarkNumber
	maximum := 65535
	switch name {
	case "write":
		if err := starlark.UnpackArgs(name, args, kwargs, "data", &data); err != nil {
			return nil, err
		}
		if err := p.client.Write([]byte(data)); err != nil {
			return nil, err
		}
		return starlark.None, nil
	case "read":
		if err := starlark.UnpackArgs(name, args, kwargs, "maximum?", &maximum); err != nil {
			return nil, err
		}
		data, err := p.client.Read(maximum)
		return starlark.Bytes(data), err
	case "close":
		if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
			return nil, err
		}
		p.client.Close()
		return starlark.None, nil
	case "input":
		if err := starlark.UnpackArgs(name, args, kwargs, "packet", &data, "now?", &now); err != nil {
			return nil, err
		}
	default:
		if err := starlark.UnpackArgs(name, args, kwargs, "now?", &now); err != nil {
			return nil, err
		}
	}
	if now < 0 || now > 1e9 {
		return nil, fmt.Errorf("packet_tcp: now must be0..1e9 monotonic seconds")
	}
	at := time.Duration(float64(now) * float64(time.Second))
	var packet []byte
	var err error
	switch name {
	case "input":
		packet, err = p.client.Input([]byte(data), at)
	case "start":
		packet, err = p.client.Start(at)
	case "poll":
		packet, err = p.client.Poll(at)
	}
	if err != nil {
		return nil, err
	}
	if packet == nil {
		return starlark.None, nil
	}
	return starlark.Bytes(packet), nil
}
func tcpIPv4Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var local, remote string
	var lp, rp int
	mtu, sequence := 1024, uint32(1)
	if err := starlark.UnpackArgs("tcp_ipv4", args, kwargs, "local", &local, "remote", &remote, "local_port", &lp, "remote_port", &rp, "sequence?", &sequence, "mtu?", &mtu); err != nil {
		return nil, err
	}
	l, err := netip.ParseAddr(local)
	if err != nil || !l.Is4() {
		return nil, fmt.Errorf("tcp_ipv4: local must be an IPv4 address")
	}
	r, err := netip.ParseAddr(remote)
	if err != nil || !r.Is4() {
		return nil, fmt.Errorf("tcp_ipv4: remote must be an IPv4 address")
	}
	if lp < 1 || lp > 65535 || rp < 1 || rp > 65535 {
		return nil, fmt.Errorf("tcp_ipv4: invalid port")
	}
	c, err := tcpip.NewClient(tcpip.Config{Local: l.As4(), Remote: r.As4(), LocalPort: uint16(lp), RemotePort: uint16(rp), Sequence: sequence, MTU: mtu})
	if err != nil {
		return nil, err
	}
	return &packetTCP{client: c}, nil
}
