// Package native connects private Ethernet switches to explicitly granted host networking.
package native

import (
	"context"
	"github.com/tinyrange/trex/vmm/ethernet"
	ccnetwork "j5.nz/cc/network"
	"sync"
	"time"
)

// Gateway owns a single-guest packet endpoint and its switch pump.
// Internet grants public IPv4 TCP and DNS only; no host socket is bound.
type Gateway struct {
	Network *ccnetwork.Isolated
	Switch  *ethernet.Switch
	port    *ethernet.Port
	cancel  context.CancelFunc
	done    chan struct{}
	once    sync.Once
}

func NewGateway(ctx context.Context, guest, host [6]byte, internet bool) (*Gateway, error) {
	constructor := ccnetwork.NewIsolated
	if internet {
		constructor = ccnetwork.NewInternet
	}
	network, err := constructor(guest, host)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	g := &Gateway{Network: network, Switch: ethernet.NewSwitch(), cancel: cancel, done: make(chan struct{})}
	g.port = g.Switch.Connect()
	go func() {
		defer close(g.done)
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			for i := 0; i < 256; i++ {
				incoming := g.port.Receive()
				if incoming != nil {
					_ = network.Receive(incoming)
				}
				outgoing := network.Poll()
				if outgoing != nil {
					g.port.Send(outgoing)
				}
				if incoming == nil && outgoing == nil {
					break
				}
			}
		}
	}()
	return g, nil
}
func (g *Gateway) Close() error {
	g.once.Do(func() { g.cancel(); <-g.done; g.Network.Close(); g.port.Close() })
	return nil
}
