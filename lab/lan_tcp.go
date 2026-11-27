package lab

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"time"

	"github.com/tinyrange/trex/vmm/ethernet"
	ccnetwork "j5.nz/cc/network"
)

type lanTCPPeerKey struct {
	mac [6]byte
	ip  netip.Addr
}

type lanTCPPeer struct {
	network *ccnetwork.Isolated
	cancel  context.CancelFunc
	done    chan struct{}
	last    time.Time
}

func (p *lanTCPPeer) close() {
	p.cancel()
	p.network.Close()
	<-p.done
}

// lanTCP connects a lab Ethernet port to in-memory TCP listeners. Receive,
// poll, and close are called serially by the owner of the Ethernet port.
type lanTCP struct {
	port        ethernet.Endpoint
	mac         [6]byte
	service     uint16
	deliver     func(context.Context, net.Conn) error
	peers       map[lanTCPPeerKey]*lanTCPPeer
	nextCleanup time.Time
}

func newLANTCP(port ethernet.Endpoint, mac [6]byte, service uint16, deliver func(context.Context, net.Conn) error) lanTCP {
	return lanTCP{
		port: port, mac: mac, service: service, deliver: deliver,
		peers: make(map[lanTCPPeerKey]*lanTCPPeer),
	}
}

func (t *lanTCP) receive(ctx context.Context, frame, payload []byte, key lanTCPPeerKey, address netip.Addr, now time.Time) {
	if len(payload) < 20 || binary.BigEndian.Uint16(payload[2:]) != t.service {
		return
	}
	peer := t.peers[key]
	if peer == nil && payload[13]&0x12 == 0x02 && len(t.peers) < 64 {
		peer = t.startPeer(ctx, key, address)
	}
	if peer != nil {
		peer.last = now
		_ = peer.network.Receive(frame)
	}
}

func (t *lanTCP) startPeer(ctx context.Context, key lanTCPPeerKey, address netip.Addr) *lanTCPPeer {
	stack, err := ccnetwork.NewStaticPeer(key.mac, t.mac, key.ip, address)
	if err != nil {
		return nil
	}
	listener, err := stack.ListenTCP(t.service)
	if err != nil {
		stack.Close()
		return nil
	}
	ctx, cancel := context.WithCancel(ctx)
	peer := &lanTCPPeer{network: stack, cancel: cancel, done: make(chan struct{})}
	t.peers[key] = peer
	go func() {
		defer close(peer.done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if err := t.deliver(ctx, conn); err != nil {
				conn.Close()
				return
			}
		}
	}()
	return peer
}

func (t *lanTCP) poll(now time.Time) {
	cleanup := !now.Before(t.nextCleanup)
	for key, peer := range t.peers {
		if cleanup && now.Sub(peer.last) > time.Minute {
			peer.close()
			delete(t.peers, key)
			continue
		}
		for range 32 {
			frame := peer.network.Poll()
			if frame == nil {
				break
			}
			_ = t.port.Send(frame)
		}
	}
	if cleanup {
		t.nextCleanup = now.Add(time.Second)
	}
}

func (t *lanTCP) close() {
	for key, peer := range t.peers {
		peer.close()
		delete(t.peers, key)
	}
}
