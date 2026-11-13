package starlarkfrontend

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/tinyrange/trex/emulator/s390"
	ccnetwork "j5.nz/cc/network"
)

// The CTC link is point to point: the bridge presents it to the userspace
// network stack as an Ethernet peer with fixed addresses, answers ARP on
// the guest's behalf, and forwards chosen host ports to guest ports.
var (
	ctcGuestMAC = [6]byte{0x02, 0x00, 0x00, 0x00, 0x39, 0x02}
	ctcHostMAC  = [6]byte{0x02, 0x00, 0x00, 0x00, 0x39, 0x01}
)

// startNetwork connects a machine's CTC adapter to an isolated network
// and opens its host port forwards. It stops when ctx is done.
func startNetwork(ctx context.Context, live *s390.Live, spec *s390.NetworkSpec, logf func(string, ...any)) error {
	ip := net.ParseIP(spec.Address).To4()
	if ip == nil {
		return fmt.Errorf("network: guest address %q is not IPv4", spec.Address)
	}
	n, err := ccnetwork.NewIsolated(ctcGuestMAC, ctcHostMAC)
	if err != nil {
		return err
	}
	if err := n.SetGuestIPv4(ip); err != nil {
		n.Close()
		return err
	}
	var listeners []net.Listener
	for host, port := range spec.Forwards {
		if err := validateScriptedWebAddress(host); err != nil {
			n.Close()
			return fmt.Errorf("network forward %s: %w", host, err)
		}
		l, err := net.Listen("tcp", host)
		if err != nil {
			n.Close()
			return err
		}
		listeners = append(listeners, l)
		logf("network: %s forwards to %s port %d", l.Addr(), spec.Address, port)
		go forward(ctx, l, n, uint16(port))
	}
	out := make(chan []byte, 1024)
	live.Do(func(*s390.Machine) {
		spec.CTC.Out = func(p []byte) {
			select {
			case out <- p:
			default: // congested: drop, as a busy link does
			}
		}
	})
	go func() {
		defer func() {
			for _, l := range listeners {
				l.Close()
			}
			n.Close()
		}()
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		var inbound [][]byte
		for {
			select {
			case <-ctx.Done():
				return
			case p := <-out:
				frame := make([]byte, 0, 14+len(p))
				frame = append(frame, ctcHostMAC[:]...)
				frame = append(frame, ctcGuestMAC[:]...)
				frame = append(frame, 0x08, 0x00)
				_ = n.Receive(append(frame, p...))
				continue
			case <-tick.C:
			}
			inbound = inbound[:0]
			for f := n.Poll(); f != nil; f = n.Poll() {
				if len(f) < 14 {
					continue
				}
				switch uint16(f[12])<<8 | uint16(f[13]) {
				case 0x0800:
					inbound = append(inbound, f[14:])
				case 0x0806:
					if reply := arpReply(f); reply != nil {
						_ = n.Receive(reply)
					}
				}
			}
			if len(inbound) > 0 {
				live.Do(func(*s390.Machine) {
					for _, p := range inbound {
						spec.CTC.Deliver(p)
					}
				})
			}
		}
	}()
	return nil
}

// arpReply answers an ARP request for any address with the guest's MAC:
// everything beyond the stack is reached over the CTC link.
func arpReply(f []byte) []byte {
	if len(f) < 42 || f[20] != 0 || f[21] != 1 { // not a request
		return nil
	}
	r := make([]byte, 42)
	copy(r[0:6], f[6:12])
	copy(r[6:12], ctcGuestMAC[:])
	r[12], r[13] = 0x08, 0x06
	copy(r[14:20], f[14:20]) // hardware/protocol types and sizes
	r[20], r[21] = 0, 2      // reply
	copy(r[22:28], ctcGuestMAC[:])
	copy(r[28:32], f[38:42]) // the address asked about
	copy(r[32:38], f[22:28])
	copy(r[38:42], f[28:32])
	return r
}

// forward proxies connections on l to a guest TCP port.
func forward(ctx context.Context, l net.Listener, n *ccnetwork.Isolated, port uint16) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
			g, err := n.DialGuest(dctx, port)
			cancel()
			if err != nil {
				return
			}
			defer g.Close()
			var wg sync.WaitGroup
			wg.Add(2)
			go func() { defer wg.Done(); io.Copy(g, c); closeWrite(g) }()
			go func() { defer wg.Done(); io.Copy(c, g); closeWrite(c) }()
			wg.Wait()
		}()
	}
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	} else {
		c.Close()
	}
}
