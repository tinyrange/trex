// Package native provides optional host transports for portable byte channels.
package native

import (
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/tinyrange/trex/channel"
)

// TCPBridge owns a channel and one loopback TCP connection. It accepts exactly
// one client: reconnecting an RPC stream could replay or misattribute effects.
// Close interrupts both directions and joins all bridge workers. The supplied
// channel must unblock Read and Write when closed and must not be used elsewhere.
type TCPBridge struct {
	listener net.Listener
	channel  channel.ByteChannel
	port     int
	mu       sync.Mutex
	client   net.Conn
	closed   bool
	once     sync.Once
	done     chan struct{}
}

// ExposeTCP starts listening on IPv4 loopback. Port zero selects a free port.
// Ownership of stream transfers only on success.
func ExposeTCP(stream channel.ByteChannel, port int) (*TCPBridge, error) {
	if stream == nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("expose_tcp: invalid channel or port")
	}
	listener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, err
	}
	b := &TCPBridge{listener: listener, channel: stream, port: listener.Addr().(*net.TCPAddr).Port, done: make(chan struct{})}
	go b.serve()
	return b, nil
}
func (b *TCPBridge) Port() int { return b.port }
func (b *TCPBridge) stop() {
	b.once.Do(func() {
		b.mu.Lock()
		b.closed = true
		client := b.client
		b.mu.Unlock()
		b.listener.Close()
		if client != nil {
			client.Close()
		}
		b.channel.Close()
	})
}
func (b *TCPBridge) Close() error { b.stop(); <-b.done; return nil }
func (b *TCPBridge) serve() {
	defer close(b.done)
	defer b.stop()
	client, err := b.listener.Accept()
	if err != nil {
		return
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		client.Close()
		return
	}
	b.client = client
	b.mu.Unlock()
	b.listener.Close()
	finished := make(chan struct{}, 2)
	copyStream := func(dst io.Writer, src io.Reader) {
		// Fixed memory bound in each direction, independent of peer output volume.
		io.CopyBuffer(struct{ io.Writer }{dst}, struct{ io.Reader }{src}, make([]byte, 4096))
		finished <- struct{}{}
	}
	go copyStream(client, b.channel)
	go copyStream(b.channel, client)
	<-finished
	b.stop()
	<-finished
}
