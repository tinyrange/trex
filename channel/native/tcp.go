// Package native provides optional host transports for portable byte channels.
package native

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/tinyrange/trex/channel"
)

// TCPBridge owns a channel and one loopback TCP connection. It accepts exactly
// one client: reconnecting an RPC stream could replay or misattribute effects.
// Close interrupts both directions and joins all bridge workers. The supplied
// channel must either unblock Read and Write when closed or expose cooperative
// read and write-capacity notifications. It must not be used elsewhere.
type TCPBridge struct {
	listener net.Listener
	channel  channel.ByteChannel
	port     int
	mu       sync.Mutex
	client   net.Conn
	closed   bool
	once     sync.Once
	stopped  chan struct{}
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
	b := &TCPBridge{listener: listener, channel: stream, port: listener.Addr().(*net.TCPAddr).Port, stopped: make(chan struct{}), done: make(chan struct{})}
	go b.serve()
	return b, nil
}
func (b *TCPBridge) Port() int { return b.port }
func (b *TCPBridge) stop() {
	b.once.Do(func() {
		close(b.stopped)
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

// bridgeStream waits only at the native transport boundary. The underlying
// cooperative channel keeps its nonblocking operations and bounded queues.
type bridgeStream struct{ bridge *TCPBridge }

func (s bridgeStream) wait(changed <-chan struct{}) error {
	select {
	case <-s.bridge.stopped:
		return io.ErrClosedPipe
	case <-changed:
		return nil
	}
}

func (s bridgeStream) Read(p []byte) (int, error) {
	for {
		select {
		case <-s.bridge.stopped:
			return 0, io.ErrClosedPipe
		default:
		}
		var ready <-chan struct{}
		if notifier, ok := s.bridge.channel.(channel.ReadNotifier); ok {
			ready = notifier.ReadReady()
		}
		n, err := s.bridge.channel.Read(p)
		if !errors.Is(err, channel.ErrWouldBlock) || ready == nil {
			return n, err
		}
		if n > 0 {
			return n, nil
		}
		if err := s.wait(ready); err != nil {
			return 0, err
		}
	}
}

func (s bridgeStream) Write(p []byte) (int, error) {
	written := 0
	for len(p) != 0 {
		select {
		case <-s.bridge.stopped:
			return written, io.ErrClosedPipe
		default:
		}
		part := p
		var changed <-chan struct{}
		if notifier, ok := s.bridge.channel.(channel.WriteCapacityNotifier); ok {
			capacity, notification, err := notifier.WriteCapacity()
			if err != nil && !errors.Is(err, channel.ErrWriteCapacityUnsupported) {
				return written, err
			}
			if err == nil {
				changed = notification
				if capacity == 0 {
					if err := s.wait(changed); err != nil {
						return written, err
					}
					continue
				}
				part = p[:min(len(p), capacity)]
			}
		}
		n, err := s.bridge.channel.Write(part)
		written += n
		p = p[n:]
		if errors.Is(err, channel.ErrWouldBlock) && changed != nil {
			if err := s.wait(changed); err != nil {
				return written, err
			}
			continue
		}
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
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
	stream := bridgeStream{bridge: b}
	go copyStream(client, stream)
	go copyStream(stream, client)
	<-finished
	b.stop()
	<-finished
}
