package labfrontend

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/tinyrange/trex/channel"
	"github.com/tinyrange/trex/vmm/ethernet"
)

// qemuEthernet adapts QEMU's length-prefixed Ethernet stream to a Trex switch
// port. The listener is local to the QEMU backend and accepts one peer.
func qemuEthernet(parent context.Context, switcher *ethernet.Switch) (string, func() error, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	closeListener := context.AfterFunc(ctx, func() { _ = listener.Close() })
	port := switcher.Connect()
	go func() {
		defer close(done)
		defer closeListener()
		defer port.Close()
		conn, err := listener.Accept()
		_ = listener.Close()
		if err != nil {
			return
		}
		defer conn.Close()
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		defer stop()

		inboundDone := make(chan struct{})
		go func() {
			defer close(inboundDone)
			defer conn.Close()
			var length [4]byte
			var frame [ethernet.MaxFrame]byte
			for {
				if _, err := io.ReadFull(conn, length[:]); err != nil {
					return
				}
				size := binary.BigEndian.Uint32(length[:])
				if size < 14 || size > ethernet.MaxFrame {
					return
				}
				if _, err := io.ReadFull(conn, frame[:size]); err != nil {
					return
				}
				if err := port.Send(frame[:size]); err != nil {
					return
				}
			}
		}()

		defer func() {
			_ = conn.Close()
			<-inboundDone
		}()
		tick := time.NewTicker(4 * time.Millisecond)
		defer tick.Stop()
		var packet [4 + ethernet.MaxFrame]byte
		for {
			select {
			case <-ctx.Done():
				return
			case <-inboundDone:
				return
			case <-tick.C:
				for frame := port.Receive(); frame != nil; frame = port.Receive() {
					binary.BigEndian.PutUint32(packet[:4], uint32(len(frame)))
					copy(packet[4:], frame)
					_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
					if channel.WriteAll(conn, packet[:4+len(frame)]) != nil {
						return
					}
				}
			}
		}
	}()
	return listener.Addr().String(), func() error {
		cancel()
		<-done
		return nil
	}, nil
}
