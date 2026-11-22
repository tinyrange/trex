package tcpip

import (
	"bytes"
	device "renvo.dev/device/tcpip"
	"testing"
	"time"
)

// The independently implemented device TCP endpoint validates checksums and
// sequence numbers in packets produced by this client (and vice versa).
func TestClientAgainstDeviceTCP(t *testing.T) {
	c, err := NewClient(Config{Local: [4]byte{126, 240, 0, 1}, Remote: [4]byte{126, 240, 0, 2}, LocalPort: 32000, RemotePort: 23, Sequence: 0xfffffff0, MTU: 1024})
	if err != nil {
		t.Fatal(err)
	}
	s := &device.Echo{MAC: [6]byte{2, 0, 0, 0, 0, 2}, IP: [4]byte{126, 240, 0, 2}, Port: 23}
	peer := func(packet []byte, now time.Duration) []byte {
		frame := make([]byte, 14+len(packet))
		copy(frame, s.MAC[:])
		copy(frame[6:], []byte{2, 0, 0, 0, 0, 1})
		frame[12] = 8
		copy(frame[14:], packet)
		result := s.Handle(frame, uint32(now/time.Millisecond))
		if len(result) < 14 {
			return nil
		}
		return append([]byte(nil), result[14:]...)
	}
	flush := func(packet []byte, now time.Duration) {
		t.Helper()
		for i := 0; len(packet) != 0 && i < 8; i++ {
			response := peer(packet, now)
			if len(response) == 0 {
				return
			}
			packet, err = c.Input(response, now)
			if err != nil {
				t.Fatal(err)
			}
		}
		if len(packet) != 0 {
			t.Fatal("ACK exchange failed to settle")
		}
	}
	packet, err := c.Start(0)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := c.Poll(time.Second)
	if err != nil || !bytes.Equal(packet, retry) {
		t.Fatal("SYN retransmission changed packet")
	}
	packet = peer(retry, time.Second)
	if len(packet) == 0 {
		t.Fatal("device rejected SYN")
	}
	packet, err = c.Input(packet, time.Second)
	if err != nil || c.State() != "established" {
		t.Fatalf("handshake: %s %v", c.State(), err)
	}
	if reply := peer(packet, time.Second); len(reply) != 0 {
		t.Fatal("unexpected handshake response")
	}
	payload := make([]byte, 2051)
	for i := range payload {
		payload[i] = byte(i)
	}
	if err = c.Write(payload); err != nil {
		t.Fatal(err)
	}
	var received []byte
	for i := 0; i < 32 && len(received) < len(payload); i++ {
		now := time.Second + time.Duration(i+1)*time.Millisecond
		packet, err = c.Poll(now)
		if err != nil {
			t.Fatal(err)
		}
		if len(packet) == 0 {
			t.Fatal("no queued data")
		}
		response := peer(packet, now)
		if len(response) == 0 {
			t.Fatal("device rejected data")
		}
		bad := append([]byte(nil), response...)
		bad[len(bad)-1] ^= 1
		if reply, err := c.Input(bad, now); err != nil || len(reply) != 0 {
			t.Fatal("corrupt packet affected connection")
		}
		packet, err = c.Input(response, now)
		if err != nil {
			t.Fatal(err)
		}
		flush(packet, now)
		// A duplicate must provoke an ACK without duplicating application data.
		packet, err = c.Input(response, now)
		if err != nil || len(packet) == 0 {
			t.Fatal("duplicate not acknowledged")
		}
		flush(packet, now)
		data, err := c.Read(65535)
		if err != nil {
			t.Fatal(err)
		}
		received = append(received, data...)
	}
	if !bytes.Equal(received, payload) {
		t.Fatalf("echo length=%d expected=%d", len(received), len(payload))
	}
	c.Close()
	packet, err = c.Poll(2 * time.Second)
	if err != nil || len(packet) == 0 {
		t.Fatal("FIN missing")
	}
	packet = peer(packet, 2*time.Second)
	packet, err = c.Input(packet, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	peer(packet, 2*time.Second)
	if !c.EOF() || c.State() != "time-wait" {
		t.Fatalf("close: %s EOF=%v", c.State(), c.EOF())
	}
	c.Poll(123 * time.Second)
	if c.State() != "closed" {
		t.Fatal("TIME-WAIT never expired")
	}
	if _, err := c.Start(124 * time.Second); err == nil {
		t.Fatal("client reused sequence space after close")
	}
}

func TestClientBoundsAndTimeout(t *testing.T) {
	c, _ := NewClient(Config{Local: [4]byte{1, 1, 1, 1}, Remote: [4]byte{2, 2, 2, 2}, LocalPort: 1, RemotePort: 2})
	c.Start(0)
	if c.Write(make([]byte, 65536)) == nil {
		t.Fatal("unbounded send accepted")
	}
	if _, err := c.Read(0); err == nil {
		t.Fatal("invalid read size accepted")
	}
	for i := 1; i <= 7; i++ {
		c.Poll(time.Duration(i) * 10 * time.Second)
	}
	if c.State() != "closed" || c.Error() != "retransmission timeout" {
		t.Fatal("unanswered SYN did not time out")
	}
	if _, err := c.Poll(time.Second); err == nil {
		t.Fatal("backwards clock accepted")
	}
}

func TestCancelPendingConnection(t *testing.T) {
	c, _ := NewClient(Config{Local: [4]byte{1, 1, 1, 1}, Remote: [4]byte{2, 2, 2, 2}, LocalPort: 1, RemotePort: 2})
	c.Start(0)
	c.Close()
	if p, err := c.Poll(2 * time.Second); err != nil || p != nil || c.State() != "closed" {
		t.Fatal("cancelled connect kept retransmitting")
	}
}
