package native

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tinyrange/trex/channel"
	channelstar "github.com/tinyrange/trex/channel/star"
)

func TestTCPBridgeDuplexAndDisconnect(t *testing.T) {
	host, guest := net.Pipe()
	defer guest.Close()
	bridge, err := ExposeTCP(host, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	client, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", bridge.Port()), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	guest.SetDeadline(time.Now().Add(3 * time.Second))
	payload := bytes.Repeat([]byte{0, 255, '\t', '\n', 42}, 4000)
	result := make(chan error, 1)
	go func() {
		received := make([]byte, len(payload))
		_, err := io.ReadFull(guest, received)
		if err == nil && !bytes.Equal(received, payload) {
			err = fmt.Errorf("request mismatch")
		}
		if err == nil {
			_, err = guest.Write(received)
		}
		result <- err
	}()
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, payload) {
		t.Fatal("response mismatch")
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if second, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", bridge.Port()), time.Second); err == nil {
		second.Close()
		t.Fatal("accepted second client")
	}
	client.Close()
	select {
	case <-bridge.done:
	case <-time.After(3 * time.Second):
		t.Fatal("disconnect did not stop bridge")
	}
	if _, err := guest.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("guest not closed: %v", err)
	}
}

type observedMemory struct {
	*channel.Memory
	readBlocked, writeBlocked chan struct{}
}

func observeMemory(memory *channel.Memory) *observedMemory {
	return &observedMemory{memory, make(chan struct{}, 1), make(chan struct{}, 1)}
}

func (m *observedMemory) Read(p []byte) (int, error) {
	n, err := m.Memory.Read(p)
	if err == channel.ErrWouldBlock {
		select {
		case m.readBlocked <- struct{}{}:
		default:
		}
	}
	return n, err
}

func (m *observedMemory) WriteCapacity() (int, <-chan struct{}, error) {
	capacity, changed, err := m.Memory.WriteCapacity()
	if capacity == 0 && err == nil {
		select {
		case m.writeBlocked <- struct{}{}:
		default:
		}
	}
	return capacity, changed, err
}

func waitBridgeEvent(t *testing.T, event <-chan struct{}) {
	t.Helper()
	select {
	case <-event:
	case <-time.After(3 * time.Second):
		t.Fatal("bridge did not reach expected state")
	}
}

func memoryReadFull(m *channel.Memory, p []byte) error {
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for len(p) > 0 {
		ready := m.ReadReady()
		n, err := m.ReadAvailable(p)
		p = p[n:]
		if err == channel.ErrWouldBlock {
			select {
			case <-ready:
			case <-timer.C:
				return fmt.Errorf("cooperative read timed out")
			}
		} else if err != nil {
			return err
		}
	}
	return nil
}

func memoryWriteAll(m *channel.Memory, p []byte) error {
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for len(p) > 0 {
		capacity, changed, err := m.WriteCapacity()
		if err != nil {
			return err
		}
		if capacity == 0 {
			select {
			case <-changed:
			case <-timer.C:
				return fmt.Errorf("cooperative write timed out")
			}
			continue
		}
		n, err := m.WriteAvailable(p[:min(len(p), capacity)])
		if err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}

func memoryBridge(t *testing.T, host *observedMemory) (*TCPBridge, net.Conn) {
	t.Helper()
	// ExposeTCPBuiltin passes a Starlark Value, so exercise capability
	// forwarding through that same wrapper rather than only raw Memory.
	bridge, err := ExposeTCP(channelstar.New("test-memory", host), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { bridge.Close() })
	client, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", bridge.Port()), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	client.SetDeadline(time.Now().Add(3 * time.Second))
	return bridge, client
}

func TestTCPBridgeCooperativeDuplexAndBackpressure(t *testing.T) {
	for _, capacity := range []int{1, 7, 4093} {
		t.Run(fmt.Sprint(capacity), func(t *testing.T) {
			host, guest, _ := channel.NewMemoryPair(capacity)
			observed := observeMemory(host)
			bridge, client := memoryBridge(t, observed)
			waitBridgeEvent(t, observed.readBlocked)
			request := bytes.Repeat([]byte{0, 255, 41, 32, 10}, 4000)
			response := bytes.Repeat([]byte{13, 10, 0, 78, 128}, 4000)
			if _, err := client.Write(request); err != nil {
				t.Fatal(err)
			}
			// No consumer has drained the bounded queue. Reaching this state
			// proves the bridge waits for capacity instead of aborting.
			waitBridgeEvent(t, observed.writeBlocked)
			got := make([]byte, len(request))
			readResult, writeResult := make(chan error, 1), make(chan error, 1)
			go func() { readResult <- memoryReadFull(guest, got) }()
			go func() { writeResult <- memoryWriteAll(guest, response) }()
			reply := make([]byte, len(response))
			if _, err := io.ReadFull(client, reply); err != nil {
				t.Fatal(err)
			}
			if err := <-readResult; err != nil {
				t.Fatal(err)
			}
			if err := <-writeResult; err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, request) || !bytes.Equal(reply, response) {
				t.Fatal("cooperative duplex bytes differ")
			}
			client.Close()
			waitBridgeEvent(t, bridge.done)
		})
	}
}

func TestTCPBridgeCooperativeCloseWaitingForCapacity(t *testing.T) {
	host, _, _ := channel.NewMemoryPair(1)
	observed := observeMemory(host)
	bridge, client := memoryBridge(t, observed)
	waitBridgeEvent(t, observed.readBlocked)
	if _, err := client.Write([]byte("blocked")); err != nil {
		t.Fatal(err)
	}
	waitBridgeEvent(t, observed.writeBlocked)
	closed := make(chan struct{})
	go func() { bridge.Close(); bridge.Close(); close(closed) }()
	waitBridgeEvent(t, closed)
}

func TestTCPBridgeCooperativeCheckpointWake(t *testing.T) {
	host, guest, _ := channel.NewMemoryPair(4)
	empty, _ := host.CaptureCheckpoint()
	host.Write([]byte("full"))
	guest.Write([]byte("snap"))
	snapshot, _ := host.CaptureCheckpoint()
	empty()
	observed := observeMemory(host)
	_, client := memoryBridge(t, observed)
	waitBridgeEvent(t, observed.readBlocked)
	snapshot()
	got := make([]byte, 4)
	if _, err := io.ReadFull(client, got); err != nil || string(got) != "snap" {
		t.Fatalf("restored read: %q %v", got, err)
	}
	client.Write([]byte("next"))
	waitBridgeEvent(t, observed.writeBlocked)
	// Discarding the captured full queue must wake the pending writer.
	empty()
	if err := memoryReadFull(guest, got); err != nil || string(got) != "next" {
		t.Fatalf("restored capacity: %q %v", got, err)
	}
}

func TestTCPBridgeCloseWaitingAndBlocked(t *testing.T) {
	for _, connect := range []bool{false, true} {
		t.Run(fmt.Sprint(connect), func(t *testing.T) {
			host, guest := net.Pipe()
			defer guest.Close()
			bridge, err := ExposeTCP(host, 0)
			if err != nil {
				t.Fatal(err)
			}
			if connect {
				client, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", bridge.Port()), time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				client.Write([]byte("blocked guest write"))
			}
			done := make(chan struct{})
			go func() { bridge.Close(); bridge.Close(); close(done) }()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("close blocked")
			}
		})
	}
}
