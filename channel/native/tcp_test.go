package native

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
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
