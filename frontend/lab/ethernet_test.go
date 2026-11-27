package labfrontend

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tinyrange/trex/vmm/ethernet"
)

func TestQEMUEthernetBridgeFrames(t *testing.T) {
	network := ethernet.NewSwitch()
	observer := network.Connect()
	defer observer.Close()
	peer, closeBridge, err := qemuEthernet(t.Context(), network)
	if err != nil {
		t.Fatal(err)
	}
	defer closeBridge()
	conn, err := net.Dial("tcp", peer)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	frame := []byte{255, 255, 255, 255, 255, 255, 2, 0, 1, 2, 3, 4, 0x08, 0x00, 9}
	wire := binary.BigEndian.AppendUint32(nil, uint32(len(frame)))
	wire = append(wire, frame...)
	if _, err := conn.Write(wire); err != nil {
		t.Fatal(err)
	}
	poll := time.NewTicker(time.Millisecond)
	defer poll.Stop()
	deadline := time.After(2 * time.Second)
	for {
		if received := observer.Receive(); len(received) != 0 {
			if !bytes.Equal(received, frame) {
				t.Fatalf("switch received %x, want %x", received, frame)
			}
			break
		}
		select {
		case <-deadline:
			t.Fatal("switch did not receive the QEMU Ethernet frame")
		case <-poll.C:
		}
	}

	frame[11]++
	if err := observer.Send(frame); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, wire); err != nil {
		t.Fatal(err)
	}
	if size := binary.BigEndian.Uint32(wire); size != uint32(len(frame)) || !bytes.Equal(wire[4:], frame) {
		t.Fatalf("QEMU stream received %x", wire)
	}
}
