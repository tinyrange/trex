package cc

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/tinyrange/trex/vmm/ethernet"
	"j5.nz/cc/hypervisor"
)

func TestNE2000ReceiveWrapDMAAndIRQ(t *testing.T) {
	s := ethernet.NewSwitch()
	peer := s.Connect()
	mac := [6]byte{2, 0, 0, 0, 0, 1}
	level := false
	n := newNE2000(s.Connect(), mac, func(v bool) error { level = v; return nil })
	n.command = 0x22
	n.start = 0x40
	n.stop = 0x44
	n.current = 0x43
	n.boundary = 0x42
	n.imr = 1
	frame := make([]byte, 300)
	copy(frame, mac[:])
	copy(frame[6:], []byte{2, 0, 0, 0, 0, 2})
	for i := 14; i < len(frame); i++ {
		frame[i] = byte(i)
	}
	peer.Send(frame)
	if err := n.poll(); err != nil {
		t.Fatal(err)
	}
	if !level || n.current != 0x41 || n.isr&1 == 0 {
		t.Fatalf("receive state %+v", n.current)
	}
	n.remote = 0x4300
	n.remaining = uint16(len(frame) + 8)
	data := make([]byte, len(frame)+8)
	if err := n.io(hypervisor.X86Exit{Port: 0x310, Size: 2, Count: uint32(len(data) / 2), Data: data}); err != nil {
		t.Fatal(err)
	}
	if data[1] != 0x41 || binary.LittleEndian.Uint16(data[2:]) != 304 || !bytes.Equal(data[4:304], frame) {
		t.Fatal("ring header or DMA wrap")
	}
	n.write(7, 1)
	n.updateIRQ()
	if level || n.remaining != 0 || n.isr&0x40 == 0 {
		t.Fatal("IRQ acknowledgement or DMA completion")
	}
	// Filling a ring must preserve the unread boundary, not overwrite it.
	n.current = 0x41
	before := n.mem
	n.receive(frame, false)
	if n.isr&0x10 == 0 || n.mem != before {
		t.Fatal("overflow overwrote unread packet")
	}
}

func TestNE2000PROMByteReadInWordMode(t *testing.T) {
	mac := [6]byte{2, 0, 0, 0, 0, 7}
	n := newNE2000(ethernet.NewSwitch().Connect(), mac, func(bool) error { return nil })
	n.dataConfig = 1
	n.remote = 0
	n.remaining = 12
	data := make([]byte, 6)
	if err := n.io(hypervisor.X86Exit{Port: 0x310, Size: 1, Count: 6, Data: data}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, mac[:]) || n.remaining != 0 {
		t.Fatal("word-mode PROM", data, n.remaining)
	}
}

func TestNE2000TransmitAndReceiveFiltering(t *testing.T) {
	s := ethernet.NewSwitch()
	peer := s.Connect()
	n := newNE2000(s.Connect(), [6]byte{2, 0, 0, 0, 0, 1}, func(bool) error { return nil })
	frame := make([]byte, 60)
	copy(frame, []byte{2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1})
	n.remote, n.remaining, n.dataConfig = 0x4000, 60, 1
	if err := n.io(hypervisor.X86Exit{Port: 0x310, Size: 2, Count: 30, Write: true, Data: frame}); err != nil {
		t.Fatal(err)
	}
	n.txPage, n.txCount = 0x40, 60
	if err := n.write(0, 0x26); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(peer.Receive(), frame) || n.tx != 1 || n.txStatus != 1 || n.command&4 != 0 {
		t.Fatal("transmit completion")
	}
	n.start, n.stop, n.current, n.boundary = 0x4c, 0x80, 0x4d, 0x4c
	n.receive(frame, false)
	if n.rx != 0 {
		t.Fatal("accepted another unicast address")
	}
	for i := 0; i < 6; i++ {
		frame[i] = 255
	}
	n.receive(frame, false)
	if n.rx != 0 {
		t.Fatal("broadcast accepted with AB disabled")
	}
	n.receiveConfig = 4
	n.receive(frame, false)
	if n.rx != 1 || n.rxStatus != 0x21 {
		t.Fatal("broadcast filtering")
	}
}
