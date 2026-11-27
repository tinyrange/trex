package lab

import (
	"encoding/binary"
	"testing"
)

func TestNetworkObservesSenderAddress(t *testing.T) {
	s := newNetworkSegment()
	defer s.observer.Close()
	port := s.switcher.Connect()
	defer port.Close()
	var arp [42]byte
	for i := 0; i < 6; i++ {
		arp[i] = 0xff
	}
	mac := hardwareAddress("alpine")
	copy(arp[6:12], mac[:])
	binary.BigEndian.PutUint16(arp[12:14], 0x0806)
	binary.BigEndian.PutUint16(arp[14:16], 1)
	binary.BigEndian.PutUint16(arp[16:18], 0x0800)
	arp[18], arp[19] = 6, 4
	copy(arp[22:28], mac[:])
	copy(arp[28:32], []byte{10, 20, 0, 40})
	if err := port.Send(arp[:]); err != nil {
		t.Fatal(err)
	}
	if address := s.address("alpine"); address.String() != "10.20.0.40" || s.address("other").IsValid() {
		t.Fatalf("incorrect learned address: %v", address)
	}
	copy(arp[28:32], []byte{169, 254, 20, 40})
	if err := port.Send(arp[:]); err != nil {
		t.Fatal(err)
	}
	if address := s.address("alpine"); address.String() != "169.254.20.40" {
		t.Fatalf("incorrect link-local address: %v", address)
	}
	if err := port.Send(arp[:]); err != nil {
		t.Fatal(err)
	}
	s.forget("alpine")
	if address := s.address("alpine"); address.IsValid() {
		t.Fatalf("stopped guest address restored from queued traffic: %v", address)
	}
}
