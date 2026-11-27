package lab

import (
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"sync"

	"github.com/tinyrange/trex/vmm/ethernet"
)

func hardwareAddress(id string) [6]byte {
	hash := sha256.Sum256([]byte(id))
	return [6]byte{2, 0x54, hash[0], hash[1], hash[2], hash[3]}
}

func usableLANIP(ip netip.Addr) bool {
	return ip.Is4() && (ip.IsGlobalUnicast() || ip.IsLinkLocalUnicast())
}

type networkSegment struct {
	switcher *ethernet.Switch
	observer *ethernet.Port
	mu       sync.Mutex
	seen     map[[6]byte]netip.Addr
}

func newNetworkSegment() *networkSegment {
	switcher := ethernet.NewSwitch()
	return &networkSegment{switcher: switcher, observer: switcher.Connect(), seen: make(map[[6]byte]netip.Addr)}
}

func (s *networkSegment) address(id string) netip.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.collect()
	return s.seen[hardwareAddress(id)]
}

func (s *networkSegment) collect() {
	for i := 0; i < 256; i++ {
		frame := s.observer.Receive()
		if len(frame) < 14 {
			break
		}
		if ip := sourceIPv4(frame); ip.IsGlobalUnicast() || ip.IsLinkLocalUnicast() {
			s.record([6]byte(frame[6:12]), ip)
		}
	}
}

func (s *networkSegment) record(mac [6]byte, ip netip.Addr) {
	if len(s.seen) < 256 || s.seen[mac].IsValid() {
		s.seen[mac] = ip
	}
}

func (s *networkSegment) recordLease(mac [6]byte, ip netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.collect()
	s.record(mac, ip)
}

func (s *networkSegment) forget(id string) {
	s.forgetHardware(hardwareAddress(id))
}

func (s *networkSegment) forgetHardware(mac [6]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.collect()
	delete(s.seen, mac)
}

// Learn from broadcasts and other traffic visible to this switch port.
func sourceIPv4(frame []byte) netip.Addr {
	if len(frame) < 14 {
		return netip.Addr{}
	}
	switch binary.BigEndian.Uint16(frame[12:14]) {
	case 0x0800:
		if len(frame) >= 34 && frame[14]>>4 == 4 && frame[14]&0xf >= 5 {
			return netip.AddrFrom4([4]byte(frame[26:30]))
		}
	case 0x0806:
		if len(frame) >= 42 && binary.BigEndian.Uint16(frame[14:]) == 1 && binary.BigEndian.Uint16(frame[16:]) == 0x0800 &&
			frame[18] == 6 && frame[19] == 4 && [6]byte(frame[6:12]) == [6]byte(frame[22:28]) {
			return netip.AddrFrom4([4]byte(frame[28:32]))
		}
	}
	return netip.Addr{}
}
