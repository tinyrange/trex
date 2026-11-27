package lab

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net/netip"
	"time"

	"github.com/tinyrange/trex/vmm/ethernet"
)

type webEthernet struct {
	port    *ethernet.Port
	mac     [6]byte
	address netip.Addr
	tcp     lanTCP
	change  func(string)
	log     func(string)
	dhcp    *webDHCP
}

func startWebEthernet(ctx context.Context, req StartRequest, listener *webListener, address netip.Addr, port uint16) <-chan struct{} {
	w := &webEthernet{
		port: req.Switch.Connect(), mac: hardwareAddress(req.Node.ID), address: address,
		change: req.Address, log: req.Log,
	}
	w.tcp = newLANTCP(w.port, w.mac, port, listener.deliver)
	if !address.IsValid() {
		w.dhcp = &webDHCP{}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer w.port.Close()
		defer w.tcp.close()
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				w.updateDHCP(now)
				for range 64 {
					frame := w.port.Receive()
					if frame == nil {
						break
					}
					w.receive(ctx, frame, now)
				}
				w.tcp.poll(now)
			}
		}
	}()
	return done
}

func (w *webEthernet) receive(ctx context.Context, frame []byte, now time.Time) {
	if len(frame) < 14 {
		return
	}
	to, from := [6]byte(frame[:6]), [6]byte(frame[6:12])
	if (to != w.mac && to != ethernetBroadcast) || from == w.mac || from == [6]byte{} || from[0]&1 != 0 {
		return
	}
	switch binary.BigEndian.Uint16(frame[12:]) {
	case 0x0806:
		if w.address.IsValid() {
			if reply := arpReply(frame[14:], from, w.mac, w.address.As4()); reply != nil {
				_ = w.port.Send(reply)
			}
		}
	case 0x0800:
		ip := frame[14:]
		if len(ip) < 20 || ip[0]>>4 != 4 {
			return
		}
		header, size := int(ip[0]&15)*4, int(binary.BigEndian.Uint16(ip[2:]))
		if header < 20 || size < header || size > len(ip) || binary.BigEndian.Uint16(ip[6:])&0x3fff != 0 || packetChecksum(ip[:header]) != 0 {
			return
		}
		fromIP, toIP := netip.AddrFrom4([4]byte(ip[12:16])), netip.AddrFrom4([4]byte(ip[16:20]))
		payload := ip[header:size]
		if ip[9] == 17 && w.dhcp != nil {
			w.receiveDHCP(fromIP, payload, now)
			return
		}
		if !w.address.IsValid() || to != w.mac || toIP != w.address || !usableLANIP(fromIP) || fromIP == w.address {
			return
		}
		if ip[9] == 1 && len(payload) >= 8 && payload[0] == 8 && payload[1] == 0 && packetChecksum(payload) == 0 {
			reply := ipv4Packet(from, w.mac, w.address.As4(), fromIP.As4(), 1, len(payload))
			copy(reply[34:], payload)
			reply[34], reply[36], reply[37] = 0, 0, 0
			binary.BigEndian.PutUint16(reply[36:], packetChecksum(reply[34:]))
			_ = w.port.Send(reply)
			return
		}
		if ip[9] == 6 {
			w.tcp.receive(ctx, frame[:14+size], payload, lanTCPPeerKey{from, fromIP}, w.address, now)
		}
	}
}

type webDHCP struct {
	xid       [4]byte
	requested netip.Addr
	server    netip.Addr
	next      time.Time
	expiry    time.Time
	renew     time.Time
	retries   int
}

func (w *webEthernet) updateDHCP(now time.Time) {
	d := w.dhcp
	if d == nil {
		return
	}
	if !d.expiry.IsZero() && !now.Before(d.expiry) {
		d.expiry, d.renew = time.Time{}, time.Time{}
		w.setAddress(netip.Addr{})
	}
	if now.Before(d.next) || w.address.IsValid() && now.Before(d.renew) {
		return
	}
	if d.retries == 0 || d.retries >= 3 {
		_, _ = rand.Read(d.xid[:])
		d.requested, d.server, d.retries = netip.Addr{}, netip.Addr{}, 0
	}
	w.sendDHCP(now)
}

func (w *webEthernet) sendDHCP(now time.Time) {
	d := w.dhcp
	payload := make([]byte, 240, 300)
	payload[0], payload[1], payload[2], payload[10] = 1, 1, 6, 0x80
	copy(payload[4:8], d.xid[:])
	copy(payload[28:34], w.mac[:])
	copy(payload[236:240], []byte{99, 130, 83, 99})
	if d.requested.IsValid() {
		ip, server := d.requested.As4(), d.server.As4()
		payload = append(payload, 53, 1, request, 50, 4)
		payload = append(payload, ip[:]...)
		payload = append(payload, 54, 4)
		payload = append(payload, server[:]...)
	} else {
		payload = append(payload, 53, 1, discover)
	}
	payload = append(payload, 255)
	payload = append(payload, make([]byte, 300-len(payload))...)
	frame := ipv4Packet(ethernetBroadcast, w.mac, [4]byte{}, ipv4Broadcast, 17, 8+len(payload))
	binary.BigEndian.PutUint32(frame[34:], 68<<16|67)
	binary.BigEndian.PutUint16(frame[38:], uint16(8+len(payload)))
	copy(frame[42:], payload)
	_ = w.port.Send(frame)
	d.next = now.Add(3 * time.Second)
	d.retries++
}

func (w *webEthernet) receiveDHCP(from netip.Addr, udp []byte, now time.Time) {
	d := w.dhcp
	if d.retries == 0 || len(udp) < 248 || binary.BigEndian.Uint32(udp[:4]) != 67<<16|68 {
		return
	}
	size := int(binary.BigEndian.Uint16(udp[4:6]))
	if size < 248 || size > len(udp) {
		return
	}
	p := udp[8:size]
	if p[0] != 2 || p[1] != 1 || p[2] != 6 || [4]byte(p[4:8]) != d.xid ||
		[6]byte(p[28:34]) != w.mac || [4]byte(p[236:240]) != [4]byte{99, 130, 83, 99} {
		return
	}
	options, ok := dhcpOptions(p[240:])
	if !ok || len(options[53]) != 1 || len(options[54]) != 4 {
		return
	}
	server, ip := netip.AddrFrom4([4]byte(options[54])), netip.AddrFrom4([4]byte(p[16:20]))
	if !usableLANIP(server) || from != server || (d.server.IsValid() && d.server != server) {
		return
	}
	switch options[53][0] {
	case offer:
		if !d.requested.IsValid() && usableLANIP(ip) {
			d.requested, d.server, d.retries = ip, server, 0
			w.sendDHCP(now)
		}
	case ack:
		if !d.requested.IsValid() || ip != d.requested || len(options[51]) != 4 {
			return
		}
		lease := time.Duration(binary.BigEndian.Uint32(options[51])) * time.Second
		if lease == 0 {
			return
		}
		d.expiry, d.renew = now.Add(lease), now.Add(lease/2)
		d.next, d.retries = d.renew, 0
		w.setAddress(ip)
	case nak:
		if d.requested.IsValid() {
			d.expiry, d.renew, d.retries = time.Time{}, time.Time{}, 0
			w.setAddress(netip.Addr{})
		}
	}
}

func (w *webEthernet) setAddress(ip netip.Addr) {
	if w.address == ip {
		return
	}
	w.tcp.close()
	w.address = ip
	if w.change != nil {
		address := ""
		if ip.IsValid() {
			address = ip.String()
		}
		w.change(address)
	}
	if w.log != nil {
		if ip.IsValid() {
			w.log("DHCP assigned " + ip.String())
		} else {
			w.log("DHCP lease ended")
		}
	}
}
