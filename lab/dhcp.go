package lab

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/tinyrange/trex/vmm/ethernet"
)

type dhcpSettings struct {
	address, first, last, dns netip.Addr
	mask                      [4]byte
	enabled                   bool
	lease                     time.Duration
}

func routerSettings(node Node, r Recipe) (dhcpSettings, string, error) {
	var settings dhcpSettings
	prefix, err := netip.ParsePrefix(node.String(r, "routerAddress"))
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() < 1 || prefix.Bits() > 30 {
		return settings, "routerAddress", errors.New("enter an IPv4 LAN address with a /1 to /30 prefix")
	}
	mask := ^uint32(0) << (32 - prefix.Bits())
	binary.BigEndian.PutUint32(settings.mask[:], mask)
	network := ipv4Number(prefix.Masked().Addr())
	broadcast := network | ^mask
	validHost := func(a netip.Addr) bool {
		return a.Is4() && ipv4Number(a) > network && ipv4Number(a) < broadcast
	}
	settings.address = prefix.Addr()
	if !validHost(settings.address) || !settings.address.IsGlobalUnicast() {
		return settings, "routerAddress", errors.New("choose a usable unicast LAN address within the subnet")
	}
	settings.enabled, _ = node.Value(r, "dhcp").(bool)
	if !settings.enabled {
		return settings, "", nil
	}
	settings.first, _ = netip.ParseAddr(node.String(r, "dhcpStart"))
	settings.last, _ = netip.ParseAddr(node.String(r, "dhcpEnd"))
	if !validHost(settings.first) {
		return settings, "dhcpStart", errors.New("the first lease address must be a usable address in the LAN subnet")
	}
	if !validHost(settings.last) || settings.last.Less(settings.first) {
		return settings, "dhcpEnd", errors.New("the last lease address must be in the LAN subnet and at or after the first address")
	}
	if !settings.address.Less(settings.first) && !settings.last.Less(settings.address) {
		return settings, "dhcpStart", errors.New("exclude the router’s own address from the DHCP range")
	}
	if raw := node.String(r, "dhcpDNS"); raw != "" {
		settings.dns, _ = netip.ParseAddr(raw)
		if !settings.dns.Is4() || !settings.dns.IsGlobalUnicast() {
			return settings, "dhcpDNS", errors.New("enter a unicast IPv4 DNS server")
		}
	}
	var minutes float64
	switch value := node.Value(r, "dhcpMinutes").(type) {
	case float64:
		minutes = value
	case int:
		minutes = float64(value)
	}
	if minutes < 1 || minutes > 10080 || float64(int(minutes)) != minutes {
		return settings, "dhcpMinutes", errors.New("use a lease length from 1 to 10080 whole minutes")
	}
	settings.lease = time.Duration(minutes) * time.Minute
	return settings, "", nil
}

func ipv4Number(address netip.Addr) uint32 {
	bytes := address.As4()
	return binary.BigEndian.Uint32(bytes[:])
}

type dhcpLease struct {
	address netip.Addr
	expires time.Time
}

type dhcpRouter struct {
	config   dhcpSettings
	mac      [6]byte
	port     *ethernet.Port
	segment  *networkSegment
	cancel   context.CancelFunc
	done     chan struct{}
	leases   map[[6]byte]dhcpLease
	declined map[netip.Addr]time.Time
}

func startDHCPRouter(ctx context.Context, node Node, recipe Recipe, segment *networkSegment) (*dhcpRouter, error) {
	cfg, _, err := routerSettings(node, recipe)
	if err != nil {
		return nil, err
	}
	if segment == nil {
		return nil, errors.New("the router needs a connection to an isolated switch")
	}
	life, cancel := context.WithCancel(ctx)
	router := &dhcpRouter{config: cfg, mac: hardwareAddress(node.ID), port: segment.switcher.Connect(), segment: segment, cancel: cancel, done: make(chan struct{}),
		leases: make(map[[6]byte]dhcpLease), declined: make(map[netip.Addr]time.Time)}
	go router.run(life)
	return router, nil
}

func (r *dhcpRouter) run(ctx context.Context) {
	defer close(r.done)
	defer r.port.Close()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			for i := 0; i < 64; i++ {
				frame := r.port.Receive()
				if frame == nil {
					break
				}
				if reply := r.receive(frame, now); reply != nil {
					_ = r.port.Send(reply)
				}
			}
		}
	}
}

func (r *dhcpRouter) Close() error        { r.cancel(); <-r.done; return nil }
func (r *dhcpRouter) Surfaces() []Surface { return nil }
func (r *dhcpRouter) Address() string     { return r.config.address.String() }
func (r *dhcpRouter) Message() string {
	if !r.config.enabled {
		return "LAN interface up. DHCP disabled."
	}
	return fmt.Sprintf("DHCP serving %s through %s", r.config.first, r.config.last)
}

var ethernetBroadcast = [6]byte{255, 255, 255, 255, 255, 255}
var ipv4Broadcast = [4]byte{255, 255, 255, 255}

func (r *dhcpRouter) receive(frame []byte, now time.Time) []byte {
	if len(frame) < 14 {
		return nil
	}
	from, to := [6]byte(frame[6:12]), [6]byte(frame[:6])
	if from == r.mac || from[0]&1 != 0 || from == [6]byte{} || to != r.mac && to != ethernetBroadcast {
		return nil
	}
	address := r.config.address.As4()
	switch binary.BigEndian.Uint16(frame[12:]) {
	case 0x0806:
		arp := frame[14:]
		if len(arp) < 28 || binary.BigEndian.Uint32(arp[:4]) != 0x00010800 ||
			binary.BigEndian.Uint32(arp[4:8]) != 0x06040001 ||
			[6]byte(arp[8:14]) != from || [4]byte(arp[24:28]) != address {
			return nil
		}
		reply := ethernetHeader(from, r.mac, 0x0806, 28)
		copy(reply[14:20], arp[:6])
		reply[21] = 2
		copy(reply[22:28], r.mac[:])
		copy(reply[28:32], address[:])
		copy(reply[32:42], arp[8:18])
		return reply
	case 0x0800:
		ip := frame[14:]
		if len(ip) < 20 || ip[0]>>4 != 4 {
			return nil
		}
		header, size := int(ip[0]&15)*4, int(binary.BigEndian.Uint16(ip[2:]))
		if header < 20 || size < header || size > len(ip) || binary.BigEndian.Uint16(ip[6:])&0x3fff != 0 || packetChecksum(ip[:header]) != 0 {
			return nil
		}
		target := [4]byte(ip[16:20])
		payload := ip[header:size]
		source := [4]byte(ip[12:16])
		if r.config.enabled && ip[9] == 17 && (target == address || target == ipv4Broadcast) {
			return r.dhcp(from, payload, now)
		}
		if ip[9] == 1 && target == address && len(payload) >= 8 && payload[0] == 8 && payload[1] == 0 && packetChecksum(payload) == 0 {
			reply := ipv4Packet(from, r.mac, address, source, 1, len(payload))
			copy(reply[34:], payload)
			reply[34], reply[36], reply[37] = 0, 0, 0
			binary.BigEndian.PutUint16(reply[36:], packetChecksum(reply[34:]))
			return reply
		}
	}
	return nil
}

const (
	discover = 1
	offer    = 2
	request  = 3
	decline  = 4
	ack      = 5
	nak      = 6
	release  = 7
	inform   = 8
)

func (r *dhcpRouter) dhcp(mac [6]byte, udp []byte, now time.Time) []byte {
	const fixed = 240
	if len(udp) < 8+fixed || binary.BigEndian.Uint32(udp[:4]) != 68<<16|67 {
		return nil
	}
	size := int(binary.BigEndian.Uint16(udp[4:]))
	if size < 8+fixed || size > len(udp) {
		return nil
	}
	packet := udp[8:size]
	if [4]byte(packet[:4]) != [4]byte{1, 1, 6, 0} || [4]byte(packet[24:28]) != [4]byte{} ||
		[6]byte(packet[28:34]) != mac || [4]byte(packet[236:240]) != [4]byte{99, 130, 83, 99} {
		return nil
	}
	options, ok := dhcpOptions(packet[fixed:])
	if !ok || len(options[53]) != 1 || options[52] != nil {
		return nil
	}
	server := r.config.address.As4()
	if id := options[54]; id != nil && (len(id) != 4 || [4]byte(id) != server) {
		return nil
	}
	client := netip.AddrFrom4([4]byte(packet[12:16]))
	want := client
	if requested := options[50]; requested != nil {
		if len(requested) != 4 {
			return nil
		}
		want = netip.AddrFrom4([4]byte(requested))
	}
	for owner, lease := range r.leases {
		if !lease.expires.After(now) {
			delete(r.leases, owner)
		}
	}
	for ip, until := range r.declined {
		if !until.After(now) {
			delete(r.declined, ip)
		}
	}
	current := r.leases[mac]
	var reply byte
	var assigned netip.Addr
	switch options[53][0] {
	case discover:
		assigned = current.address
		if !assigned.IsValid() {
			assigned = r.offer(mac, want)
			if !assigned.IsValid() {
				return nil
			}
			r.leases[mac] = dhcpLease{assigned, now.Add(30 * time.Second)}
		}
		reply = offer
	case request:
		reply = nak
		if r.available(mac, want) {
			assigned, reply = want, ack
			r.leases[mac] = dhcpLease{assigned, now.Add(r.config.lease)}
			r.segment.recordLease(mac, assigned)
		}
	case decline:
		if current.address == want && want.IsValid() && len(r.declined) < 256 {
			delete(r.leases, mac)
			r.declined[want] = now.Add(5 * time.Minute)
		}
		return nil
	case release:
		if current.address == client {
			delete(r.leases, mac)
		}
		return nil
	case inform:
		if client.IsUnspecified() {
			return nil
		}
		reply = ack
	default:
		return nil
	}
	out := make([]byte, fixed)
	out[0], out[1], out[2] = 2, 1, 6
	copy(out[4:12], packet[4:12])
	copy(out[28:34], mac[:])
	copy(out[236:240], packet[236:240])
	if assigned.IsValid() {
		ip := assigned.As4()
		copy(out[16:20], ip[:])
	}
	out = append(out, 53, 1, reply, 54, 4)
	out = append(out, server[:]...)
	if reply != nak {
		out = append(out, 1, 4)
		out = append(out, r.config.mask[:]...)
		if assigned.IsValid() {
			out = append(out, 51, 4)
			out = binary.BigEndian.AppendUint32(out, uint32(r.config.lease/time.Second))
		}
		if r.config.dns.IsValid() {
			dns := r.config.dns.As4()
			out = append(out, 6, 4)
			out = append(out, dns[:]...)
		}
	}
	out = append(out, 255)
	if len(out) < 300 {
		out = append(out, make([]byte, 300-len(out))...)
	}
	destination, ip := ethernetBroadcast, ipv4Broadcast
	if reply != nak && !client.IsUnspecified() {
		destination, ip = mac, client.As4()
	}
	frame := ipv4Packet(destination, r.mac, server, ip, 17, 8+len(out))
	binary.BigEndian.PutUint32(frame[34:], 67<<16|68)
	binary.BigEndian.PutUint16(frame[38:], uint16(8+len(out)))
	copy(frame[42:], out)
	return frame
}

func dhcpOptions(data []byte) ([256][]byte, bool) {
	var options [256][]byte
	for len(data) > 0 {
		code := data[0]
		data = data[1:]
		switch code {
		case 255:
			return options, true
		case 0:
			continue
		}
		if options[code] != nil || len(data) == 0 || int(data[0])+1 > len(data) {
			break
		}
		extent := int(data[0]) + 1
		options[code], data = data[1:extent], data[extent:]
	}
	return options, false
}

func (r *dhcpRouter) available(mac [6]byte, ip netip.Addr) bool {
	if !ip.Is4() || ip.Less(r.config.first) || r.config.last.Less(ip) ||
		!r.declined[ip].IsZero() || len(r.leases) >= 256 && !r.leases[mac].address.IsValid() {
		return false
	}
	for owner, lease := range r.leases {
		if owner != mac && lease.address == ip {
			return false
		}
	}
	return true
}

func (r *dhcpRouter) offer(mac [6]byte, preferred netip.Addr) netip.Addr {
	if len(r.leases) >= 256 {
		return netip.Addr{}
	}
	if r.available(mac, preferred) {
		return preferred
	}
	for ip := r.config.first; !r.config.last.Less(ip); ip = ip.Next() {
		if r.available(mac, ip) {
			return ip
		}
	}
	return netip.Addr{}
}

func ethernetHeader(dst, src [6]byte, etherType uint16, size int) []byte {
	frame := make([]byte, 14+size)
	copy(frame[:6], dst[:])
	copy(frame[6:12], src[:])
	binary.BigEndian.PutUint16(frame[12:], etherType)
	return frame
}

func ipv4Packet(dst, src [6]byte, from, to [4]byte, protocol byte, size int) []byte {
	frame := ethernetHeader(dst, src, 0x0800, 20+size)
	h := frame[14:34]
	h[0], h[8], h[9] = 0x45, 64, protocol
	binary.BigEndian.PutUint16(h[2:], uint16(20+size))
	copy(h[12:16], from[:])
	copy(h[16:20], to[:])
	binary.BigEndian.PutUint16(h[10:], packetChecksum(h))
	return frame
}

func packetChecksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
