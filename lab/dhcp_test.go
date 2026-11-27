package lab

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func TestRouterDHCPLeaseAndExhaustion(t *testing.T) {
	segment := newNetworkSegment()
	defer segment.observer.Close()
	settings := dhcpSettings{enabled: true, address: netip.MustParseAddr("10.8.0.1"),
		first: netip.MustParseAddr("10.8.0.40"), last: netip.MustParseAddr("10.8.0.40"),
		mask: [4]byte{255, 255, 255, 0}, lease: time.Minute}
	router := &dhcpRouter{config: settings, mac: hardwareAddress("router"), segment: segment,
		leases: make(map[[6]byte]dhcpLease), declined: make(map[netip.Addr]time.Time)}
	packet := func(mac [6]byte, kind byte, options ...byte) []byte {
		body := make([]byte, 240)
		body[0], body[1], body[2] = 1, 1, 6
		copy(body[28:34], mac[:])
		copy(body[236:240], []byte{99, 130, 83, 99})
		body = append(body, 53, 1, kind)
		body = append(body, options...)
		body = append(body, 255)
		frame := ipv4Packet(ethernetBroadcast, mac, [4]byte{}, ipv4Broadcast, 17, 8+len(body))
		binary.BigEndian.PutUint32(frame[34:], 68<<16|67)
		binary.BigEndian.PutUint16(frame[38:], uint16(8+len(body)))
		copy(frame[42:], body)
		return frame
	}
	now := time.Unix(0, 0)
	first, second := hardwareAddress("first"), hardwareAddress("second")
	if reply := router.receive(packet(first, discover), now); len(reply) < 285 || reply[284] != offer {
		t.Fatalf("expected an offer, got %x", reply)
	}
	if reply := router.receive(packet(second, discover), now); reply != nil {
		t.Fatal("offered a reserved address twice")
	}
	wanted := []byte{50, 4, 10, 8, 0, 40}
	reply := router.receive(packet(first, request, wanted...), now)
	if len(reply) < 285 || reply[284] != ack || [4]byte(reply[58:62]) != settings.first.As4() {
		t.Fatalf("expected a lease ACK, got %x", reply)
	}
	options, ok := dhcpOptions(reply[282:])
	if !ok || options[3] != nil || segment.address("first") != settings.first {
		t.Fatalf("expected a LAN lease without a default gateway, got %#v", options[3])
	}
	if reply := router.receive(packet(second, discover), now.Add(settings.lease)); len(reply) < 285 || reply[284] != offer {
		t.Fatalf("expected the expired address to be reusable, got %x", reply)
	}
}

func TestRouterConfigurationAndSharedSwitch(t *testing.T) {
	recipes := make(map[string]Recipe)
	for _, recipe := range Catalog() {
		recipes[recipe.ID] = recipe
	}
	d := Blank()
	d.Nodes = []Node{
		{ID: "switch", Name: "Switch", Recipe: "switch"},
		{ID: "router", Name: "Router", Recipe: "router"},
		{ID: "other", Name: "Other router", Recipe: "router"},
	}
	d.Links = []Link{{End{"switch", "port1"}, End{"router", "lan"}}, {End{"switch", "port2"}, End{"other", "lan"}}}
	if issues := Validate(d, recipes, nil); len(issues) != 1 || issues[0].Field != "dhcp" {
		t.Fatalf("expected one DHCP server per switch issue: %+v", issues)
	}
	d.Nodes[2].Config = map[string]any{"dhcp": false, "routerAddress": "10.20.0.2/24"}
	if issues := Validate(d, recipes, nil); len(issues) != 0 {
		t.Fatalf("another LAN node with DHCP disabled should be valid: %+v", issues)
	}
	d.Nodes[1].Config = map[string]any{"dhcpStart": "10.20.0.1"}
	if issues := Validate(d, recipes, nil); len(issues) != 1 || issues[0].Field != "dhcpStart" {
		t.Fatalf("expected an issue for the router address in the DHCP range: %+v", issues)
	}
}
