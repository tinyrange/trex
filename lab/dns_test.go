package lab

import (
	"encoding/binary"
	"io"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func dnsQuery(t *testing.T, name string, typ dnsmessage.Type) []byte {
	t.Helper()
	message := dnsmessage.Message{Header: dnsmessage.Header{ID: 37, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET}}}
	data, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func dnsExchangeTCP(t *testing.T, conn io.ReadWriter, query []byte) dnsmessage.Message {
	t.Helper()
	data := binary.BigEndian.AppendUint16(nil, uint16(len(query)))
	if _, err := conn.Write(append(data, query...)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, data); err != nil {
		t.Fatal(err)
	}
	data = make([]byte, binary.BigEndian.Uint16(data))
	if _, err := io.ReadFull(conn, data); err != nil {
		t.Fatal(err)
	}
	var message dnsmessage.Message
	if err := message.Unpack(data); err != nil {
		t.Fatal(err)
	}
	return message
}

func TestRouterDNSOnlyResolvesItsRunningSegment(t *testing.T) {
	lan := newNetworkSegment()
	defer lan.observer.Close()
	draft := Blank()
	draft.Nodes = []Node{
		{ID: "switch"}, {ID: "separate"},
		{ID: "web_1", Name: "Web Server"}, {ID: "other", Name: "Other"},
		{ID: "stopped", Name: "Stopped"},
	}
	draft.Links = []Link{
		{End{"switch", "port1"}, End{"web_1", "lan"}},
		{End{"separate", "port1"}, End{"other", "lan"}},
		{End{"switch", "port2"}, End{"stopped", "lan"}},
	}
	m := NewManager(t.Context(), Blank(), nil, nil, nil, nil)
	m.switches["switch"], m.active = lan, draft
	const webIP = "10.20.0.100"
	m.nodeViews["web_1"] = NodeView{Phase: "running", Address: webIP}
	m.nodeViews["other"] = NodeView{Phase: "running", Address: "10.20.0.120"}
	m.nodeViews["stopped"] = NodeView{Phase: "stopped", Address: "10.20.0.130"}
	router := dhcpRouter{config: dhcpSettings{address: netip.MustParseAddr("10.20.0.1")}, mac: hardwareAddress("router"),
		dns: lanDNS{lookup: func(label string) netip.Addr { return m.lanAddress("switch", lan, label) }},
	}
	clientIP := [4]byte{10, 20, 0, 99}
	clientMAC := hardwareAddress("test-client")
	for _, test := range []struct {
		name string
		typ  dnsmessage.Type
		code dnsmessage.RCode
		ip   string
	}{
		{"Web-Server.lab.test.", dnsmessage.TypeA, dnsmessage.RCodeSuccess, webIP},
		{"web-1.lab.test.", dnsmessage.TypeA, dnsmessage.RCodeSuccess, webIP},
		{"web-server.lab.test.", dnsmessage.TypeAAAA, dnsmessage.RCodeSuccess, ""},
		{"other.lab.test.", dnsmessage.TypeA, dnsmessage.RCodeNameError, ""},
		{"stopped.lab.test.", dnsmessage.TypeA, dnsmessage.RCodeNameError, ""},
		{"unrelated.test.", dnsmessage.TypeA, dnsmessage.RCodeRefused, ""},
	} {
		query := dnsQuery(t, test.name, test.typ)
		frame := ipv4Packet(router.mac, clientMAC, clientIP, router.config.address.As4(), 17, 8+len(query))
		binary.BigEndian.PutUint32(frame[34:], 55000<<16|53)
		binary.BigEndian.PutUint16(frame[38:], uint16(8+len(query)))
		copy(frame[42:], query)
		reply := router.receive(t.Context(), frame, time.Now())
		if len(reply) < 42 || [6]byte(reply[:6]) != clientMAC || [4]byte(reply[30:34]) != clientIP ||
			binary.BigEndian.Uint32(reply[34:]) != 53<<16|55000 {
			t.Fatalf("%s: invalid DNS reply frame %x", test.name, reply)
		}
		var message dnsmessage.Message
		if err := message.Unpack(reply[42:]); err != nil {
			t.Fatal(err)
		}
		if !message.Response || message.ID != 37 || message.RecursionAvailable || message.RCode != test.code {
			t.Errorf("%s: invalid reply: %+v", test.name, message)
		}
		if test.ip == "" {
			if len(message.Answers) != 0 {
				t.Errorf("%s: unexpected answer: %+v", test.name, message.Answers)
			}
		} else if len(message.Answers) != 1 || message.Answers[0].Body.(*dnsmessage.AResource).A != netip.MustParseAddr(test.ip).As4() {
			t.Errorf("%s: need %s: %+v", test.name, test.ip, message.Answers)
		}
	}
}
