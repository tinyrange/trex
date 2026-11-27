package lab

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const labDNSDomain = "lab.test"

func dnsLabel(name string) string {
	var label strings.Builder
	separator := false
	for _, char := range strings.ToLower(name) {
		if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' {
			if separator {
				label.WriteByte('-')
			}
			if label.Len() >= 63 {
				break
			}
			label.WriteByte(byte(char))
			separator = false
		} else {
			separator = label.Len() > 0
		}
		if label.Len() == 63 {
			break
		}
	}
	return strings.TrimSuffix(label.String(), "-")
}

type lanDNS struct {
	lookup     func(string) netip.Addr
	tcpClients chan struct{}
}

func (d lanDNS) reply(query []byte) []byte {
	var parser dnsmessage.Parser
	header, err := parser.Start(query)
	if err != nil || header.Response {
		return nil
	}
	message := dnsmessage.Message{Header: dnsmessage.Header{
		ID: header.ID, Response: true, OpCode: header.OpCode, RecursionDesired: header.RecursionDesired,
	}}
	question, err := parser.Question()
	switch {
	case header.OpCode != 0:
		message.RCode = dnsmessage.RCodeNotImplemented
	case err != nil || parser.SkipQuestion() != dnsmessage.ErrSectionDone || parser.SkipAnswer() != dnsmessage.ErrSectionDone ||
		parser.SkipAuthority() != dnsmessage.ErrSectionDone || parser.SkipAllAdditionals() != nil:
		message.RCode = dnsmessage.RCodeFormatError
	default:
		message.Questions = []dnsmessage.Question{question}
		name := strings.ToLower(question.Name.String())
		label, local := strings.CutSuffix(name, "."+labDNSDomain+".")
		if question.Class != dnsmessage.ClassINET || (!local && name != labDNSDomain+".") {
			message.RCode = dnsmessage.RCodeRefused
			break
		}
		message.Authoritative = true
		if name == labDNSDomain+"." {
			break
		}
		var ip netip.Addr
		if d.lookup != nil && label != "" && dnsLabel(label) == label {
			ip = d.lookup(label)
		}
		if !usableLANIP(ip) {
			message.RCode = dnsmessage.RCodeNameError
		} else if question.Type == dnsmessage.TypeA || question.Type == dnsmessage.TypeALL {
			message.Answers = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: 30},
				Body:   &dnsmessage.AResource{A: ip.As4()},
			}}
		}
	}
	reply, _ := message.Pack()
	return reply
}

func (r *dhcpRouter) dnsUDP(mac [6]byte, source [4]byte, udp []byte) []byte {
	port, size := binary.BigEndian.Uint16(udp[:2]), int(binary.BigEndian.Uint16(udp[4:6]))
	if port == 0 || size < 8 || size > len(udp) || !usableLANIP(netip.AddrFrom4(source)) || source == r.config.address.As4() {
		return nil
	}
	data := r.dns.reply(udp[8:size])
	if len(data) == 0 {
		return nil
	}
	frame := ipv4Packet(mac, r.mac, r.config.address.As4(), source, 17, 8+len(data))
	binary.BigEndian.PutUint16(frame[34:36], 53)
	binary.BigEndian.PutUint16(frame[36:38], port)
	binary.BigEndian.PutUint16(frame[38:40], uint16(8+len(data)))
	copy(frame[42:], data)
	return frame
}

func (d lanDNS) accept(ctx context.Context, conn net.Conn) error {
	select {
	case d.tcpClients <- struct{}{}:
		go func() {
			defer func() { <-d.tcpClients }()
			defer conn.Close()
			d.serveTCP(ctx, conn)
		}()
	default:
		conn.Close()
	}
	return nil
}

func (d lanDNS) serveTCP(ctx context.Context, conn net.Conn) {
	var size [2]byte
	for ctx.Err() == nil {
		if conn.SetDeadline(time.Now().Add(5*time.Second)) != nil {
			return
		}
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			return
		}
		query := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		reply := d.reply(query)
		if len(reply) == 0 {
			return
		}
		if _, err := conn.Write(binary.BigEndian.AppendUint16(nil, uint16(len(reply)))); err != nil {
			return
		}
		if _, err := conn.Write(reply); err != nil {
			return
		}
	}
}
