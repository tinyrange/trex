package cc

import (
	"encoding/binary"
	"fmt"
)

func ethernetChecksum(data []byte, seed uint32) uint16 {
	for len(data) >= 2 {
		seed += uint32(binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	if len(data) != 0 {
		seed += uint32(data[0]) << 8
	}
	for seed>>16 != 0 {
		seed = (seed & 65535) + (seed >> 16)
	}
	return ^uint16(seed)
}
func insertE1000Checksum(packet []byte, start, offset, end int) error {
	if end == 0 {
		end = len(packet) - 1
	}
	if start > end || end >= len(packet) || offset < start || offset+1 > end {
		return fmt.Errorf("e1000 invalid checksum range")
	}
	binary.BigEndian.PutUint16(packet[offset:], ethernetChecksum(packet[start:end+1], 0))
	return nil
}
func (d *e1000) sendPacket(extended bool, desc [16]byte) error {
	packet := d.txPacket
	if extended && d.txTSO {
		return d.segmentTCP(packet)
	}
	if extended {
		c := d.txContext
		if d.txOptions&1 != 0 {
			if err := insertE1000Checksum(packet, int(c[0]), int(c[1]), int(binary.LittleEndian.Uint16(c[2:]))); err != nil {
				return err
			}
		}
		if d.txOptions&2 != 0 {
			if err := insertE1000Checksum(packet, int(c[4]), int(c[5]), int(binary.LittleEndian.Uint16(c[6:]))); err != nil {
				return err
			}
		}
	} else if desc[11]&4 != 0 {
		if err := insertE1000Checksum(packet, int(desc[13]), int(desc[10]), 0); err != nil {
			return err
		}
	}
	if desc[11]&0x40 != 0 && d.regs[0]&0x40000000 != 0 {
		if len(packet) < 14 {
			return fmt.Errorf("e1000 short VLAN frame")
		}
		tagged := make([]byte, len(packet)+4)
		copy(tagged, packet[:12])
		binary.BigEndian.PutUint16(tagged[12:], uint16(d.regs[0x38/4]))
		binary.BigEndian.PutUint16(tagged[14:], binary.LittleEndian.Uint16(desc[14:]))
		copy(tagged[16:], packet[12:])
		packet = tagged
	}
	return d.sendFrame(packet)
}

// TCP segmentation expands a bounded super-packet into ordinary Ethernet
// frames. Header offsets are guest input: validate before indexing or copying.
func (d *e1000) segmentTCP(packet []byte) error {
	c := d.txContext
	ip, tcp, hdr := int(c[0]), int(c[4]), int(c[13])
	mss := int(binary.LittleEndian.Uint16(c[14:]))
	if mss == 0 || hdr > len(packet) || ip < 14 || tcp < ip+20 || hdr < tcp+20 || hdr+mss > 1518 {
		return fmt.Errorf("e1000 invalid TSO context")
	}
	ipv4 := packet[ip]>>4 == 4
	ipv6 := packet[ip]>>4 == 6
	if !ipv4 && !ipv6 || ipv6 && tcp < ip+40 {
		return fmt.Errorf("e1000 unsupported TSO IP header")
	}
	sequence := binary.BigEndian.Uint32(packet[tcp+4:])
	identifier := binary.BigEndian.Uint16(packet[ip+4:])
	payload := packet[hdr:]
	for off, segment := 0, 0; off < len(payload) || segment == 0; segment++ {
		n := min(mss, len(payload)-off)
		frame := make([]byte, hdr+n)
		copy(frame, packet[:hdr])
		copy(frame[hdr:], payload[off:off+n])
		binary.BigEndian.PutUint32(frame[tcp+4:], sequence+uint32(off))
		if off+n < len(payload) {
			frame[tcp+13] &= ^byte(9)
		} // FIN/PSH only on final segment.
		frame[tcp+16], frame[tcp+17] = 0, 0
		var pseudo uint32
		if ipv4 {
			ihl := int(frame[ip]&15) * 4
			if ihl < 20 || ip+ihl > tcp {
				return fmt.Errorf("e1000 invalid TSO IPv4 IHL")
			}
			binary.BigEndian.PutUint16(frame[ip+2:], uint16(len(frame)-ip))
			binary.BigEndian.PutUint16(frame[ip+4:], identifier+uint16(segment))
			frame[ip+10], frame[ip+11] = 0, 0
			binary.BigEndian.PutUint16(frame[ip+10:], ethernetChecksum(frame[ip:ip+ihl], 0))
			pseudo = uint32(^ethernetChecksum(frame[ip+12:ip+20], 0)) + 6 + uint32(len(frame)-tcp)
		} else {
			binary.BigEndian.PutUint16(frame[ip+4:], uint16(len(frame)-ip-40))
			pseudo = uint32(^ethernetChecksum(frame[ip+8:ip+40], 0)) + 6 + uint32(len(frame)-tcp)
		}
		binary.BigEndian.PutUint16(frame[tcp+16:], ethernetChecksum(frame[tcp:], pseudo))
		if err := d.sendFrame(frame); err != nil {
			return err
		}
		off += n
	}
	return nil
}
