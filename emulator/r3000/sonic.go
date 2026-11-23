package r3000

import (
	"encoding/binary"
	"hash/crc32"
)

type sonic struct {
	reg               [64]uint16
	cam               [16][6]byte
	buffer, remaining uint32
	eol               bool
	watchdog          uint64
}

const (
	sonicCommand         = 0
	sonicReceiveControl  = 2
	sonicTransmitControl = 3
	sonicInterruptMask   = 4
	sonicInterruptStatus = 5
	sonicUpperTransmit   = 6
	sonicCurrentTransmit = 7
	sonicUpperReceive    = 0x0d
	sonicCurrentReceive  = 0x0e
	sonicEndBuffer       = 0x13
	sonicUpperResource   = 0x14
	sonicResourceStart   = 0x15
	sonicResourceEnd     = 0x16
	sonicResourceRead    = 0x17
	sonicResourceWrite   = 0x18
	sonicCAMEnable       = 0x25
	sonicCAMPointer      = 0x26
	sonicCAMCount        = 0x27
	sonicRevision        = 0x28
	sonicReceiveSequence = 0x2b
)

func (s *sonic) reset() {
	*s = sonic{}
	s.reg[sonicCommand] = 0x94
	s.reg[sonicTransmitControl] = 0x101
	s.reg[sonicEndBuffer] = 0x2f8
	s.reg[sonicRevision] = 6
}

func (s *sonic) irq() bool { return s.reg[sonicInterruptMask]&s.reg[sonicInterruptStatus] != 0 }

func (s *sonic) watchdogValue(cycles uint64) uint32 {
	return uint32(s.watchdog - cycles/5)
}

func (s *sonic) tick(cycles uint64) {
	if s.reg[sonicCommand]&0x20 != 0 && cycles%5 == 0 && cycles/5 == s.watchdog+1 {
		s.reg[sonicInterruptStatus] |= 0x80
		s.watchdog += 1 << 32
	}
}

func (s *sonic) access(m *Machine, offset, size, value uint32, write bool) (uint32, bool) {
	index, lane := offset/4, offset&3
	if index >= 64 || lane != 0 && !(lane == 1 && size == 1) {
		return 0, false
	}
	if s.reg[sonicCommand]&0x20 != 0 && (index == 0x29 || index == 0x2a) {
		timer := s.watchdogValue(m.cycles)
		s.reg[0x29], s.reg[0x2a] = uint16(timer), uint16(timer>>16)
	}
	mask := uint16(0xffff)
	if size == 1 {
		mask = 0xff << (8 * lane)
	}
	word := s.reg[index]
	if !write {
		return uint32((word & mask) >> (8 * lane)), true
	}
	shifted := uint16(value<<(8*lane)) & mask
	word = word&^mask | shifted
	switch {
	case index == 0x28 || (index >= 0x30 && index != 0x3f) || (index >= 0x22 && index <= 0x24):
		return 0, true
	case index == sonicInterruptStatus:
		s.reg[index] &^= shifted
	case index >= 0x2c && index <= 0x2e:
		s.reg[index] = ^word
	case (index == 1 || index == 0x25 || index == 0x3f) && s.reg[sonicCommand]&0x80 == 0:
		return 0, true
	case index == sonicCommand:
		old := s.reg[index]
		if word&0x80 != 0 {
			s.stopWatchdog(m.cycles)
			s.reg[index] = 0x94
			return 0, true
		}
		s.reg[index] &^= 0x80
		if word&8 != 0 {
			s.reg[index] = s.reg[index]&^4 | 8
		}
		if word&4 != 0 {
			s.reg[index] = s.reg[index]&^8 | 4
		}
		if word&0x20 != 0 {
			if old&0x20 == 0 {
				s.setWatchdog(m.cycles)
			}
			s.reg[index] = s.reg[index]&^0x10 | 0x20
		}
		if word&0x10 != 0 {
			s.stopWatchdog(m.cycles)
			s.reg[index] = s.reg[index]&^0x20 | 0x10
		}
		if word&0x200 != 0 && !s.loadCAM(m) {
			s.reg[sonicInterruptStatus] |= 0x4000
		}
		if word&0x100 != 0 && !s.loadResource(m) {
			s.reg[sonicInterruptStatus] |= 0x4000
		}
		if word&2 != 0 && !s.transmit(m) {
			s.reg[sonicInterruptStatus] |= 0x100
		}
	default:
		s.reg[index] = word
		if (index == 0x29 || index == 0x2a) && s.reg[sonicCommand]&0x20 != 0 {
			s.setWatchdog(m.cycles)
		}
	}
	return 0, true
}

func (s *sonic) stopWatchdog(cycles uint64) {
	if s.reg[sonicCommand]&0x20 != 0 {
		v := s.watchdogValue(cycles)
		s.reg[0x29], s.reg[0x2a] = uint16(v), uint16(v>>16)
	}
}

func (s *sonic) setWatchdog(cycles uint64) {
	s.watchdog = cycles/5 + uint64(uint32(s.reg[0x29])|uint32(s.reg[0x2a])<<16)
}

func dmaWords(m *Machine, address uint32, words []uint16, write bool) bool {
	var bytes [32]byte
	if len(words) > len(bytes)/4 {
		return false
	}
	for i := range words {
		part := bytes[i*4 : i*4+2]
		if write {
			binary.LittleEndian.PutUint16(part, words[i])
		}
		if !m.dma(address+uint32(i*4), part, write) {
			return false
		}
		if !write {
			words[i] = binary.LittleEndian.Uint16(part)
		}
	}
	return true
}

func wordPair(low, high uint16) uint32 { return uint32(low) | uint32(high)<<16 }

func (s *sonic) loadCAM(m *Machine) bool {
	r := &s.reg
	base := wordPair(r[sonicCAMPointer], r[sonicUpperResource])
	count := int(r[sonicCAMCount])
	if count > len(s.cam) {
		return false
	}
	for i := 0; i < count; i++ {
		var words [4]uint16
		if !dmaWords(m, base+uint32(16*i), words[:], false) || words[0] >= 16 {
			return false
		}
		for j, w := range words[1:] {
			binary.LittleEndian.PutUint16(s.cam[words[0]][j*2:], w)
		}
	}
	if !dmaWords(m, base+uint32(count*16), r[sonicCAMEnable:sonicCAMEnable+1], false) {
		return false
	}
	r[sonicCAMCount] = 0
	r[sonicInterruptStatus] |= 0x1000
	return true
}

func (s *sonic) loadResource(m *Machine) bool {
	r := &s.reg
	var words [4]uint16
	if !dmaWords(m, wordPair(r[sonicResourceRead], r[sonicUpperResource]), words[:], false) {
		return false
	}
	s.buffer = wordPair(words[0], words[1])
	length := wordPair(words[2], words[3])
	if length > 0x7fffffff {
		return false
	}
	s.remaining = length * 2
	copy(r[0x0f:], words[:])
	pointer := uint32(r[sonicResourceRead]) + 16
	if pointer >= uint32(r[sonicResourceEnd]) {
		pointer = uint32(r[sonicResourceStart])
	}
	r[sonicResourceRead] = uint16(pointer)
	if r[sonicResourceRead] == r[sonicResourceWrite] {
		r[sonicInterruptStatus] |= 0x20
	}
	return s.remaining != 0
}

func (s *sonic) accepts(destination [6]byte) bool {
	control := s.reg[sonicReceiveControl]
	broadcast := destination == [6]byte{255, 255, 255, 255, 255, 255}
	if destination[0]&1 != 0 && control&0x800 != 0 || broadcast && control&0x2000 != 0 ||
		destination[0]&1 == 0 && control&0x1000 != 0 {
		return true
	}
	for i, station := range s.cam {
		if s.reg[sonicCAMEnable]&(1<<i) != 0 && destination == station {
			return true
		}
	}
	return false
}

func (s *sonic) receive(m *Machine, frame []byte) {
	r := &s.reg
	if len(frame) < 14 || len(frame) > 1518 || (len(frame) < 60 && r[sonicReceiveControl]&0x4000 == 0) ||
		r[sonicCommand]&8 == 0 || !s.accepts([6]byte(frame[:6])) {
		return
	}
	size := uint32(len(frame)+7) &^ 3
	if s.remaining < size {
		r[sonicInterruptStatus] |= 0x10
		return
	}
	if !s.receiveDescriptor(m, frame, size) {
		r[sonicInterruptStatus] |= 0x4000
	}
}

func (s *sonic) receiveDescriptor(m *Machine, frame []byte, size uint32) bool {
	r := &s.reg
	address := wordPair(r[sonicCurrentReceive], r[sonicUpperReceive])
	var descriptor [7]uint16
	if !dmaWords(m, address, descriptor[:], false) {
		return false
	}
	if s.eol {
		if descriptor[5]&1 != 0 {
			return true
		}
		if !dmaWords(m, address+24, []uint16{0}, true) {
			return false
		}
		r[sonicCurrentReceive], s.eol = descriptor[5], false
		r[sonicInterruptStatus] &^= 0x40
		address = wordPair(r[sonicCurrentReceive], r[sonicUpperReceive])
		if !dmaWords(m, address, descriptor[:], false) {
			return false
		}
	}
	if descriptor[6] == 0 {
		r[sonicInterruptStatus] |= 0x40
		return true
	}
	var fcs [4]byte
	binary.LittleEndian.PutUint32(fcs[:], crc32.ChecksumIEEE(frame))
	if !m.dma(s.buffer, frame, true) || !m.dma(s.buffer+uint32(len(frame)), fcs[:], true) {
		return false
	}
	packetStatus := uint16(1)
	if frame[0]&1 != 0 {
		packetStatus |= 0x100
	}
	if [6]byte(frame[:6]) == [6]byte{255, 255, 255, 255, 255, 255} {
		packetStatus |= 0x80
	}
	r[sonicReceiveControl] = r[sonicReceiveControl]&0xfe00 | packetStatus
	values := []uint16{r[sonicReceiveControl], uint16(len(frame) + 4), uint16(s.buffer), uint16(s.buffer >> 16), r[sonicReceiveSequence]}
	if !dmaWords(m, address, values, true) {
		return false
	}
	r[sonicReceiveSequence]++
	if descriptor[5]&1 != 0 {
		r[sonicInterruptStatus] |= 0x40
		s.eol = true
	} else {
		if !dmaWords(m, address+24, []uint16{0}, true) {
			return false
		}
		r[sonicCurrentReceive] = descriptor[5]
	}
	s.remaining -= size
	s.buffer += size
	r[0x0f], r[0x10] = uint16(s.buffer), uint16(s.buffer>>16)
	r[0x11], r[0x12] = uint16(s.remaining/2), uint16(s.remaining>>17)
	if s.remaining/2 < uint32(r[sonicEndBuffer]) && r[sonicResourceRead] != r[sonicResourceWrite] && !s.loadResource(m) {
		return false
	}
	r[sonicInterruptStatus] |= 0x400
	return true
}

func (s *sonic) transmit(m *Machine) bool {
	r := &s.reg
	for count := 0; count < 256; count++ {
		address := wordPair(r[sonicCurrentTransmit], r[sonicUpperTransmit])
		var header [4]uint16
		if !dmaWords(m, address, header[:], false) || header[3] == 0 || header[3] > 16 || header[2] > 1518 {
			return false
		}
		var frame [1518]byte
		length := 0
		for i := uint32(0); i < uint32(header[3]); i++ {
			var fragment [3]uint16
			if !dmaWords(m, address+16+i*12, fragment[:], false) {
				return false
			}
			n := int(fragment[2])
			if length+n > len(frame) || !m.dma(wordPair(fragment[0], fragment[1]), frame[length:length+n], false) {
				return false
			}
			length += n
		}
		var link [1]uint16
		if !dmaWords(m, address+16+uint32(header[3])*12, link[:], false) {
			return false
		}
		transmitStatus := uint16(1)
		if length != int(header[2]) {
			transmitStatus = 2
		}
		if !dmaWords(m, address, []uint16{transmitStatus}, true) {
			return false
		}
		r[sonicTransmitControl] = transmitStatus
		if transmitStatus == 2 {
			return false
		}
		if m.net != nil && length >= 14 {
			if err := m.net.Send(frame[:length]); err != nil {
				return false
			}
		}
		if r[sonicReceiveControl]&0x600 != 0 {
			s.receive(m, frame[:length])
		}
		if link[0]&1 != 0 {
			r[sonicInterruptStatus] |= 0x200
			return true
		}
		r[sonicCurrentTransmit] = link[0]
	}
	return false
}
