package r3000

import "encoding/binary"

type soundController struct {
	registers [0x1000]byte
	phase     uint32
}

var soundRates = [4]uint32{11025, 22050, 44100, 0}

func (s *soundController) irq() bool { return s.registers[1]&0xc0 != 0 }

func (s *soundController) tick(m *Machine) {
	mode := s.registers[2]
	s.phase += soundRates[mode&3]
	if s.phase < cyclesPerSecond {
		return
	}
	s.phase -= cyclesPerSecond
	control := &s.registers[0]
	index := 0x140/8 + 4*int(*control>>2&1)
	status, count, address := &m.board[index+1], &m.board[index+2], &m.board[index+3]
	playback := *control&2 != 0
	size := uint32(1)
	if mode&8 != 0 {
		size *= 2
	}
	if mode&0x20 != 0 {
		size *= 2
	}
	if *status&1 != 0 && (*status&2 != 0) == playback && *count >= size {
		var frame [4]byte
		if !playback && mode&8 == 0 {
			frame[0], frame[1] = 0x80, 0x80
		}
		if m.dma(*address, frame[:size], !playback) {
			*address += size
			*count -= size
			if *count == 0 {
				*status = *status&^1 | 0x100
				*control ^= 4
				s.registers[1] |= 0x40
			}
			return
		}
		*status |= 0x400
	}
	*control &^= 1
	s.registers[1] |= 0x80
}

func (s *soundController) access(offset, size, value uint32, write bool) (uint32, bool) {
	if !write {
		return loadLE(s.registers[offset:], size), true
	}
	before := binary.LittleEndian.Uint16(s.registers[:])
	next := before
	for i := uint32(0); i < size; i++ {
		b := byte(value >> (8 * i))
		switch offset + i {
		case 0:
			next = next&0xff00 | uint16(b&7)
		case 1:
			next &^= uint16(b) << 8
		case 2:
			s.registers[2] = b & 0x2b
		case 3:
		default:
			s.registers[offset+i] = b
		}
	}
	if offset < 2 {
		if before&0x8000 != 0 {
			next &^= 1
		}
		if before&0xc001 != 0 {
			next = next&^4 | before&4
		}
		binary.LittleEndian.PutUint16(s.registers[:], next)
	}
	return 0, true
}
