package s390

import (
	"fmt"
	"strings"
)

// sclp models the service-call logical processor: READ SCP INFO and the
// event facility used by the hardware system console (operating system
// messages and operator commands, and the VT220 console).
type sclp struct {
	m *Machine
	// Masks the control program registered with WRITE EVENT MASK.
	cpReceive, cpSend uint32
	pending           []sclpEvent // queued for READ EVENT DATA
	// Lines holds completed message lines; Partial the unterminated tail of
	// the VT220 stream.
	Lines   []string
	Partial []byte
	// LineLimit bounds Lines.
	LineLimit int
	dropped   int    // lines trimmed from the front of Lines
	version   uint64 // changes with every output or input
}

type sclpEvent struct {
	typ  byte
	data []byte
}

// Event types and their mask bits (bit n-1 from the left for type n).
const (
	evOpCmd   = 0x01
	evMsg     = 0x02
	evPMsgCmd = 0x09
	evVT220   = 0x1a
)

func evMask(t byte) uint32 { return 0x80000000 >> (t - 1) }

const (
	sclpReceiveMask = 0x80000000>>(evMsg-1) | 0x80000000>>(evPMsgCmd-1) | 0x80000000>>(evVT220-1)
	sclpSendMask    = 0x80000000>>(evOpCmd-1) | 0x80000000>>(evPMsgCmd-1) | 0x80000000>>(evVT220-1)
)

const (
	sclpReadSCPInfo    = 0x00020001
	sclpReadSCPInfoF   = 0x00120001
	sclpReadCPUInfo    = 0x00010001
	sclpReadChpInfo    = 0x00030001
	sclpWriteEventData = 0x00760005
	sclpReadEventData  = 0x00770005
	sclpWriteEventMask = 0x00780005
)

func (s *sclp) servc(c *CPU, cmd uint32, sccb uint32) {
	if sccb&7 != 0 {
		c.program(pgmSpecification)
	}
	abs := c.realToAbs(sccb & 0x7ffffff8)
	if !c.S.valid(abs, 8) {
		c.program(pgmAddressing)
	}
	if s.m.serviceSignal && s.m.serviceParam&^7 != 0 {
		c.PSW.CC = 2 // previous command not yet presented
		return
	}
	m := c.S.Mem
	length := uint32(be.Uint16(m[abs:]))
	if length < 8 || !c.S.valid(abs, length) {
		c.program(pgmSpecification)
	}
	s.m.event("servc", c, fmt.Sprintf("command %08X sccb %08X", cmd, sccb))
	resp := uint16(0x01f0) // invalid command
	switch cmd {
	case sclpReadSCPInfo, sclpReadSCPInfoF:
		if length < 64 {
			resp = 0x0300
			break
		}
		for i := uint32(8); i < length; i++ {
			m[abs+i] = 0
		}
		incr := uint32(1) // MB per increment
		n := c.S.Size() >> 20
		for n > 0xffff {
			incr <<= 1
			n >>= 1
		}
		be.PutUint16(m[abs+8:], uint16(n))
		m[abs+10] = byte(incr)
		m[abs+11] = 4               // storage block size in KB
		be.PutUint16(m[abs+12:], 1) // increment block interleave interval
		lp := ebcdicPad(s.m.LoadParm, 8)
		copy(m[abs+24:abs+32], lp)
		// Configuration characteristics (installed facilities).
		copy(m[abs+80:abs+86], s.m.SCPConfig[:])
		be.PutUint16(m[abs+16:], uint16(len(s.m.CPUs)))
		be.PutUint16(m[abs+18:], 128)
		if length >= 128+uint32(len(s.m.CPUs))*16 {
			for i, cpu := range s.m.CPUs {
				e := abs + 128 + uint32(i)*16
				m[e] = byte(cpu.Addr)
				copy(m[e+2:e+14], s.m.SCPCPUFacilities[:])
			}
		}
		resp = 0x0010
	case sclpReadChpInfo:
		// Recognized (offset 8), standby (40) and configured (72)
		// 256-bit channel-path maps. Each subchannel's CHPID is its
		// device number's high byte; every one is recognized and
		// configured, none is in standby.
		if length < 8+96 {
			resp = 0x0300
			break
		}
		for i := uint32(8); i < 8+96; i++ {
			m[abs+i] = 0
		}
		for _, x := range s.m.CSS.subs {
			chp := uint32(x.devno >> 8 & 0xff)
			bit := byte(0x80) >> (chp % 8)
			m[abs+8+chp/8] |= bit
			m[abs+72+chp/8] |= bit
		}
		resp = 0x0010
	case sclpWriteEventMask:
		resp = s.writeEventMask(m[abs : abs+length])
	case sclpWriteEventData:
		resp = s.writeEventData(m[abs : abs+length])
	case sclpReadEventData:
		resp = s.readEventData(m[abs : abs+length])
	}
	be.PutUint16(m[abs+6:], resp)
	for a := abs; a < abs+length; a += 1 << c.S.KeyShift {
		*c.S.key(a) |= keyRef | keyChg
	}
	*c.S.key(abs + length - 1) |= keyRef | keyChg
	s.m.serviceSignal = true
	s.m.serviceParam = sccb&0x7ffffff8 | s.eventPending()
	c.PSW.CC = 0
	c.pswChanged = true
}

// eventPending is the external-interruption parameter bit that tells the
// control program event buffers are waiting.
func (s *sclp) eventPending() uint32 {
	for _, e := range s.pending {
		if s.cpReceive&evMask(e.typ) != 0 {
			return 1
		}
	}
	return 0
}

func (s *sclp) writeEventMask(b []byte) uint16 {
	if len(b) < 12 {
		return 0x0300
	}
	n := int(be.Uint16(b[10:]))
	if n < 1 || n > 4 || len(b) < 12+4*n {
		return 0x74f0 // invalid mask length
	}
	get := func(i int) uint32 {
		var w [4]byte
		copy(w[:], b[12+i*n:12+i*n+n])
		return be.Uint32(w[:])
	}
	put := func(i int, v uint32) {
		var w [4]byte
		be.PutUint32(w[:], v)
		copy(b[12+i*n:12+i*n+n], w[:n])
	}
	s.cpReceive, s.cpSend = get(0), get(1)
	put(2, sclpReceiveMask)
	put(3, sclpSendMask)
	return 0x0020
}

// writeEventData consumes message (MDB) and VT220 event buffers.
func (s *sclp) writeEventData(b []byte) uint16 {
	n := int(be.Uint16(b))
	if n > len(b) {
		n = len(b)
	}
	any := false
	for off := 8; off+6 <= n; {
		l := int(be.Uint16(b[off:]))
		if l < 6 || off+l > n {
			return 0x0340
		}
		ev := b[off : off+l]
		switch ev[2] {
		case evMsg, evPMsgCmd:
			s.message(ev[6:])
		case evVT220:
			s.vt220(ev[6:])
		default:
			return 0x0340
		}
		ev[3] |= 0x80 // buffer processed
		any = true
		off += l
	}
	if !any {
		return 0x0340
	}
	return 0x0020
}

// message extracts message-text objects from a message data block.
func (s *sclp) message(b []byte) {
	if len(b) < 4 {
		return
	}
	end := int(be.Uint16(b))
	if end > len(b) {
		end = len(b)
	}
	for off := 12; off+4 <= end; { // after the 12-byte MDB header
		l := int(be.Uint16(b[off:]))
		if l < 4 || off+l > end {
			return
		}
		if be.Uint16(b[off+2:]) == 0x0004 && l >= 10 { // message text object
			s.addLine(strings.TrimRight(EBCDIC500String(b[off+10:off+l]), " "))
		}
		off += l
	}
}

func (s *sclp) vt220(b []byte) {
	for _, x := range b {
		switch x {
		case '\n':
			s.addLine(string(s.Partial))
			s.Partial = s.Partial[:0]
		case '\r', 0:
		default:
			s.Partial = append(s.Partial, x)
		}
	}
	s.version++
}

func (s *sclp) addLine(line string) {
	limit := s.LineLimit
	if limit == 0 {
		limit = 10000
	}
	if len(s.Lines) >= limit {
		drop := len(s.Lines) - limit/2
		s.dropped += drop
		s.Lines = append(s.Lines[:0], s.Lines[drop:]...)
	}
	s.Lines = append(s.Lines, line)
	s.version++
	s.m.event("console", nil, line)
}

// readEventData returns queued event buffers the control program accepts.
func (s *sclp) readEventData(b []byte) uint16 {
	off := 8
	var rest []sclpEvent
	stored := false
	for _, e := range s.pending {
		l := 6 + len(e.data)
		if s.cpReceive&evMask(e.typ) == 0 || off+l > len(b) {
			rest = append(rest, e)
			continue
		}
		be.PutUint16(b[off:], uint16(l))
		b[off+2] = e.typ
		b[off+3] = 0
		be.PutUint16(b[off+4:], 0)
		copy(b[off+6:], e.data)
		off += l
		stored = true
	}
	s.pending = rest
	if !stored {
		return 0x60f0 // no event buffers stored
	}
	be.PutUint16(b, uint16(off))
	return 0x0020
}

// Command queues an operator command for the control program: an
// operator-command event in the message-unit form of the hardware console,
// or, when the program registered only the VT220 console, VT220 input.
func (s *sclp) Command(text string) {
	if s.cpReceive&evMask(evOpCmd) == 0 && s.cpReceive&evMask(evVT220) != 0 {
		s.pending = append(s.pending, sclpEvent{typ: evVT220, data: []byte(text + "\n")})
	} else {
		msg := EncodeEBCDIC500(text)
		if len(msg) > 240 {
			msg = msg[:240]
		}
		text := append([]byte{byte(2 + len(msg)), 0x30}, msg...)
		sdtm := append([]byte{byte(2 + len(text)), 0x31}, text...)
		vec := func(id uint16, body []byte) []byte {
			out := make([]byte, 4, 4+len(body))
			be.PutUint16(out, uint16(4+len(body)))
			be.PutUint16(out[2:], id)
			return append(out, body...)
		}
		mu := vec(0x1310, vec(0x1212, vec(0x1320, sdtm)))
		s.pending = append(s.pending, sclpEvent{typ: evOpCmd, data: mu})
	}
	if s.eventPending() != 0 {
		if !s.m.serviceSignal {
			s.m.serviceParam = 0
		}
		s.m.serviceSignal = true
		s.m.serviceParam |= 1
	}
}
