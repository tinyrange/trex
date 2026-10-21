package cc

import (
	"encoding/binary"
	"j5.nz/cc/hypervisor"
	"sort"
)

// smc implements the byte-wide SMC key protocol, not a guest decryptor.
// Wire facts: Linux drivers/hwmon/applesmc.c (ports, commands, status bits,
// big-endian indices and six-byte key metadata). No driver code is copied.
// Original AppleSMC matches the ACPI APP0001 device. The optional caller's
// OSK is never synthesized, logged, or included in inspection results.
const smcBase = 0x300

type smcKey struct {
	data     []byte
	kind     string
	writable bool
}
type smc struct {
	keys                    map[string]smcKey
	names                   []string
	command, status, result byte
	argument                [4]byte
	argumentSize            int
	length                  int
	payload                 [32]byte
	position                int
	trace                   []any
}

func newSMC(osk []byte) *smc {
	s := &smc{keys: map[string]smcKey{
		"#KEY": {data: make([]byte, 4), kind: "ui32"},
		"REV ": {data: []byte{1, 0, 0, 0, 0, 0}, kind: "{rev"},
		"FNum": {data: []byte{0}, kind: "ui8 "},
		"MSTS": {data: []byte{0}, kind: "ui8 "},
	}}
	if len(osk) == 64 {
		s.keys["OSK0"] = smcKey{data: append([]byte(nil), osk[:32]...), kind: "ch8*"}
		s.keys["OSK1"] = smcKey{data: append([]byte(nil), osk[32:]...), kind: "ch8*"}
	}
	for name := range s.keys {
		s.names = append(s.names, name)
	}
	sort.Strings(s.names)
	binary.BigEndian.PutUint32(s.keys["#KEY"].data, uint32(len(s.names)))
	return s
}

func (s *smc) record(key string) {
	s.trace = append(s.trace, map[string]any{"command": int(s.command), "key": key, "length": s.length, "result": int(s.result)})
	if len(s.trace) > 64 {
		s.trace = s.trace[len(s.trace)-64:]
	}
}
func (s *smc) fail(result byte) { s.result = result; s.status = 0; s.position = 0 }
func (s *smc) begin(command byte) {
	s.command = command
	s.status = 0x0c
	s.result = 0
	s.argumentSize = 0
	s.position = 0
	s.length = 0
	clear(s.payload[:])
	if command < 0x10 || command > 0x13 {
		s.fail(0x82)
	}
}
func (s *smc) input(value byte) {
	if s.status&4 == 0 || s.status&1 != 0 {
		return
	}
	if s.argumentSize < 4 {
		s.argument[s.argumentSize] = value
		s.argumentSize++
		s.status = 4
		// Lion's original client omits the redundant length byte for
		// fixed-width index/info commands; accept Linux's extra byte too.
		if s.argumentSize == 4 && (s.command == 0x12 || s.command == 0x13) {
			s.length = 4
			if s.command == 0x13 {
				s.length = 6
			}
			s.prepare()
		}
		return
	}
	if s.length == 0 {
		s.length = int(value)
		s.prepare()
		return
	}
	if s.command == 0x11 && s.position < s.length {
		s.payload[s.position] = value
		s.position++
		if s.position == s.length {
			entry := s.keys[string(s.argument[:])]
			copy(entry.data, s.payload[:s.length])
			s.status = 0
		}
	}
}
func (s *smc) output() byte {
	if s.status&1 == 0 || s.position >= s.length {
		return 0
	}
	value := s.payload[s.position]
	s.position++
	if s.position == s.length {
		s.status = 0
	}
	return value
}
func (s *smc) io(ex hypervisor.X86Exit) error {
	for i := uint32(0); i < ex.Count; i++ {
		for j := uint16(0); j < uint16(ex.Size); j++ {
			pos := int(i)*int(ex.Size) + int(j)
			port := ex.Port + j
			value := byte(0)
			switch port {
			case smcBase:
				if ex.Write {
					s.input(ex.Data[pos])
				} else {
					value = s.output()
				}
			case smcBase + 4:
				if ex.Write {
					s.begin(ex.Data[pos])
				} else {
					value = s.status
				}
			case smcBase + 0x1e:
				value = s.result
			}
			if !ex.Write {
				ex.Data[pos] = value
			}
		}
	}
	return nil
}

func (s *smc) prepare() {
	name := string(s.argument[:])
	if s.length == 0 || s.length > len(s.payload) {
		s.fail(0x85)
		s.record(name)
		return
	}
	entry, found := s.keys[name]
	switch s.command {
	case 0x10:
		if !found {
			s.fail(0x84)
		} else if s.length != len(entry.data) {
			s.fail(0x85)
		} else {
			copy(s.payload[:], entry.data)
			s.status = 5
		}
	case 0x11:
		if !found {
			s.fail(0x84)
		} else if !entry.writable {
			s.fail(0x86)
		} else if s.length != len(entry.data) {
			s.fail(0x85)
		} else {
			s.status = 4
		}
	case 0x12:
		index := binary.BigEndian.Uint32(s.argument[:])
		if index >= uint32(len(s.names)) {
			s.fail(0x84)
		} else if s.length != 4 {
			s.fail(0x85)
		} else {
			copy(s.payload[:], s.names[index])
			s.status = 5
		}
	case 0x13:
		if !found {
			s.fail(0x84)
		} else if s.length != 6 {
			s.fail(0x85)
		} else {
			s.payload[0] = byte(len(entry.data))
			copy(s.payload[1:5], entry.kind)
			s.payload[5] = 0x80
			if entry.writable {
				s.payload[5] |= 0x40
			}
			s.status = 5
		}
	}
	s.record(name)
}
