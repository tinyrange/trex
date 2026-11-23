package r3000

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/tinyrange/trex/binary/mipscoff"
	"github.com/tinyrange/trex/storage"
	"github.com/tinyrange/trex/vmm/ethernet"
)

var mopMulticast = [6]byte{0xab, 0, 0, 1, 0, 0}
var mopMAC = [6]byte{2, 0, 0x4d, 0x4f, 0x50, 1}

type mopServer struct {
	image        *mipscoff.Image
	name         string
	client       [6]byte
	payload      []byte
	sequence     byte
	section      int
	offset       uint32
	blockSize    uint32
	sent         uint32
	acknowledged uint64
	requests     uint64
	complete     bool
}

// ServeMOP exports a single named ROM COFF file to the isolated Jazz network.
func (m *Machine) ServeMOP(name string, file storage.Reader) error {
	if !validSoftwareID([]byte(name)) {
		return fmt.Errorf("MOP: invalid software ID %q", name)
	}
	image, err := mipscoff.Open(file)
	if err != nil {
		return err
	}
	if !image.ROM {
		return fmt.Errorf("MOP: expected fixed Jazz ROM COFF image")
	}
	if m.net == nil {
		m.net, m.serverPort = newNetwork()
	}
	m.mop = &mopServer{image: image, name: name}
	return nil
}

func newNetwork() (ethernet.Endpoint, ethernet.Endpoint) {
	sw := ethernet.NewSwitch()
	return sw.Connect(), sw.Connect()
}

func validSoftwareID(name []byte) bool {
	if len(name) == 0 || len(name) > 16 || bytes.Equal(name, []byte(".")) || bytes.Equal(name, []byte("..")) {
		return false
	}
	for _, b := range name {
		if b < 0x21 || b > 0x7e || b == '/' || b == '\\' || b == ':' {
			return false
		}
	}
	return true
}

func softwareRequest(packet []byte) (string, uint32) {
	if len(packet) < 6 || packet[2] != 1 || packet[3] != 2 {
		return "", 0
	}
	n := int(packet[4])
	if n+6 > len(packet) || packet[5+n] != 0 || !validSoftwareID(packet[5:5+n]) {
		return "", 0
	}
	name := string(packet[5 : 5+n])
	payload := uint32(262)
	for args := packet[6+n:]; len(args) > 0; {
		if len(args) < 3 || 3+int(args[2]) > len(args) {
			return "", 0
		}
		size := int(args[2])
		if binary.LittleEndian.Uint16(args) == 401 {
			if size != 2 {
				return "", 0
			}
			payload = uint32(binary.LittleEndian.Uint16(args[3:]))
		}
		args = args[3+size:]
	}
	if payload == 1030 {
		payload = 1010
	}
	if payload < 19 {
		return "", 0
	}
	return name, min(payload, 1498) - 6
}

func (m *Machine) mopTick() {
	if m.mop == nil {
		return
	}
	for frame := m.serverPort.Receive(); frame != nil; frame = m.serverPort.Receive() {
		reply, err := m.mop.receive(frame, m.epoch.Add(time.Duration(m.cycles)*(time.Second/cyclesPerSecond)))
		if err != nil {
			m.fault = err
			return
		}
		if len(reply) != 0 {
			if err = m.serverPort.Send(reply); err != nil {
				m.fault = err
				return
			}
		}
	}
}

func (s *mopServer) receive(frame []byte, now time.Time) ([]byte, error) {
	if len(frame) < 17 || len(frame) > 1518 || frame[12] != 0x60 || frame[13] != 1 || frame[6]&1 != 0 {
		return nil, nil
	}
	destination, source := [6]byte(frame[:6]), [6]byte(frame[6:12])
	if destination != mopMulticast && destination != mopMAC {
		return nil, nil
	}
	n := int(binary.LittleEndian.Uint16(frame[14:]))
	if n == 0 || n > 1498 || 16+n > len(frame) {
		return nil, nil
	}
	packet := frame[16 : 16+n]
	switch packet[0] {
	case 8:
		name, size := softwareRequest(packet)
		if size == 0 || !strings.EqualFold(name, s.name) {
			return nil, nil
		}
		s.requests++
		if destination == mopMulticast {
			return mopFrame(source, []byte{3}), nil
		}
		s.client, s.blockSize = source, size
		s.sequence, s.section, s.offset, s.acknowledged, s.complete = 0, 0, 0, 0, false
	case 10:
		if destination != mopMAC || source != s.client || s.blockSize == 0 || (n != 2 && n != 3) {
			return nil, nil
		}
		if packet[1] == s.sequence {
			return mopFrame(source, s.payload), nil
		}
		if packet[1] != s.sequence+1 {
			return nil, nil
		}
		if s.section == len(s.image.Sections) {
			s.complete = true
			return nil, nil
		}
		s.acknowledged += uint64(s.sent)
		s.offset += s.sent
		if s.offset == s.image.Sections[s.section].Size {
			s.section++
			s.offset = 0
		}
		s.sequence++
	default:
		return nil, nil
	}
	if s.section == len(s.image.Sections) {
		_, offset := now.Zone()
		s.payload = []byte{20, s.sequence, 5, 10, byte(now.Year() / 100), byte(now.Year() % 100), byte(now.Month()), byte(now.Day()),
			byte(now.Hour()), byte(now.Minute()), byte(now.Second()), byte(now.Nanosecond() / 10_000_000), byte(offset / 3600), byte(offset % 3600 / 60), 0}
		s.payload = binary.LittleEndian.AppendUint32(s.payload, s.image.Entry)
		s.sent = 0
	} else {
		section := s.image.Sections[s.section]
		s.sent = min(s.blockSize, section.Size-s.offset)
		s.payload = make([]byte, 6+s.sent)
		s.payload[0], s.payload[1] = 2, s.sequence
		binary.LittleEndian.PutUint32(s.payload[2:], section.Address+s.offset)
		if err := s.image.ReadSection(s.section, s.offset, s.payload[6:]); err != nil {
			return nil, err
		}
	}
	return mopFrame(source, s.payload), nil
}

func mopFrame(target [6]byte, payload []byte) []byte {
	frame := make([]byte, max(60, 16+len(payload)))
	copy(frame[:6], target[:])
	copy(frame[6:12], mopMAC[:])
	frame[12], frame[13] = 0x60, 1
	binary.LittleEndian.PutUint16(frame[14:], uint16(len(payload)))
	copy(frame[16:], payload)
	return frame
}
