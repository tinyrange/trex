package cc

import (
	"encoding/binary"
	"fmt"
	"j5.nz/cc/hypervisor"
	"time"
)

// sb16 is an explicit ISA PCM device, DSP 4.05, base 220h, IRQ5, DMA1/5.
// Guest DMA data is retained in a bounded, portable 44.1-kHz stereo PCM sink.
// No host sound server, media converter, or synthetic playback success is used.
// FM synthesis, MIDI UART, ADC and Creative ADPCM are not implemented.
type sb16 struct {
	dma                          *isaDMA
	ram                          []byte
	irq                          func(uint32, bool) error
	mixer                        [256]byte
	index                        byte
	reset                        bool
	response                     []byte
	command                      byte
	params                       []byte
	needed                       int
	test                         byte
	speaker                      bool
	rate                         int
	block, remaining             int
	bits, channels               int
	signed, auto, active, paused bool
	silence                      bool
	next                         time.Time
	pending                      byte
	capture                      []byte
	totalFrames                  uint64
	truncated                    bool
	phase                        int
	commands                     []int
	fault                        string
}

const sbCaptureLimit = 16 << 20

func newSB16(ram []byte, irq func(uint32, bool) error) *sb16 {
	s := &sb16{dma: newISADMA(), ram: ram, irq: irq, rate: 11025, bits: 8, channels: 1}
	s.resetMixer()
	return s
}
func (s *sb16) resetMixer() {
	s.mixer = [256]byte{}
	s.mixer[0x80], s.mixer[0x81] = 2, 0x22
	s.mixer[0x22], s.mixer[4] = 0xff, 0xff
	for _, i := range []int{0x30, 0x31, 0x32, 0x33} {
		s.mixer[i] = 0xf8
	}
}
func (s *sb16) irqLine() uint32 {
	switch s.mixer[0x80] & 15 {
	case 1:
		return 9
	case 2:
		return 5
	case 4:
		return 7
	case 8:
		return 10
	}
	return 5
}
func (s *sb16) setPending(mask byte) error {
	s.pending = mask
	s.mixer[0x82] = mask
	return s.irq(s.irqLine(), mask != 0)
}
func (s *sb16) period() time.Duration {
	n := s.block
	if n < 1 {
		n = 1
	}
	return max(time.Microsecond, time.Duration(n)*time.Second/time.Duration(max(1, s.rate*s.channels*(s.bits/8))))
}
func (s *sb16) start(now time.Time, bits, channels, length int, signed, auto bool) {
	s.bits, s.channels, s.signed, s.auto = bits, channels, signed, auto
	s.block = max(length, 1)
	s.remaining = s.block
	s.active, s.paused = true, false
	s.silence = false
	s.next = now.Add(s.period())
}
func (s *sb16) dsp(value byte, now time.Time) error {
	if s.needed > 0 {
		s.params = append(s.params, value)
		if len(s.params) < s.needed {
			return nil
		}
		p := s.params
		switch s.command {
		case 0x10:
			s.appendPCM([]byte{p[0]}, 8, 1, false)
		case 0x14, 0x91:
			s.start(now, 8, 1, (int(p[0])|int(p[1])<<8)+1, false, false)
		case 0x40:
			s.rate = 1000000 / (256 - int(p[0]))
		case 0x41, 0x42:
			s.rate = max(1, min(48000, int(p[0])<<8|int(p[1])))
		case 0x48:
			s.block = (int(p[0]) | int(p[1])<<8) + 1
		case 0xe0:
			s.response = append(s.response, ^p[0])
		case 0xe4:
			s.test = p[0]
		case 0x80:
			s.start(now, 8, 1, (int(p[0])|int(p[1])<<8)+1, false, false)
			s.silence = true
		default:
			if s.command >= 0xb0 && s.command <= 0xcf {
				if s.command&8 != 0 {
					s.fault = fmt.Sprintf("SB16 ADC command %#x is unsupported", s.command)
					break
				}
				bits, channels := 8, 1
				if s.command < 0xc0 {
					bits = 16
				}
				if p[0]&0x20 != 0 {
					channels = 2
				}
				count := (int(p[1]) | int(p[2])<<8) + 1
				auto := s.command&4 != 0
				count *= bits / 8
				if !auto {
					count *= channels
				}
				s.start(now, bits, channels, count, p[0]&0x10 != 0, auto)
			}
		}
		s.needed = 0
		s.params = nil
		return nil
	}
	s.command = value
	if len(s.commands) == 64 {
		copy(s.commands, s.commands[1:])
		s.commands = s.commands[:63]
	}
	s.commands = append(s.commands, int(value))
	switch value {
	case 0x10, 0x40, 0xe0, 0xe4:
		s.needed = 1
	case 0x14, 0x41, 0x42, 0x48, 0x80, 0x91:
		s.needed = 2
	case 0x1c, 0x90:
		s.start(now, 8, 1, s.block, false, true)
	case 0x45, 0x47:
		s.auto, s.paused = true, false
		if s.block > 0 {
			s.active = true
			if s.remaining <= 0 {
				s.remaining = s.block
			}
			s.next = now.Add(s.period())
		}
	case 0xd0, 0xd5:
		s.paused = true
	case 0xd4, 0xd6:
		s.paused = false
		s.next = now.Add(s.period())
	case 0xd1:
		s.speaker = true
	case 0xd3:
		s.speaker = false
	case 0xd8:
		if s.speaker {
			s.response = append(s.response, 0xff)
		} else {
			s.response = append(s.response, 0)
		}
	case 0xd9, 0xda:
		s.auto = false
	case 0xe1:
		s.response = append(s.response, 4, 5)
	case 0xe3:
		s.response = append(s.response, []byte("COPYRIGHT (C) CREATIVE TECHNOLOGY LTD, 1992.\x00")...)
	case 0xe8:
		s.response = append(s.response, s.test)
	case 0xf2:
		return s.setPending(s.pending | 1)
	case 0xf3:
		return s.setPending(s.pending | 2)
	default:
		if value >= 0xb0 && value <= 0xcf {
			s.needed = 3
		} else {
			s.fault = fmt.Sprintf("unsupported SB16 DSP command %#x", value)
		}
	}
	return nil
}
func (s *sb16) io(ex hypervisor.X86Exit, now time.Time) (bool, error) {
	port := ex.Port
	audioPort := port >= 0x220 && port <= 0x22f
	dmaPort := port <= 15 || dmaPageChannel(port) >= 0 || port >= 0xc0 && port <= 0xde && port&1 == 0
	if !audioPort && !dmaPort {
		return false, nil
	}
	if ex.Size != 1 {
		if !ex.Write {
			for i := range ex.Data {
				ex.Data[i] = 0xff
			}
		}
		return true, nil
	}
	for i := uint32(0); i < ex.Count; i++ {
		data := &ex.Data[i]
		if dmaPort {
			value, _ := s.dma.port(port, ex.Write, *data)
			if !ex.Write {
				*data = value
			}
			continue
		}
		value := byte(0xff)
		if ex.Write {
			switch port - 0x220 {
			case 4:
				s.index = *data
			case 5:
				if s.index == 0 {
					s.resetMixer()
				} else if s.index != 0x82 {
					s.mixer[s.index] = *data
				}
				if s.index == 0x22 {
					s.mixer[0x30] = *data & 0xf0
					s.mixer[0x31] = *data << 4
				}
				if s.index == 4 {
					s.mixer[0x32] = *data & 0xf0
					s.mixer[0x33] = *data << 4
				}
			case 6:
				if *data&1 != 0 {
					s.reset = true
					s.active = false
					s.needed = 0
					s.params = nil
					s.response = nil
					if err := s.setPending(0); err != nil {
						return true, err
					}
				} else if s.reset {
					s.reset = false
					s.response = []byte{0xaa}
				}
			case 12:
				if err := s.dsp(*data, now); err != nil {
					return true, err
				}
			}
		} else {
			switch port - 0x220 {
			case 4:
				value = s.index
			case 5:
				value = s.mixer[s.index]
			case 10:
				if len(s.response) > 0 {
					value = s.response[0]
					s.response = s.response[1:]
				}
			case 12:
				value = 0
			case 14:
				value = 0
				if len(s.response) > 0 {
					value = 0x80
				}
				if err := s.setPending(s.pending &^ 1); err != nil {
					return true, err
				}
			case 15:
				if err := s.setPending(s.pending &^ 2); err != nil {
					return true, err
				}
				value = 0
			}
			*data = value
		}
	}
	return true, nil
}
func (s *sb16) dmaChannel() int {
	mask := s.mixer[0x81]
	if s.bits == 16 {
		for _, c := range []int{5, 6, 7} {
			if mask&(1<<c) != 0 {
				return c
			}
		}
	} else {
		for _, c := range []int{0, 1, 3} {
			if mask&(1<<c) != 0 {
				return c
			}
		}
	}
	return -1
}
func (s *sb16) poll(now time.Time) error {
	if !s.active || s.paused || s.pending != 0 || now.Before(s.next) {
		return nil
	}
	if s.silence {
		// DSP 80h is a timed silence generator, not a DMA operation.
		// It must neither read nor advance a guest DMA buffer.
		data := make([]byte, s.block)
		for i := range data {
			data[i] = 128
		}
		s.appendPCM(data, 8, 1, false)
		s.active, s.silence = false, false
		return s.setPending(s.pending | 1)
	}
	c := s.dmaChannel()
	data := make([]byte, 0, s.block)
	for len(data) < s.remaining {
		unit, ok := s.dma.readUnit(c, s.ram)
		if !ok {
			break
		}
		data = append(data, unit...)
	}
	if len(data) == 0 {
		s.next = now.Add(time.Millisecond)
		return nil
	}
	s.appendPCM(data, s.bits, s.channels, s.signed)
	s.remaining -= len(data)
	if s.remaining > 0 {
		s.next = now.Add(time.Millisecond)
		return nil
	}
	if s.auto {
		s.remaining = s.block
		s.next = now.Add(s.period())
	} else {
		s.active = false
	}
	flag := byte(1)
	if s.bits == 16 {
		flag = 2
	}
	return s.setPending(s.pending | flag)
}
func (s *sb16) deadline() time.Time {
	if s.active && !s.paused && s.pending == 0 {
		return s.next
	}
	return time.Time{}
}
func (s *sb16) appendPCM(data []byte, bits, channels int, signed bool) {
	bytesPerSample := bits / 8
	frameSize := bytesPerSample * channels
	for off := 0; off+frameSize <= len(data); off += frameSize {
		sample := func(ch int) int16 {
			p := off + min(ch, channels-1)*bytesPerSample
			v := int32(0)
			if bits == 16 {
				v = int32(binary.LittleEndian.Uint16(data[p:]))
				if signed {
					v = int32(int16(v))
				} else {
					v -= 32768
				}
			} else {
				v = int32(data[p])
				if signed {
					v = int32(int8(data[p]))
				} else {
					v -= 128
				}
				v *= 256
			}
			// SB16 DSP PCM commands enable DAC output independently of the old
			// SB 1.x speaker gate. Apply both digital voice and master levels.
			gain := int32(s.mixer[0x30+ch]>>3) * int32(s.mixer[0x32+ch]>>3)
			return int16(v * gain / (31 * 31))
		}
		left, right := sample(0), sample(1)
		s.phase += 44100
		for s.phase >= s.rate {
			s.phase -= s.rate
			s.totalFrames++
			if len(s.capture)+4 > sbCaptureLimit {
				s.truncated = true
				continue
			}
			s.capture = binary.LittleEndian.AppendUint16(s.capture, uint16(left))
			s.capture = binary.LittleEndian.AppendUint16(s.capture, uint16(right))
		}
	}
}
func (s *sb16) wav() []byte {
	b := make([]byte, 44, len(s.capture)+44)
	copy(b, "RIFF")
	binary.LittleEndian.PutUint32(b[4:], uint32(36+len(s.capture)))
	copy(b[8:], "WAVEfmt ")
	binary.LittleEndian.PutUint32(b[16:], 16)
	binary.LittleEndian.PutUint16(b[20:], 1)
	binary.LittleEndian.PutUint16(b[22:], 2)
	binary.LittleEndian.PutUint32(b[24:], 44100)
	binary.LittleEndian.PutUint32(b[28:], 44100*4)
	binary.LittleEndian.PutUint16(b[32:], 4)
	binary.LittleEndian.PutUint16(b[34:], 16)
	copy(b[36:], "data")
	binary.LittleEndian.PutUint32(b[40:], uint32(len(s.capture)))
	return append(b, s.capture...)
}
