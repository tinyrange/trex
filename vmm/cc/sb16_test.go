package cc

import (
	"bytes"
	"encoding/binary"
	"j5.nz/cc/hypervisor"
	"testing"
	"time"
)

func sbPort(t *testing.T, s *sb16, now time.Time, port uint16, write bool, value byte) byte {
	t.Helper()
	data := []byte{value}
	handled, err := s.io(hypervisor.X86Exit{Port: port, Size: 1, Count: 1, Write: write, Data: data}, now)
	if err != nil || !handled {
		t.Fatal(handled, err)
	}
	return data[0]
}
func sbCommands(t *testing.T, s *sb16, now time.Time, values ...byte) {
	t.Helper()
	for _, v := range values {
		sbPort(t, s, now, 0x22c, true, v)
	}
}
func TestSB16ResetVersionAndIndependentIRQAcknowledgements(t *testing.T) {
	var level bool
	s := newSB16(nil, func(line uint32, v bool) error {
		if line != 5 {
			t.Fatal(line)
		}
		level = v
		return nil
	})
	now := time.Unix(0, 0)
	sbPort(t, s, now, 0x226, true, 1)
	sbPort(t, s, now, 0x226, true, 0)
	if sbPort(t, s, now, 0x22e, false, 0) != 0x80 || sbPort(t, s, now, 0x22a, false, 0) != 0xaa {
		t.Fatal("DSP reset handshake")
	}
	sbCommands(t, s, now, 0xe1)
	if sbPort(t, s, now, 0x22a, false, 0) != 4 || sbPort(t, s, now, 0x22a, false, 0) != 5 {
		t.Fatal("DSP version")
	}
	sbCommands(t, s, now, 0xf2, 0xf3)
	if !level || s.pending != 3 {
		t.Fatal("IRQ raise")
	}
	sbPort(t, s, now, 0x22e, false, 0)
	if !level || s.pending != 2 {
		t.Fatal("8-bit ACK cleared 16-bit IRQ")
	}
	sbPort(t, s, now, 0x22f, false, 0)
	if level || s.pending != 0 {
		t.Fatal("16-bit ACK")
	}
}
func TestSB16GuestDMAUnsigned8PCMAndDeadline(t *testing.T) {
	ram := make([]byte, 0x1000)
	ram[0x100], ram[0x101] = 0, 255
	var irq bool
	s := newSB16(ram, func(_ uint32, v bool) error { irq = v; return nil })
	now := time.Unix(0, 0)
	programISADMA(s.dma, 1, 0x100, 1, 0, 0x48)
	sbCommands(t, s, now, 0x41, 0x56, 0x22, 0xc0, 0, 1, 0) // 22050 Hz, two unsigned mono samples
	if err := s.poll(s.deadline().Add(-1)); err != nil {
		t.Fatal(err)
	}
	if irq || len(s.capture) != 0 {
		t.Fatal("DMA completed before its deadline")
	}
	if err := s.poll(s.deadline()); err != nil {
		t.Fatal(err)
	}
	if !irq || s.active || len(s.capture) != 16 {
		t.Fatal(irq, s.active, len(s.capture))
	}
	if binary.LittleEndian.Uint16(s.capture) != 0x8000 || binary.LittleEndian.Uint16(s.capture[8:]) != 0x7f00 {
		t.Fatalf("PCM conversion %x", s.capture)
	}
	w := s.wav()
	if string(w[:4]) != "RIFF" || binary.LittleEndian.Uint32(w[40:]) != 16 || !bytes.Equal(w[44:], s.capture) {
		t.Fatal("WAV output")
	}
}
func TestSB16SignedStereoAutoInitPauseAndExit(t *testing.T) {
	ram := make([]byte, 0x1000)
	source := []byte{0, 0x80, 0xff, 0x7f, 0x34, 0x12, 0xcc, 0xed}
	copy(ram[0x200:], source)
	s := newSB16(ram, func(uint32, bool) error { return nil })
	now := time.Unix(0, 0)
	programISADMA(s.dma, 5, 0x100, 3, 0, 0x58)
	sbCommands(t, s, now, 0x41, 0xac, 0x44, 0xb6, 0x30, 3, 0) // 44100 Hz, signed stereo, four words/block
	deadline := s.deadline()
	sbCommands(t, s, now, 0xd5)
	if err := s.poll(deadline.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(s.capture) != 0 {
		t.Fatal("paused DMA transferred")
	}
	sbCommands(t, s, deadline, 0xd6)
	if err := s.poll(s.deadline()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s.capture, source) || !s.active || s.pending != 2 {
		t.Fatalf("auto PCM %x", s.capture)
	}
	sbPort(t, s, deadline, 0x22f, false, 0)
	sbCommands(t, s, deadline, 0xd9)
	if err := s.poll(s.deadline()); err != nil {
		t.Fatal(err)
	}
	if s.active || len(s.capture) != 16 || !bytes.Equal(s.capture[8:], source) {
		t.Fatal("auto exit/reload")
	}
}
func TestSB16NoFabricatedDMAAndBoundedCapture(t *testing.T) {
	s := newSB16(make([]byte, 32), func(uint32, bool) error { return nil })
	now := time.Unix(0, 0)
	sbCommands(t, s, now, 0xc0, 0, 0, 0)
	if err := s.poll(s.deadline()); err != nil {
		t.Fatal(err)
	}
	if s.pending != 0 || len(s.capture) != 0 {
		t.Fatal("unprogrammed DMA fabricated playback")
	}
	s.capture = make([]byte, sbCaptureLimit)
	s.rate = 44100
	s.appendPCM([]byte{0, 255}, 8, 1, false)
	if !s.truncated || s.totalFrames != 2 || len(s.capture) != sbCaptureLimit {
		t.Fatal("capture limit")
	}
}

func TestSB16ContinueAutoAfterExit(t *testing.T) {
	ram := make([]byte, 16)
	copy(ram, []byte{0, 255})
	s := newSB16(ram, func(uint32, bool) error { return nil })
	now := time.Unix(0, 0)
	programISADMA(s.dma, 1, 0, 1, 0, 0x58)
	sbCommands(t, s, now, 0xc6, 0, 1, 0, 0xda)
	if err := s.poll(s.deadline()); err != nil {
		t.Fatal(err)
	}
	if s.active {
		t.Fatal("auto exit ignored")
	}
	sbPort(t, s, now, 0x22e, false, 0)
	before := len(s.capture)
	sbCommands(t, s, now, 0x45)
	if !s.active || !s.auto || s.fault != "" {
		t.Fatal("8-bit auto continuation")
	}
	if err := s.poll(s.deadline()); err != nil {
		t.Fatal(err)
	}
	if len(s.capture) != before*2 {
		t.Fatal("continued block missing")
	}
}

func TestSB16TimedSilenceDoesNotConsumeDMA(t *testing.T) {
	s := newSB16([]byte{1, 2, 3, 4}, func(uint32, bool) error { return nil })
	now := time.Unix(0, 0)
	programISADMA(s.dma, 1, 0, 3, 0, 0x48)
	before := s.dma.channels[1]
	sbCommands(t, s, now, 0x41, 0xac, 0x44, 0x80, 3, 0)
	if err := s.poll(s.deadline().Add(-1)); err != nil {
		t.Fatal(err)
	}
	if len(s.capture) != 0 || s.pending != 0 {
		t.Fatal("silence IRQ before its deadline")
	}
	if err := s.poll(s.deadline()); err != nil {
		t.Fatal(err)
	}
	if s.active || s.pending != 1 || len(s.capture) != 16 || !bytes.Equal(s.capture, make([]byte, 16)) || s.dma.channels[1] != before {
		t.Fatal("silence read DMA or emitted non-silence")
	}
}
