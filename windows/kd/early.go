package kd

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/tinyrange/trex/channel"
)

const (
	earlyPacketLimit    = 4000
	earlyHeaderSize     = 8
	earlyManipulateSize = 24
	earlyWaitStateSize  = 80
	earlyContextSize    = 304
)

var earlyLeader = []byte("0000")

// EarlyEvent is a decoded packet from the April 1991 NT KD protocol.
type EarlyEvent struct {
	Kind                                       string
	Type                                       uint16
	API, Processor, ProcessorCount, Thread, PC uint32
	Code, Address, Status, Actual, Limit       uint32
	FirstChance                                bool
	Text                                       string
	Raw, Data                                  []byte
	Context                                    *MIPSContext
}

// MIPSContext is the R3000 register context carried by early NT KD.
type MIPSContext struct {
	GPR, FPR                     [32]uint32
	Lo, Hi, FCSR, PC, PSR, Flags uint32
}

func ParseMIPSContext(raw []byte) (MIPSContext, error) {
	if len(raw) != earlyContextSize {
		return MIPSContext{}, fmt.Errorf("early KD: context has %d bytes, want %d", len(raw), earlyContextSize)
	}
	le := binary.LittleEndian
	var out MIPSContext
	for i := range out.GPR {
		out.GPR[i] = le.Uint32(raw[0x90+4*i:])
		out.FPR[i] = le.Uint32(raw[0x10+4*i:])
	}
	out.Lo, out.Hi = le.Uint32(raw[0x110:]), le.Uint32(raw[0x114:])
	out.FCSR, out.PC = le.Uint32(raw[0x118:]), le.Uint32(raw[0x11c:])
	out.PSR, out.Flags = le.Uint32(raw[0x120:]), le.Uint32(raw[0x124:])
	return out, nil
}

// EarlySession uses the original eight-byte KD header and single-byte break-in.
// The caller advances an embedded target between requests and Poll calls.
type EarlySession struct {
	transport channel.ByteChannel
	ready     channel.ReadNotifier
	buffer    []byte
	pending   uint32
	stopped   bool
	prompt    *EarlyEvent
}

func NewEarlySession(transport channel.ByteChannel) (*EarlySession, error) {
	ready, ok := transport.(channel.ReadNotifier)
	if !ok || ready.ReadReady() == nil {
		return nil, fmt.Errorf("early KD: channel must expose read readiness")
	}
	return &EarlySession{transport: transport, ready: ready}, nil
}

func (s *EarlySession) Close() error  { return s.transport.Close() }
func (s *EarlySession) Stopped() bool { return s.stopped }

func earlyFrame(kind uint16, payload []byte) []byte {
	frame := make([]byte, earlyHeaderSize, len(payload)+earlyHeaderSize)
	copy(frame, earlyLeader)
	binary.LittleEndian.PutUint16(frame[4:], uint16(len(payload)))
	binary.LittleEndian.PutUint16(frame[6:], kind)
	return append(frame, payload...)
}

func (s *EarlySession) send(frame []byte) error {
	if capacity, ok := s.transport.(channel.WriteCapacityNotifier); ok {
		n, _, err := capacity.WriteCapacity()
		if err != nil && !errors.Is(err, channel.ErrWriteCapacityUnsupported) {
			return err
		}
		if err == nil && n < len(frame) {
			return channel.ErrWouldBlock
		}
	}
	return channel.WriteAll(s.transport, frame)
}

func (s *EarlySession) BreakIn() error {
	if err := s.send([]byte{0x62}); err != nil {
		return err
	}
	s.prompt = nil
	return nil
}

// ReplyPrompt responds to the current debugger console input request.
func (s *EarlySession) ReplyPrompt(text []byte) error {
	if s.prompt == nil {
		return fmt.Errorf("early KD: no prompt is pending")
	}
	if len(text) > earlyPacketLimit-16 || uint64(len(text)) > uint64(s.prompt.Limit) {
		return fmt.Errorf("early KD: prompt response exceeds limit %d", s.prompt.Limit)
	}
	payload := make([]byte, 16, 16+len(text))
	le := binary.LittleEndian
	le.PutUint32(payload, kdAPIGetString)
	le.PutUint32(payload[4:], s.prompt.Processor)
	le.PutUint32(payload[12:], uint32(len(text)))
	if err := s.send(earlyFrame(kdPacketDebugIO, append(payload, text...))); err != nil {
		return err
	}
	s.prompt = nil
	return nil
}

func (s *EarlySession) Request(api, processor, arg0, arg1, arg2 uint32, data []byte) error {
	if !s.stopped {
		return fmt.Errorf("early KD: target is running")
	}
	if s.pending != 0 {
		return fmt.Errorf("early KD: request %#x is pending", s.pending)
	}
	if api < 0x3130 || api > 0x313c {
		return fmt.Errorf("early KD: unsupported API %#x", api)
	}
	if len(data) > earlyPacketLimit-earlyManipulateSize {
		return fmt.Errorf("early KD: request exceeds packet limit")
	}
	payload := make([]byte, earlyManipulateSize, earlyManipulateSize+len(data))
	le := binary.LittleEndian
	le.PutUint32(payload, api)
	le.PutUint32(payload[4:], processor)
	le.PutUint32(payload[12:], arg0)
	le.PutUint32(payload[16:], arg1)
	le.PutUint32(payload[20:], arg2)
	payload = append(payload, data...)
	if err := s.send(earlyFrame(kdPacketStateManipulate, payload)); err != nil {
		return err
	}
	if api == kdAPIContinue || api == kdAPIContinue2 {
		s.stopped = false
	} else {
		s.pending = api
	}
	return nil
}

// Poll returns one complete event, preserving partial headers and payloads.
func (s *EarlySession) Poll() (*EarlyEvent, error) {
	var chunk [4096]byte
	for reads := 0; reads < 8; reads++ {
		for {
			at := bytes.Index(s.buffer, earlyLeader)
			if at < 0 {
				remaining := min(3, len(s.buffer))
				copy(s.buffer, s.buffer[len(s.buffer)-remaining:])
				s.buffer = s.buffer[:remaining]
				break
			}
			s.buffer = s.buffer[at:]
			if len(s.buffer) < earlyHeaderSize {
				break
			}
			n := int(binary.LittleEndian.Uint16(s.buffer[4:]))
			kind := binary.LittleEndian.Uint16(s.buffer[6:])
			if n == 0 || n > earlyPacketLimit || kind < 1 || kind > 3 {
				s.buffer = s.buffer[1:]
				continue
			}
			if len(s.buffer) < earlyHeaderSize+n {
				break
			}
			payload := append([]byte(nil), s.buffer[earlyHeaderSize:earlyHeaderSize+n]...)
			s.buffer = s.buffer[earlyHeaderSize+n:]
			event, err := parseEarlyEvent(kind, payload)
			if err != nil {
				return nil, err
			}
			switch kind {
			case kdPacketStateChange32:
				s.stopped, s.pending, s.prompt = true, 0, nil
			case kdPacketStateManipulate:
				if event.API == s.pending {
					s.pending = 0
				}
			case kdPacketDebugIO:
				if event.Kind == "prompt" {
					s.prompt = &EarlyEvent{Processor: event.Processor, Limit: event.Limit}
				}
			}
			return event, nil
		}
		select {
		case <-s.ready.ReadReady():
			n, err := s.transport.Read(chunk[:])
			if n > 0 {
				s.buffer = append(s.buffer, chunk[:n]...)
				continue
			}
			if errors.Is(err, channel.ErrWouldBlock) {
				return nil, nil
			}
			if err == nil {
				err = io.ErrNoProgress
			}
			return nil, err
		default:
			return nil, nil
		}
	}
	return nil, nil
}

func parseEarlyEvent(kind uint16, payload []byte) (*EarlyEvent, error) {
	event := &EarlyEvent{Type: kind, Raw: payload}
	le := binary.LittleEndian
	switch kind {
	case kdPacketStateChange32:
		if len(payload) < earlyWaitStateSize {
			return nil, fmt.Errorf("early KD: truncated state change")
		}
		event.API, event.Processor, event.ProcessorCount = le.Uint32(payload), le.Uint32(payload[4:]), le.Uint32(payload[8:])
		event.Thread, event.PC = le.Uint32(payload[12:]), le.Uint32(payload[16:])
		event.Kind = "state"
		switch event.API {
		case kdStateException:
			event.Kind = "exception"
			event.Code, event.Address = le.Uint32(payload[20:]), le.Uint32(payload[32:])
			event.FirstChance = le.Uint32(payload[56:]) != 0
			n := le.Uint32(payload[60:])
			if n > 16 {
				return nil, fmt.Errorf("early KD: oversized instruction stream in exception")
			}
			event.Data = payload[64 : 64+n]
		case kdStateLoadSymbols:
			event.Kind = "load_symbols"
			n := le.Uint32(payload[20:])
			if uint64(n) > uint64(len(payload)-earlyWaitStateSize) {
				return nil, fmt.Errorf("early KD: truncated symbol path")
			}
			event.Text = string(bytes.TrimRight(payload[earlyWaitStateSize:earlyWaitStateSize+n], "\x00"))
		}
	case kdPacketStateManipulate:
		if len(payload) < earlyManipulateSize {
			return nil, fmt.Errorf("early KD: truncated manipulate reply")
		}
		event.Kind = "reply"
		event.API, event.Processor, event.Status = le.Uint32(payload), le.Uint32(payload[4:]), le.Uint32(payload[8:])
		event.Address, event.Actual = le.Uint32(payload[12:]), le.Uint32(payload[20:])
		event.Data = payload[earlyManipulateSize:]
		if event.Status == 0 {
			switch event.API {
			case kdAPIGetContext:
				context, err := ParseMIPSContext(event.Data)
				if err != nil {
					return nil, err
				}
				event.Context = &context
			case kdAPIReadVirtual:
				if uint64(event.Actual) != uint64(len(event.Data)) {
					return nil, fmt.Errorf("early KD: inconsistent memory read length")
				}
			}
		}
	case kdPacketDebugIO:
		if len(payload) < 16 {
			return nil, fmt.Errorf("early KD: truncated debug I/O")
		}
		event.Kind = "debug_io"
		event.API, event.Processor = le.Uint32(payload), le.Uint32(payload[4:])
		n := le.Uint32(payload[8:])
		if uint64(n) > uint64(len(payload)-16) {
			return nil, fmt.Errorf("early KD: truncated debug text")
		}
		event.Text = string(payload[16 : 16+n])
		if event.API == kdAPIGetString {
			event.Kind = "prompt"
			event.Limit = le.Uint32(payload[12:])
		}
	}
	return event, nil
}
