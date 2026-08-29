package kd

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	channelpkg "github.com/tinyrange/trex/channel"
)

var errKDReset = errors.New("KD transport reset before acknowledgement")

const (
	kdInitialPacketID = uint32(0x80800000)
	kdSyncPacketID    = uint32(0x00000800)

	kdPacketLeader        = uint32(0x30303030)
	kdControlPacketLeader = uint32(0x69696969)
	kdBreakinPacket       = uint32(0x62626262)
	kdTrailingByte        = byte(0xaa)

	kdPacketStateChange32   = uint16(1)
	kdPacketStateManipulate = uint16(2)
	kdPacketDebugIO         = uint16(3)
	kdPacketAcknowledge     = uint16(4)
	kdPacketResend          = uint16(5)
	kdPacketReset           = uint16(6)
	kdPacketStateChange64   = uint16(7)
	kdPacketFileIO          = uint16(11)

	kdStateException   = uint32(0x3030)
	kdStateLoadSymbols = uint32(0x3031)
	kdStateCommand     = uint32(0x3032)

	kdAPIReadVirtual       = uint32(0x3130)
	kdAPIWriteVirtual      = uint32(0x3131)
	kdAPIGetContext        = uint32(0x3132)
	kdAPISetContext        = uint32(0x3133)
	kdAPIWriteBreakpoint   = uint32(0x3134)
	kdAPIRestoreBreakpoint = uint32(0x3135)
	kdAPIContinue          = uint32(0x3136)
	kdAPIContinue2         = uint32(0x313c)
	kdAPIReadPhysical      = uint32(0x313d)
	kdAPIWritePhysical     = uint32(0x313e)

	kdAPIPrintString = uint32(0x3230)
	kdAPIGetString   = uint32(0x3231)
	kdAPICreateFile  = uint32(0x3430)
	kdAPIReadFile    = uint32(0x3431)
	kdAPIWriteFile   = uint32(0x3432)
	kdAPICloseFile   = uint32(0x3433)

	kdContinueStatus           = uint32(0x00010002)
	kdStatusObjectNameNotFound = uint32(0xc0000034)
	kdStatusInvalidHandle      = uint32(0xc0000008)

	kdHeaderSize         = 16
	kdStateChangeSize    = 240
	kdManipulate32Size   = 52
	kdManipulate64Size   = 56
	kdManipulateSize     = kdManipulate64Size
	kdFileIOSize         = 64
	kdDefaultPacketLimit = 0xffff
)

type kdPacket struct {
	Leader   uint32
	Type     uint16
	Count    uint16
	ID       uint32
	Checksum uint32
	Payload  []byte
}

type kdWire struct {
	channel channelpkg.ByteChannel
	maximum int

	writeMu      sync.Mutex
	stateMu      sync.Mutex
	remoteID     uint32
	localID      uint32
	lastOutbound []byte
	ackWait      map[uint32]chan error
}

func newKDWire(channel channelpkg.ByteChannel, maximum int) *kdWire {
	return &kdWire{channel: channel, maximum: maximum, remoteID: kdInitialPacketID, localID: kdInitialPacketID, ackWait: make(map[uint32]chan error)}
}

func (w *kdWire) readPacket() (kdPacket, error) {
	var leaderData [4]byte
	if err := w.readLeader(leaderData[:]); err != nil {
		return kdPacket{}, err
	}
	leader := binary.LittleEndian.Uint32(leaderData[:])
	if leader == kdBreakinPacket {
		return kdPacket{Leader: leader}, nil
	}
	var rest [kdHeaderSize - 4]byte
	if _, err := io.ReadFull(w.channel, rest[:]); err != nil {
		return kdPacket{}, err
	}
	packet := kdPacket{
		Leader: leader, Type: binary.LittleEndian.Uint16(rest[0:2]), Count: binary.LittleEndian.Uint16(rest[2:4]),
		ID: binary.LittleEndian.Uint32(rest[4:8]), Checksum: binary.LittleEndian.Uint32(rest[8:12]),
	}
	if int(packet.Count) > w.maximum {
		return kdPacket{}, fmt.Errorf("KD packet payload %d exceeds limit %d", packet.Count, w.maximum)
	}
	if leader == kdPacketLeader {
		packet.Payload = make([]byte, int(packet.Count))
		if _, err := io.ReadFull(w.channel, packet.Payload); err != nil {
			return kdPacket{}, err
		}
		trailing := []byte{0}
		if _, err := io.ReadFull(w.channel, trailing); err != nil {
			return kdPacket{}, err
		}
		if trailing[0] != kdTrailingByte {
			return kdPacket{}, fmt.Errorf("invalid KD trailing byte %#x", trailing[0])
		}
	}
	return packet, nil
}

func (w *kdWire) readLeader(out []byte) error {
	var window [4]byte
	filled := 0
	for {
		value := []byte{0}
		if _, err := io.ReadFull(w.channel, value); err != nil {
			return err
		}
		if filled < len(window) {
			window[filled] = value[0]
			filled++
		} else {
			copy(window[:], window[1:])
			window[len(window)-1] = value[0]
		}
		if filled == len(window) && kdIsLeader(window[:]) {
			copy(out, window[:])
			return nil
		}
	}
}

func kdIsLeader(value []byte) bool {
	return len(value) == 4 && (bytes.Equal(value, []byte("0000")) || bytes.Equal(value, []byte("iiii")) || bytes.Equal(value, []byte("bbbb")))
}

func (w *kdWire) sendControl(kind uint16, id uint32) error {
	var packet [kdHeaderSize]byte
	binary.LittleEndian.PutUint32(packet[0:4], kdControlPacketLeader)
	binary.LittleEndian.PutUint16(packet[4:6], kind)
	binary.LittleEndian.PutUint32(packet[8:12], id)
	w.writeMu.Lock()
	err := channelpkg.WriteAll(w.channel, packet[:])
	w.writeMu.Unlock()
	return err
}

func (w *kdWire) sendData(kind uint16, payload []byte) (uint32, <-chan error, error) {
	if len(payload) > w.maximum || len(payload) > int(^uint16(0)) {
		return 0, nil, fmt.Errorf("KD payload %d exceeds limit", len(payload))
	}
	w.stateMu.Lock()
	id := w.remoteID
	ack := make(chan error, 1)
	w.ackWait[id] = ack
	w.stateMu.Unlock()
	packet := make([]byte, kdHeaderSize+len(payload)+1)
	binary.LittleEndian.PutUint32(packet[0:4], kdPacketLeader)
	binary.LittleEndian.PutUint16(packet[4:6], kind)
	binary.LittleEndian.PutUint16(packet[6:8], uint16(len(payload)))
	binary.LittleEndian.PutUint32(packet[8:12], id)
	binary.LittleEndian.PutUint32(packet[12:16], kdChecksum(payload))
	copy(packet[kdHeaderSize:], payload)
	packet[len(packet)-1] = kdTrailingByte
	w.writeMu.Lock()
	err := channelpkg.WriteAll(w.channel, packet)
	w.writeMu.Unlock()
	if err != nil {
		w.stateMu.Lock()
		delete(w.ackWait, id)
		w.stateMu.Unlock()
		return 0, nil, err
	}
	w.stateMu.Lock()
	w.lastOutbound = append(w.lastOutbound[:0], packet...)
	w.stateMu.Unlock()
	return id, ack, nil
}

func (w *kdWire) handleControl(packet kdPacket) error {
	switch packet.Type {
	case kdPacketAcknowledge:
		w.stateMu.Lock()
		id := packet.ID &^ kdSyncPacketID
		if ack := w.ackWait[id]; ack != nil {
			delete(w.ackWait, id)
			ack <- nil
			close(ack)
		}
		if id == w.remoteID {
			w.remoteID ^= 1
		}
		w.stateMu.Unlock()
	case kdPacketResend:
		w.stateMu.Lock()
		outbound := append([]byte(nil), w.lastOutbound...)
		w.stateMu.Unlock()
		if len(outbound) != 0 {
			w.writeMu.Lock()
			err := channelpkg.WriteAll(w.channel, outbound)
			w.writeMu.Unlock()
			return err
		}
	case kdPacketReset:
		w.stateMu.Lock()
		w.remoteID = kdInitialPacketID
		w.localID = kdInitialPacketID
		for id, ack := range w.ackWait {
			delete(w.ackWait, id)
			ack <- errKDReset
			close(ack)
		}
		w.stateMu.Unlock()
	}
	return nil
}

func (w *kdWire) validateAndAcknowledge(packet kdPacket) (bool, error) {
	if kdChecksum(packet.Payload) != packet.Checksum {
		return false, w.sendControl(kdPacketResend, 0)
	}
	id := packet.ID &^ kdSyncPacketID
	w.stateMu.Lock()
	if packet.ID&kdSyncPacketID != 0 {
		w.localID = id
	}
	expected := w.localID
	accept := id == expected
	duplicate := id == expected^1
	if accept {
		w.localID ^= 1
	}
	w.stateMu.Unlock()
	if !accept && !duplicate {
		return false, w.sendControl(kdPacketResend, expected)
	}
	if err := w.sendControl(kdPacketAcknowledge, id); err != nil {
		return false, err
	}
	return accept, nil
}

func (w *kdWire) breakin() error {
	w.writeMu.Lock()
	err := channelpkg.WriteAll(w.channel, []byte{0x62})
	w.writeMu.Unlock()
	return err
}

func kdChecksum(data []byte) uint32 {
	var result uint32
	for _, value := range data {
		result += uint32(value)
	}
	return result
}

func kdU16(data []byte, offset int) uint16 {
	if offset < 0 || offset+2 > len(data) {
		return 0
	}
	return binary.LittleEndian.Uint16(data[offset:])
}
func kdU32(data []byte, offset int) uint32 {
	if offset < 0 || offset+4 > len(data) {
		return 0
	}
	return binary.LittleEndian.Uint32(data[offset:])
}
func kdU64(data []byte, offset int) uint64 {
	if offset < 0 || offset+8 > len(data) {
		return 0
	}
	return binary.LittleEndian.Uint64(data[offset:])
}
