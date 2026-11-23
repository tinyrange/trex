package r3000

import (
	"encoding/binary"
	"fmt"

	"github.com/tinyrange/trex/block"
	"github.com/tinyrange/trex/scsi"
)

const (
	scsiIdle       = 0xff
	scsiDataOut    = 0
	scsiDataIn     = 1
	scsiStatus     = 3
	scsiMessageOut = 6
	scsiMessageIn  = 7
)

type scsiController struct {
	targets                                                     [8]*scsi.Disk
	reg                                                         [16]byte
	fifo                                                        [16]byte
	fifoLength                                                  int
	phase, command, status, interrupt, sequence, target, result byte
	cdb                                                         []byte
	data                                                        []byte
	offset                                                      int
	count                                                       uint32
	dmaWaiting, pioWaiting, messagePending                      bool
}

func (m *Machine) AttachDisk(target int, media block.Device) error {
	if target < 0 || target > 6 {
		return fmt.Errorf("r3000: SCSI disk target must be 0–6")
	}
	if m.scsi.phase != scsiIdle {
		return fmt.Errorf("r3000: SCSI bus is busy")
	}
	if media.Geometry().LogicalBlockSize != 512 {
		return fmt.Errorf("r3000: expected 512-byte SCSI sectors")
	}
	disk, err := scsi.NewDisk(media, scsi.DiskIdentity{Vendor: "DEC", Product: "RZ26", Revision: "1.0"})
	if err != nil {
		return err
	}
	m.scsi.targets[target] = &disk
	return nil
}

func (s *scsiController) reset() {
	targets, id := s.targets, s.reg[8]&7
	*s = scsiController{targets: targets, phase: scsiIdle}
	s.reg[8], s.reg[9], s.reg[6] = id, 2, 5
}

func (s *scsiController) signal(cause, phase byte) {
	s.interrupt, s.status = cause, 0x80|(phase&7)
	if phase == scsiIdle {
		s.status = 0x80
	}
}

func (s *scsiController) push(value byte) {
	if s.fifoLength == len(s.fifo) {
		s.status |= 0x40
		return
	}
	s.fifo[s.fifoLength] = value
	s.fifoLength++
}

func (s *scsiController) access(m *Machine, reg, size, value uint32, write bool) (uint32, bool) {
	if size != 1 {
		return 0, false
	}
	if write {
		switch reg {
		case 2:
			s.push(byte(value))
			if s.pioWaiting && s.phase == scsiDataOut {
				s.transferPIO()
			}
		case 3:
			s.issue(m, byte(value))
		default:
			s.reg[reg] = byte(value)
		}
		return 0, true
	}
	switch reg {
	case 0:
		return s.count & 255, true
	case 1:
		return s.count >> 8 & 255, true
	case 2:
		if s.fifoLength == 0 {
			return 0, true
		}
		value = uint32(s.fifo[0])
		s.fifoLength--
		copy(s.fifo[:], s.fifo[1:s.fifoLength+1])
		if s.pioWaiting {
			s.transferPIO()
		}
		return value, true
	case 3:
		return uint32(s.command), true
	case 4:
		return uint32(s.status), true
	case 5:
		value = uint32(s.interrupt)
		s.interrupt = 0
		s.status &= 0x17
		return value, true
	case 6:
		return uint32(s.sequence), true
	case 7:
		return uint32(s.sequence<<5 | byte(s.fifoLength)), true
	case 8, 11, 12:
		return uint32(s.reg[reg]), true
	default:
		return 0, true
	}
}

func (s *scsiController) issue(m *Machine, command byte) {
	s.command = command
	if command&0x80 != 0 {
		s.count = uint32(s.reg[0]) | uint32(s.reg[1])<<8
		s.status &^= 0x10
	}
	switch command & 0x7f {
	case 0, 0x1a, 0x1b, 0x44, 0x45:
	case 1:
		s.fifoLength = 0
	case 2:
		s.reset()
		s.command = command
	case 3:
		s.phase, s.fifoLength = scsiIdle, 0
		s.dmaWaiting, s.pioWaiting, s.messagePending = false, false, false
		if s.reg[8]&0x40 == 0 {
			s.signal(0x80, scsiIdle)
		}
	case 0x41, 0x42, 0x43, 0x46:
		s.selectTarget(command & 0x7f)
	case 0x10:
		if s.phase == scsiIdle || s.phase == scsiMessageOut {
			s.begin(0)
		} else if command&0x80 == 0 {
			s.transferPIO()
		} else {
			s.transferDMA(m)
		}
	case 0x11:
		if s.phase != scsiStatus {
			s.signal(0x40, scsiIdle)
			return
		}
		s.fifoLength = 0
		s.push(s.result)
		s.push(0)
		s.phase = scsiMessageIn
		s.signal(8, scsiMessageIn)
	case 0x12:
		s.phase, s.fifoLength = scsiIdle, 0
		s.dmaWaiting, s.pioWaiting, s.messagePending = false, false, false
		s.signal(0x20, scsiIdle)
	default:
		s.signal(0x40, scsiIdle)
	}
}

func (s *scsiController) selectTarget(command byte) {
	s.dmaWaiting, s.pioWaiting, s.messagePending = false, false, false
	s.target = s.reg[4] & 7
	if s.target == s.reg[8]&7 || s.targets[s.target] == nil {
		s.phase, s.sequence = scsiIdle, 0
		s.signal(0x20, scsiIdle)
		return
	}
	switch command {
	case 0x41:
		s.begin(0)
	case 0x42:
		s.begin(1)
	case 0x46:
		s.begin(3)
	case 0x43:
		s.sequence, s.fifoLength, s.phase = 1, 0, scsiMessageOut
		s.signal(0x18, scsiMessageOut)
	}
}

func (s *scsiController) begin(start int) {
	s.data, s.cdb, s.offset, s.result = nil, nil, 0, 0
	s.phase = scsiStatus
	if s.fifoLength-start < 6 || s.targets[s.target] == nil {
		s.fifoLength = 0
		s.signal(0x40, scsiStatus)
		return
	}
	s.cdb = append([]byte(nil), s.fifo[start:s.fifoLength]...)
	s.fifoLength = 0
	out := 0
	switch s.cdb[0] {
	case 0x0a:
		out = int(s.cdb[4])
		if out == 0 {
			out = 256
		}
	case 0x2a, 0x2e, 0x2f:
		if len(s.cdb) >= 10 && (s.cdb[0] != 0x2f || s.cdb[1]&2 != 0) {
			out = int(binary.BigEndian.Uint16(s.cdb[7:]))
		}
	}
	if out > 0 {
		s.data = make([]byte, out*512)
		s.phase = scsiDataOut
	} else {
		s.execute(nil)
		if len(s.data) != 0 {
			s.phase = scsiDataIn
		}
	}
	s.sequence = 4
	s.signal(0x18, s.phase)
}

func (s *scsiController) execute(out []byte) {
	result, err := s.targets[s.target].Execute(s.cdb, out)
	if err != nil {
		s.result = 2
		return
	}
	s.result = result.Status
	s.data = result.Data
}

func (s *scsiController) finishTransfer() {
	if s.offset >= len(s.data) || s.result != 0 {
		if s.phase == scsiDataOut && s.result == 0 {
			s.execute(s.data)
		}
		s.phase = scsiStatus
	}
	s.signal(0x10, s.phase)
}

func (s *scsiController) transferPIO() {
	s.pioWaiting = false
	switch s.phase {
	case scsiDataIn:
		if s.fifoLength == len(s.fifo) {
			s.pioWaiting = true
			return
		}
		if s.offset < len(s.data) {
			s.push(s.data[s.offset])
			s.offset++
		}
	case scsiDataOut:
		if s.fifoLength == 0 {
			s.pioWaiting = true
			return
		}
		n := copy(s.data[s.offset:], s.fifo[:s.fifoLength])
		s.offset += n
		copy(s.fifo[:], s.fifo[n:s.fifoLength])
		s.fifoLength -= n
	case scsiStatus, scsiMessageIn:
		if s.phase == scsiMessageIn && !s.messagePending {
			s.signal(0x40, scsiMessageIn)
			return
		}
		if s.fifoLength == len(s.fifo) {
			s.pioWaiting = true
			return
		}
		if s.phase == scsiStatus {
			s.push(s.result)
			s.phase, s.messagePending = scsiMessageIn, true
			s.signal(0x10, scsiMessageIn)
		} else {
			s.push(0)
			s.messagePending = false
			s.signal(8, scsiMessageIn)
		}
		return
	default:
		s.signal(0x40, scsiIdle)
		return
	}
	s.finishTransfer()
}

func (s *scsiController) transferDMA(m *Machine) {
	const (
		control = 0x108 / 8
		count   = 0x110 / 8
		address = 0x118 / 8
	)
	direction := s.phase == scsiDataOut
	if s.phase != scsiDataIn && !direction {
		s.dmaWaiting = false
		s.signal(0x40, s.phase)
		return
	}
	board := &m.board
	if board[control]&1 == 0 || (board[control]&2 != 0) != direction || board[count] == 0 {
		s.dmaWaiting = true
		return
	}
	s.dmaWaiting = false
	n := s.count
	if n == 0 {
		n = 65536
	}
	n = min(n, board[count], uint32(len(s.data)-s.offset))
	if m.dma(board[address], s.data[s.offset:s.offset+int(n)], !direction) {
		s.offset += int(n)
		s.count = uint32(uint16(s.count - n))
		board[address] += n
		board[count] -= n
		if board[count] == 0 {
			board[control] |= 0x100
		}
	} else {
		board[control] |= 0x400
		s.result = 2
	}
	s.finishTransfer()
	s.status |= 0x10
}
