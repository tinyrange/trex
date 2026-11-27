package r3000

import (
	"github.com/tinyrange/trex/scsi"
)

const (
	wdStatus    = 23
	wdCommand   = 24
	wdData      = 25
	wdAuxStatus = 27
)

// WD33C93A indirect registers. A read of SCSI status acknowledges the
// interrupt, while the directly addressed auxiliary status is non-destructive.
type wd33c93 struct {
	modelB      bool
	address     byte
	reg         [27]byte
	initiatorID byte
	irq         bool
	data        []byte
	scsiStatus  byte
	nextStatus  byte
	phase       byte
	selected    bool
	pio         []byte
	pioCount    uint32
	writeCDB    []byte
	writeData   []byte
	writeLen    uint32
	combined    bool
}

type wd33c93Host interface {
	scsiTarget(target byte) *scsi.Disk
	scsiDMAEnabled(toRAM bool) bool
	scsiTransfer(data []byte, toRAM bool) bool
}

func (s *wd33c93) port(host wd33c93Host, dataPort bool, value byte, write bool) uint32 {
	// BSY describes a transfer running in the controller, not a target
	// that remains selected while its phase interrupt is serviced.
	request := len(s.data) != 0 || s.pioCount != 0
	busy := s.selected
	if s.modelB {
		busy = request && !s.irq
	}
	aux := truth(s.irq)<<7 | truth(busy)<<5 | truth(request)
	if !dataPort {
		if write {
			s.address = value & 31
		}
		return aux
	}
	address := s.address
	if address == wdAuxStatus {
		return aux
	}
	if address >= byte(len(s.reg)) {
		return 0
	}
	if address != wdCommand && address != wdData {
		s.address++
	}
	if write {
		switch address {
		case wdStatus, 26:
			// Status and the WD33C93A queue-tag location are read-only.
		case wdCommand:
			s.command(host, value)
		case wdData:
			s.reg[address] = value
			if s.pioCount != 0 {
				s.pio = append(s.pio, value)
				s.pioCount--
				s.setTransferCount(s.transferCount() - 1)
				if s.pioCount == 0 {
					s.pioOut(host)
				}
			}
		default:
			s.reg[address] = value
		}
	} else {
		switch address {
		case wdStatus:
			status := s.reg[wdStatus]
			s.irq = false
			if s.nextStatus != 0 {
				s.signal(s.nextStatus)
				s.nextStatus = 0
			}
			return uint32(status)
		case wdData:
			if len(s.data) != 0 {
				s.reg[wdData] = s.data[0]
				s.data = s.data[1:]
				s.setTransferCount(s.transferCount() - 1)
				if len(s.data) == 0 {
					if s.selected {
						s.finishPIOIn()
					} else {
						s.complete()
					}
				}
			}
		}
	}
	return uint32(s.reg[address])
}

func (s *wd33c93) signal(status byte) {
	s.reg[wdStatus], s.irq = status, true
}

func (s *wd33c93) reset() {
	ownID := s.reg[0]
	// Reset latches the arbitration ID. Later writes to the shared
	// OWN ID/CDB SIZE register can describe a command length.
	*s = wd33c93{address: wdCommand, modelB: s.modelB, initiatorID: ownID & 7}
	s.reg[0] = ownID
	s.signal(ownID >> 3 & 1)
}

func (s *wd33c93) transferCount() uint32 {
	return uint32(s.reg[18])<<16 | uint32(s.reg[19])<<8 | uint32(s.reg[20])
}

func (s *wd33c93) setTransferCount(n uint32) {
	s.reg[18], s.reg[19], s.reg[20] = byte(n>>16), byte(n>>8), byte(n)
}

func (s *wd33c93) complete() {
	s.reg[15], s.reg[16] = s.scsiStatus, 0x60
	s.signal(0x16)
}

func (s *wd33c93) command(host wd33c93Host, command byte) {
	s.reg[wdCommand] = command
	switch command & 0x7f {
	case 0:
		s.reset()
	case 1:
		s.clearSelection()
		s.data = nil
		s.signal(0x22) // Selection or transfer aborted.
	case 2, 3:
		// Assert ATN and negate ACK do not finish a command.
	case 4:
		s.clearSelection()
		s.data = nil
	case 0x0f:
		s.reg[1] |= 4 // Set intermediate disconnect interrupt enable.
	case 0x20:
		s.transferInfo(host, command&0x80 != 0)
	case 6, 7, 8, 9:
		target := s.reg[21] & 7
		if host.scsiTarget(target) == nil || s.initiatorID == target {
			s.signal(0x42)
			return
		}
		if command&0x7f < 8 {
			phase := byte(2) // Command.
			if command&0x7f == 6 {
				phase = 6 // Message out after SELECT WITH ATN.
			}
			s.phase, s.selected = phase, true
			s.nextStatus = 0x88 | phase
			s.signal(0x11)
			return
		}
		if s.combined && len(s.writeCDB) != 0 {
			s.writeBurst(host, s.transferCount(), false)
			return
		}
		s.clearSelection()
		s.selectAndTransfer(host, host.scsiTarget(target))
	default:
		s.signal(0x40)
	}
}

func (s *wd33c93) clearSelection() {
	s.selected, s.phase, s.nextStatus = false, 0, 0
	s.pio, s.pioCount, s.writeCDB, s.writeData = nil, 0, nil, nil
	s.writeLen, s.combined = 0, false
}

func (s *wd33c93) transferInfo(host wd33c93Host, single bool) {
	if !s.selected {
		s.signal(0x40)
		return
	}
	count := s.transferCount()
	if single || count == 0 {
		count = 1
	}
	s.setTransferCount(count)
	switch s.phase {
	case 6, 2:
		// MESSAGE OUT and COMMAND are short initiator messages.
		if count > 260 {
			s.signal(0x48 | s.phase)
			return
		}
		s.pio, s.pioCount = make([]byte, 0, count), count
	case scsiDataOut:
		s.writeBurst(host, count, true)
	case 1:
		s.data = s.data[:min(uint32(len(s.data)), count)]
		s.dma(host)
	case 3:
		s.data = []byte{s.scsiStatus}
	case 7:
		s.data = []byte{0} // COMMAND COMPLETE.
	default:
		s.signal(0x48 | s.phase)
	}
}

func (s *wd33c93) pioOut(host wd33c93Host) {
	if s.phase == 6 {
		s.phase = 2
		s.signal(0x18 | s.phase)
		return
	}
	target := host.scsiTarget(s.reg[21] & 7)
	if target == nil {
		s.clearSelection()
		s.signal(0x42)
		return
	}
	if s.phase == scsiDataOut {
		s.appendWrite(target, s.pio)
		return
	}
	cdb := s.pio
	length, err := target.DataOutSize(cdb)
	if err != nil {
		s.clearSelection()
		s.signal(0x40)
		return
	}
	if length != 0 {
		s.beginWrite(cdb, length, false)
		s.signal(0x18)
		return
	}
	r, err := target.Execute(cdb, nil)
	if err != nil {
		s.clearSelection()
		s.signal(0x40)
		return
	}
	s.scsiStatus, s.data, s.phase = r.Status, r.Data, 3
	if len(s.data) != 0 {
		s.phase = 1
	}
	s.signal(0x18 | s.phase)
}

func (s *wd33c93) beginWrite(cdb []byte, length uint32, combined bool) {
	s.writeCDB = append([]byte(nil), cdb...)
	s.writeData = make([]byte, 0, length)
	s.writeLen, s.combined = length, combined
	s.phase, s.selected = scsiDataOut, true
}

func (s *wd33c93) writeBurst(host wd33c93Host, count uint32, allowPIO bool) {
	target := host.scsiTarget(s.reg[21] & 7)
	if len(s.writeCDB) == 0 || target == nil {
		s.signal(0x40)
		return
	}
	n := min(count, s.writeLen-uint32(len(s.writeData)))
	if n == 0 {
		s.appendWrite(target, nil)
		return
	}
	if host.scsiDMAEnabled(false) {
		data := make([]byte, n)
		if !host.scsiTransfer(data, false) {
			s.signal(0x48)
			return
		}
		s.setTransferCount(count - n)
		s.appendWrite(target, data)
	} else if allowPIO {
		s.pio = make([]byte, 0, n)
		s.pioCount = n
	} else {
		s.appendWrite(target, nil)
	}
}

func (s *wd33c93) appendWrite(target *scsi.Disk, data []byte) {
	s.writeData = append(s.writeData, data...)
	if uint32(len(s.writeData)) < s.writeLen {
		if s.combined {
			s.reg[16] = 0x46 // Select-and-transfer paused at the transfer count.
			s.signal(0x48 | scsiDataOut)
		} else {
			s.signal(0x18 | scsiDataOut)
		}
		return
	}
	result, err := target.Execute(s.writeCDB, s.writeData)
	if err != nil {
		s.clearSelection()
		s.signal(0x40)
		return
	}
	s.scsiStatus = result.Status
	if s.combined {
		s.clearSelection()
		s.complete()
	} else {
		s.writeCDB, s.writeData, s.pio, s.writeLen = nil, nil, nil, 0
		s.phase = scsiStatus
		s.signal(0x18 | scsiStatus)
	}
}

func (s *wd33c93) finishPIOIn() {
	switch s.phase {
	case 1:
		s.phase = 3
	case 3:
		s.phase = 7
	case 7:
		s.clearSelection()
		s.signal(0x41)
		return
	}
	s.signal(0x18 | s.phase)
}

func (s *wd33c93) selectAndTransfer(host wd33c93Host, target *scsi.Disk) {
	s.scsiStatus, s.data, s.irq = 0, nil, false
	cdb := s.reg[3:15]
	count := s.transferCount()
	length, err := target.DataOutSize(cdb)
	if err != nil {
		s.signal(0x40)
		return
	}
	if length != 0 {
		s.beginWrite(cdb, length, true)
		s.writeBurst(host, count, false)
		return
	}
	result, err := target.Execute(cdb, nil)
	if err != nil {
		s.signal(0x40)
		return
	}
	s.scsiStatus = result.Status
	s.data = result.Data[:min(uint32(len(result.Data)), count)]
	if len(s.data) == 0 {
		s.complete()
		return
	}
	s.dma(host)
}

func (s *wd33c93) dma(host wd33c93Host) {
	if len(s.data) == 0 || !host.scsiDMAEnabled(true) {
		return
	}
	n := uint32(len(s.data))
	if !host.scsiTransfer(s.data, true) {
		s.data = nil
		s.signal(0x49)
		return
	}
	s.setTransferCount(s.transferCount() - n)
	s.data = nil
	if s.selected {
		s.finishPIOIn()
	} else {
		s.complete()
	}
}
