package s390

import (
	"math/bits"
	"time"
)

const (
	displayCVGsPerDG9020E  = 6
	displayGroupSlots9020E = 9
	displayScanSlots9020E  = displayCVGsPerDG9020E * displayGroupSlots9020E
	displayFrame9020E      = time.Second / 55
	displayForceBit9020E   = 1 << 16    // MCW bit 47.
	displayWrapBit9020E    = 1 << 12    // MCW bit 51.
	displaySelect9020E     = 0xfffc0000 // MCW bits 32–45.
)

type displayCVG9020E struct {
	Address  uint32
	FrameEnd uint64
	ReadyAt  uint64
	Started  bool
}

type displayWrap9020E struct {
	Active, Failed   bool
	DG               byte
	Requests         byte
	Destination      uint32
	Base             int
	Length, Received int
	Data             [512]uint64
}

// The DG interfaces are paired to four buffers. Each buffer serves six
// independently addressed CVGs (IBM 9020D/E Design Data, figures 4-4 and 4-8).
type displayRefresh9020E struct {
	DGMask     uint16
	Invalid    bool
	Tails      [4]byte // One-based DG routed to each buffer.
	Force      [8]byte
	CVG        [4 * displayCVGsPerDG9020E]displayCVG9020E
	FrameEnd   uint64
	NextScan   uint64
	BusyUntil  uint64
	NextCESlot uint64
	Wrap       displayWrap9020E
}

func displayBuffer9020E(mask uint16, dg int) int {
	switch (mask >> (14 - 2*dg)) & 3 {
	case 2:
		return dg % 4
	case 1:
		return (dg + 1) % 4
	default:
		return -1
	}
}

func (m *Machine) configureDisplay9020E(index int, mask uint16) bool {
	d := &m.displayRefresh9020E[index]
	d.DGMask = mask
	d.Invalid = false
	clear(d.Tails[:])
	for dg := range 8 {
		field := (mask >> (14 - 2*dg)) & 3
		if field == 3 {
			d.Invalid = true
		}
		if buffer := displayBuffer9020E(mask, dg); buffer >= 0 {
			d.Invalid = d.Invalid || d.Tails[buffer] != 0
			d.Tails[buffer] = byte(dg + 1)
		}
	}
	m.scheduleDisplay9020E(index)
	return !d.Invalid
}

func (c *CPU) displayTarget9020E(mcw uint64) int {
	id := int(mcw >> 28 & 0xf)
	index := id - max9020EStorageElements - 1
	if index < 0 || index >= c.M.cfg.DisplayElements9020E ||
		!c.storageConfigured9020(uint32(id-1)*bytesPer9020SE) || c.M.storageLogout9020[id-1].Stopped {
		return -1
	}
	return index
}

func (c *CPU) forceDisplay9020E(mcw uint64) {
	index := c.displayTarget9020E(mcw)
	selected, requests := int(mcw>>24&0xf), byte(mcw>>18&0x3f)
	if index < 0 || selected > 8 {
		c.PSW.CC = 1
		return
	}
	d := &c.M.displayRefresh9020E[index]
	for dg := range d.Force {
		if selected == 0 || selected == dg+1 {
			d.Force[dg] = requests
		}
	}
	c.M.scheduleDisplay9020E(index)
	c.PSW.CC = 0
}

// AD3 replaces the selected DG interface with the CE wrap receiver. The
// address sequencers count four positions for each captured doubleword.
func (c *CPU) startDisplayWrap9020E(a uint32, b int, mcw uint64) {
	const fields = 0x00000fff00000000 | displaySelect9020E | displayWrapBit9020E
	if !c.M.cfg.Model9020E || !c.stateZero9020() || mcw&^uint64(fields) != 0x00ad300000000000 ||
		mcw&displayWrapBit9020E == 0 {
		c.program(pgmSpecification)
	}
	index := c.displayTarget9020E(mcw)
	dg := int(mcw>>24&0xf) - 1
	requests := byte(mcw >> 18 & 0x3f)
	length := int(mcw >> 34 & 0x1ff)
	if index < 0 || dg < 0 || dg >= 8 {
		c.PSW.CC = 1
		return
	}
	d := &c.M.displayRefresh9020E[index]
	if d.Wrap.Active || d.Invalid || displayBuffer9020E(d.DGMask, dg) < 0 {
		c.PSW.CC = 1
		return
	}
	c.setTimerInhibit9020(mcw&0x0000080000000000 != 0)
	c.PSW.CC = 0
	if length == 0 {
		return
	}
	if requests|d.requests(dg, c.M.CSS.radarDisplay9020E(index, dg)) == 0 {
		c.PSW.CC = 1
		return
	}
	c.checkStore(a+8, uint32(length)*8, b)
	d.Wrap = displayWrap9020E{Active: true, DG: byte(dg), Requests: requests, Destination: a + 8, Base: b, Length: length}
	c.maintenance9020.displayWrap = byte(index + 1)
	c.M.scheduleDisplay9020E(index)
}

// Complete the stores in the requesting CE's context, with its original
// logical addressing and storage protection. False holds the CE in DIAG.
func (c *CPU) finishDisplayWrap9020E() bool {
	index := int(c.maintenance9020.displayWrap) - 1
	d := &c.M.displayRefresh9020E[index]
	w := &d.Wrap
	id := index + max9020EStorageElements + 1
	if !c.storageConfigured9020(uint32(id-1) * bytesPer9020SE) {
		w.Failed = true
	}
	if !w.Failed && w.Received < w.Length {
		return false
	}
	c.maintenance9020.displayWrap = 0
	w.Active = false
	c.M.scheduleDisplay9020E(index)
	for i, value := range w.Data[:w.Received] {
		c.storeDouble(w.Destination+uint32(i)*8, w.Base, value)
	}
	c.PSW.CC = 0
	if w.Failed {
		c.PSW.CC = 1
	}
	return true
}

func (c *CPU) cancelDisplayWrap9020E() {
	if c.maintenance9020.displayWrap != 0 {
		index := int(c.maintenance9020.displayWrap) - 1
		c.maintenance9020.displayWrap = 0
		c.M.displayRefresh9020E[index].Wrap.Active = false
		c.M.scheduleDisplay9020E(index)
	}
}

func (d *displayRefresh9020E) wrapping(dg int) bool {
	return d.Wrap.Active && !d.Wrap.Failed && d.Wrap.Received < d.Wrap.Length && int(d.Wrap.DG) == dg
}

func (d *displayRefresh9020E) requests(dg int, endpoint *rcuEndpoint9020) byte {
	if d.wrapping(dg) && d.Wrap.Requests != 0 {
		return d.Wrap.Requests
	}
	return d.Force[dg] | endpoint.displayRequests()
}

// Fig. 4-6 runs continuously at 400 ns per slot. Five slots are exactly
// two microseconds in TOD units. Round each slot boundary independently.
func displaySlot9020E(tod uint64) uint64 {
	const span = 2 * todMicro
	return tod/span*5 + tod%span*5/span
}

func displaySlotTOD9020E(slot uint64) uint64 {
	const span = 2 * todMicro
	return slot/5*span + (slot%5*span+4)/5
}

func nextDisplayPair9020E(slot uint64) uint64 {
	switch phase := slot % displayGroupSlots9020E; {
	case phase >= 7:
		return slot + displayGroupSlots9020E - phase
	case phase&1 != 0:
		return slot + 1
	default:
		return slot
	}
}

// Idle CVGs enter the next complete priority scan together. The FAA D24A
// CVG access test compares their first six SOD pairs in CVG number order.
func (d *displayRefresh9020E) nextFrame9020E(at uint64) uint64 {
	frame := durationTOD(displayFrame9020E)
	if d.FrameEnd == 0 {
		d.FrameEnd = at + frame
	} else if at >= d.FrameEnd {
		d.FrameEnd += ((at-d.FrameEnd)/frame + 1) * frame
	}
	slot := displaySlot9020E(d.FrameEnd - 1)
	return displaySlotTOD9020E((slot/displayScanSlots9020E + 1) * displayScanSlots9020E)
}

func (m *Machine) scheduleDisplay9020E(index int) {
	d := &m.displayRefresh9020E[index]
	id := index + max9020EStorageElements + 1
	available := !d.Invalid && !m.storageLogout9020[id-1].Stopped && m.ccr9020(uint32(7+id))&stateMask9020 != 0
	if d.Wrap.Active && (!available || displayBuffer9020E(d.DGMask, int(d.Wrap.DG)) < 0) {
		d.Wrap.Failed = true
	}
	active := false
	if available {
		for dg := range d.Force {
			if displayBuffer9020E(d.DGMask, dg) >= 0 &&
				d.requests(dg, m.CSS.radarDisplay9020E(index, dg)) != 0 {
				active = true
				break
			}
		}
	}
	if active {
		if d.NextScan == 0 {
			d.NextScan = displaySlotTOD9020E(nextDisplayPair9020E(displaySlot9020E(m.tod) + 1))
		}
	} else {
		d.NextScan = 0
		if d.Wrap.Active && d.Wrap.Received < d.Wrap.Length {
			d.Wrap.Failed = true
		}
	}
	m.updateDisplayDeadline9020E()
}

func (m *Machine) updateDisplayDeadline9020E() {
	m.nextDisplay9020E = 0
	for i := range m.cfg.DisplayElements9020E {
		if next := m.displayRefresh9020E[i].NextScan; next != 0 && (m.nextDisplay9020E == 0 || next < m.nextDisplay9020E) {
			m.nextDisplay9020E = next
		}
	}
}

func (m *Machine) tickDisplay9020E() {
	for i := range m.cfg.DisplayElements9020E {
		d := &m.displayRefresh9020E[i]
		for d.NextScan != 0 && d.NextScan <= m.tod {
			at := d.NextScan
			slot := displaySlot9020E(at)
			d.NextScan = displaySlotTOD9020E(nextDisplayPair9020E(slot + 2))
			m.scanDisplay9020E(i, d, slot, at)
			if d.Wrap.Active && d.Wrap.Received == d.Wrap.Length {
				m.scheduleDisplay9020E(i)
			}
		}
	}
	m.updateDisplayDeadline9020E()
}

func (m *Machine) scanDisplay9020E(index int, d *displayRefresh9020E, slot, at uint64) {
	phase := int(slot % displayScanSlots9020E)
	buffer, cvg := phase%displayGroupSlots9020E/2, phase/displayGroupSlots9020E
	dg := int(d.Tails[buffer]) - 1
	if dg < 0 {
		return
	}
	endpoint := m.CSS.radarDisplay9020E(index, dg)
	request := byte(0x20 >> cvg)
	cursor := buffer*displayCVGsPerDG9020E + cvg
	if d.requests(dg, endpoint)&request == 0 || at < d.CVG[cursor].ReadyAt {
		return
	}
	d.BusyUntil = displaySlotTOD9020E(slot + 2)
	id := index + max9020EStorageElements + 1
	data, ok := m.displayQuadword9020E(id, d, cursor, at)
	if !ok {
		return
	}
	if d.wrapping(dg) {
		w := &d.Wrap
		w.Received += copy(w.Data[w.Received:w.Length], data[:])
	} else if endpoint.displayRequests()&request != 0 && endpoint.receiveDisplay(data) {
		m.CSS.presentRCUAttention9020()
	}
}

// Each CE request takes one doubleword slot for its bank. A CVG uses both
// slots in its pair, leaving one CE-only slot per group even at full load.
func (c *CPU) accessDisplayStorage9020E(address, size uint32) {
	m := c.M
	index := int((address - displayBase9020E) / bytesPer9020SE)
	if index >= m.cfg.DisplayElements9020E || size == 0 {
		return
	}
	d := &m.displayRefresh9020E[index]
	logout := &m.storageLogout9020[index+max9020EStorageElements]
	slot := displaySlot9020E(m.tod)
	if displaySlotTOD9020E(slot) < m.tod {
		slot++
	}
	slot = max(slot, d.NextCESlot)
	end := address + size
	for word := address &^ 7; word < end; word += 8 {
		if slot&1 != uint64(word>>3&1) {
			slot++
		}
		for {
			at := displaySlotTOD9020E(slot)
			m.tod = at
			if m.nextDisplay9020E != 0 && m.nextDisplay9020E <= at {
				m.tickDisplay9020E()
			}
			if logout.Stopped {
				c.program(pgmSEStopped9020)
			}
			if d.BusyUntil <= at {
				break
			}
			slot += 2
		}
		slot++
	}
	d.NextCESlot = slot
}

const displayAddressMask9020E = bytesPer9020DE - 16

// Storage supplies a quadword to its assigned DG buffer. Even Transfer
// and EOD words replace the odd word; an odd command follows the even
// data. DG wire parity occupies bit zero of each transmitted word.
func (m *Machine) displayQuadword9020E(id int, d *displayRefresh9020E, slot int, at uint64) ([2]uint64, bool) {
	cursor := &d.CVG[slot]
	start := !cursor.Started
	if start {
		cursor.Address = uint32(32 + 32*slot)
		cursor.Started = true
		cursor.FrameEnd = d.nextFrame9020E(at)
	}
	physical := uint32(id-1)*bytesPer9020SE + cursor.Address
	data := [2]uint64{be.Uint64(m.S.Mem[physical:]), be.Uint64(m.S.Mem[physical+8:])}
	bad := [2]byte{m.storageBadParity9020[physical], m.storageBadParity9020[physical+8]}
	m.recordStorage9020(physical, 16, accFetch, 0, 0, 0)
	if (bad[0]|bad[1]) != 0 && m.ccr9020(uint32(7+id))&0x01000000 == 0 {
		m.stopStorage9020(id, m.liveDisplayLogout9020E(id))
		return data, false
	}
	if start {
		m.S.Mem[physical+4] = 0xff
		m.clearStorageDataParity9020(physical+4, 1)
	}
	cursor.Address = (cursor.Address + 16) & displayAddressMask9020E
	for i, word := range data {
		switch word & 0x7800000000000000 {
		case 0x5000000000000000:
			cursor.Address = uint32(word) & displayAddressMask9020E
		case 0x4000000000000000:
			cursor.Started = false
			cursor.ReadyAt = cursor.FrameEnd
		default:
			continue
		}
		if i == 0 {
			data[1], bad[1] = word, bad[0]
		}
		break
	}
	for i, word := range data {
		value := word & 0x7fffffffffffffff
		parity := uint64(1 ^ (bits.OnesCount64(value)+bits.OnesCount8(bad[i]))&1)
		data[i] = value | parity<<63
	}
	return data, true
}

// The first DE control word asserts EOD for each of its first 24 bits
// that was written as one.
func (m *Machine) stopDisplayCVGs9020E(id int, address, size uint32) {
	d := &m.displayRefresh9020E[id-max9020EStorageElements-1]
	base := uint32(id-1) * bytesPer9020SE
	nextFrame := d.nextFrame9020E(m.tod)
	for a := address; a < min(address+size, base+3); a++ {
		bits := m.S.Mem[a]
		for bit := range 8 {
			if bits&(0x80>>bit) != 0 {
				cvg := &d.CVG[int(a-base)*8+bit]
				if cvg.Started {
					cvg.ReadyAt = cvg.FrameEnd
				} else {
					cvg.ReadyAt = nextFrame
				}
				cvg.Started = false
			}
		}
	}
}
