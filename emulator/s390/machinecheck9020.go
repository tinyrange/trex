package s390

import (
	"fmt"
	"time"
)

const (
	ceLogoutStart9020    = 32 * 4
	ceLogoutSize9020     = 48 * 4
	ioceLogoutStart9020  = 81 * 4
	ioceLogoutSize9020   = 45 * 4
	seLogoutSize9020     = 6 * 8
	pgmSEStopped9020     = 0x80 // A27-2734-2, figure 2-19.
	ceStorageCheck9020   = 168 - ceLogoutStart9020
	ioceSERequest9020    = 352 - ioceLogoutStart9020
	ioceCheck1Offset9020 = 356 - ioceLogoutStart9020
	ioceStorageCheck9020 = 362 - ioceLogoutStart9020
)

type machineCheck9020 struct {
	Pending      bool
	Element      uint16
	Logout       [ceLogoutSize9020]byte
	StorageID    int
	StorageUntil uint64
	Storage      [seLogoutSize9020]byte
}

type ioceMachineCheck9020 struct {
	CE    uint16
	Check machineCheck9020
}

// storageDataAbort9020 ends an instruction whose storage cycle was cancelled.
type storageDataAbort9020 struct{}

type storageLogout9020 struct {
	Stopped bool
	Logout  [seLogoutSize9020]byte
}

// ReplayStorageLogout9020 supplies captured check data for an SE or DE that has
// accepted a logout-stop signal. Storage IDs start at one. The capture is
// seven words in 9020A order or six doublewords in 9020D/E order. Call between
// Run calls. A CE or IOCE machine check may be queued separately.
func (m *Machine) ReplayStorageLogout9020(storageID int, logout []byte) error {
	if !m.Model9020 || m.cfg.IOCE || !m.CPUs[0].storageModuleInstalled9020(storageID) {
		return fmt.Errorf("9020 storage logout: invalid storage element %d", storageID)
	}
	size := seLogoutSize9020
	if m.cfg.Model9020A {
		size = seLogoutSize9020A
	}
	if len(logout) != size {
		return fmt.Errorf("9020 storage logout: element %d logout has %d bytes, want %d", storageID, len(logout), size)
	}
	state := m.storageLogoutState9020(storageID)
	if state.Stopped {
		return fmt.Errorf("9020 storage logout: element %d is already stopped for logout", storageID)
	}
	var data [seLogoutSize9020]byte
	copy(data[:], logout)
	m.stopStorage9020(storageID, data)
	return nil
}

func (m *Machine) storageLogoutState9020(id int) *storageLogout9020 {
	if m.cfg.Model9020A {
		return &m.storage9020A[id-1].Logout
	}
	return &m.storageLogout9020[id-1]
}

func (m *Machine) stopStorage9020(id int, logout [seLogoutSize9020]byte) {
	*m.storageLogoutState9020(id) = storageLogout9020{Stopped: true, Logout: logout}
	if m.cfg.Model9020E && id > max9020EStorageElements {
		m.scheduleDisplay9020E(id - max9020EStorageElements - 1)
	}
	for _, c := range m.CPUs {
		c.ipageValid = false
	}
	m.CSS.reschedule()
}

func (m *Machine) storageStopped9020(absolute uint32) bool {
	se := absolute / m.storageElementSize9020()
	return se < uint32(m.storageSlots9020()) && m.storageLogoutState9020(int(se)+1).Stopped
}

func (c *CPU) logoutStorage9020(mcwAddress uint32, b, storageID int) {
	// A27-9020-01 §12.8 places six doublewords directly after the MCW.
	// Release the element when all six stores have completed.
	c.logoutStorage9020To(mcwAddress+8, b, storageID, seLogoutSize9020, 8)
}

func (c *CPU) logoutStorage9020To(result uint32, b, storageID int, size, word uint32) {
	seSize := c.M.storageElementSize9020()
	if !c.storageModuleInstalled9020(storageID) || !c.storageConfigured9020(uint32(storageID-1)*seSize) {
		c.PSW.CC = 1 // Storage-interface timeout (7201-02 CE FETOM §1).
		return
	}
	state := c.M.storageLogoutState9020(storageID)
	end := result + size - 1
	for _, address := range [...]uint32{result, end} {
		if c.realToAbs(address&c.amask)/seSize == uint32(storageID-1) {
			c.program(pgmSEStopped9020)
		}
	}
	c.checkStore(result, size, b)
	data := state.Logout
	if !state.Stopped {
		data = c.M.liveStorageLogout9020(storageID)
		state.Stopped = true
	}
	for offset := uint32(0); offset < size; offset += word {
		if word == 4 {
			c.storeWord(result+offset, b, be.Uint32(data[offset:]))
		} else {
			c.storeDouble(result+offset, b, be.Uint64(data[offset:]))
		}
	}
	*state = storageLogout9020{}
	if c.M.cfg.Model9020E && storageID > max9020EStorageElements {
		c.M.scheduleDisplay9020E(storageID - max9020EStorageElements - 1)
	}
	c.M.CSS.reschedule()
	c.PSW.CC = 0
}

func logoutRange9020(element uint16) (start uint32, size int) {
	if element == 0 {
		return ceLogoutStart9020, ceLogoutSize9020
	}
	return ioceLogoutStart9020, ioceLogoutSize9020
}

// ReplayMachineCheck9020 presents a hardware logout to a CE at an instruction
// boundary, as described in A27-2734-2 sections 9.6 and 12.2.3. Element zero
// denotes a local CE check, and 1 through 3 denote the corresponding IOCE.
// The captured bytes are in architectural storage order. Call between Run
// calls. The receiving CE takes the interruption when its PSW enables it.
func (m *Machine) ReplayMachineCheck9020(cpu, element int, logout []byte) error {
	if !m.Model9020 || m.cfg.IOCE || cpu < 0 || cpu >= len(m.CPUs) {
		return fmt.Errorf("9020 machine check: invalid receiving CE %d", cpu)
	}
	if element < 0 || element > 3 {
		return fmt.Errorf("9020 machine check: invalid element %d", element)
	}
	_, size := logoutRange9020(uint16(element))
	if len(logout) != size {
		return fmt.Errorf("9020 machine check: element %d logout has %d bytes, want %d", element, len(logout), size)
	}
	c := m.CPUs[cpu]
	if c.maintenance9020.machineCheck.Pending {
		return fmt.Errorf("9020 machine check: CE %d already has a pending check", cpu)
	}
	check := &c.maintenance9020.machineCheck
	check.Pending, check.Element = true, uint16(element)
	copy(check.Logout[:], logout)
	c.pswChanged = true
	return nil
}

// A data check is detected in the SE. The CE can acknowledge it with LOS
// while the SE holds its check information (9020D FETOM figs. 8-2 and 8-8).
func (c *CPU) storageDataCheck9020(address uint32) {
	c.storageCheck9020(address, 0x08) // CE logword 42, SE/DE Data Check.
}

func (c *CPU) storageCheck9020(address uint32, checkCode byte) {
	check := &c.maintenance9020.machineCheck
	if !check.Pending {
		id := int(address/c.M.storageElementSize9020()) + 1
		check.Pending = true
		check.StorageID = id
		check.StorageUntil = c.M.tod + durationTOD(2500*time.Nanosecond)
		if c.M.isDisplayAddress9020(address) && !c.PSW.MC {
			// A masked CE check does not assert the DE logout-stop line.
			check.StorageUntil = 0
		}
		check.Storage = c.M.liveStorageLogout9020(id)
		// D22A0500.SPT statements 239 and 244–248.
		check.Logout[ceStorageCheck9020] = byte(id) << 4
		check.Logout[ceStorageCheck9020+1] = checkCode
		c.pswChanged = true
	}
	if c.PSW.MC {
		panic(storageDataAbort9020{})
	}
}

func (c *CPU) pendingMachineCheck9020() *machineCheck9020 {
	if check := &c.maintenance9020.machineCheck; check.Pending {
		return check
	}
	// The CE honors simultaneous IOCE requests in element order 3, 2, 1
	// (IBM 9020D System FETOM, p. 3-14).
	for i := len(c.M.CSS.ioceChecks9020) - 1; i >= 0; i-- {
		ioce := &c.M.CSS.ioceChecks9020[i]
		if ioce.Check.Pending && c.ioceConfigured9020(uint16(i)) &&
			(c.M.configuration9020[29+i].Set || ioce.CE == c.Addr) {
			return &ioce.Check
		}
	}
	return nil
}

func (c *CPU) takeMachineCheck9020(check *machineCheck9020) {
	if id := check.StorageID; id != 0 && !c.logoutStopInhibited9020() && c.M.tod < check.StorageUntil &&
		!c.M.storageLogoutState9020(id).Stopped && c.storageConfigured9020(uint32(id-1)*c.M.storageElementSize9020()) {
		c.M.stopStorage9020(id, check.Storage)
		check.Logout[ceStorageCheck9020+1] |= 0x02
	}
	if !c.preparePSA9020() {
		return
	}
	start, size := logoutRange9020(check.Element)
	if !c.S.valid(c.Prefix+start, uint32(size)) {
		c.Check = true
		c.checkReason = "9020 machine check: logout area is outside storage"
		return
	}
	for offset := 0; offset < size; offset += 4 {
		c.setLowWord(start+uint32(offset), be.Uint32(check.Logout[offset:]))
	}
	// Logout leaves diagnostic execution before the guest handler runs.
	c.maintenance9020.reverseSumParity = false
	c.maintenance9020.reverseMarkParity = false
	c.maintenance9020.reverseAddressParity = 0
	c.maintenance9020.countLogoutAt = 0
	c.PSW.IntCode, c.PSW.ILC = check.Element, 0
	c.swap(pswMCOld, pswMCNew)
	kind := fmt.Sprintf("machine check %04X", check.Element)
	c.M.Interrupts[kind]++
	c.M.event("machine-check", c, kind)
	*check = machineCheck9020{}
}
