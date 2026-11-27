package s390

import "time"

func (c *CPU) stateZero9020() bool {
	if c.Addr >= 4 {
		return false
	}
	ccr := c.M.configuration9020[20+c.Addr]
	return ccr.Set && ccr.Word&stateMask9020 == 0
}

// The I2 lines are disconnected in states One, Two, and Three.
func (c *CPU) diagInterleave9020(i2 byte) interleave9020 {
	if !c.stateZero9020() {
		return c.maintenance9020.interleave
	}
	mode := interleave9020(i2) & interleaveMask9020
	if mode == interleaveMask9020 {
		c.program(pgmSpecification)
	}
	return mode
}

func (c *CPU) endOpMCW9020(mcw uint64) {
	const inhibitTimer = 0x0000080000000000  // MCW bit 20.
	const logOnCount = 0x0200000000000000    // MCW bit 6.
	const countField = 0x000007ff00000000    // MCW bits 21–31.
	const faultControls = 0x3c00000000000000 // MCW bits 2–5.
	const diagnoseSE1 = 0x8000               // MCW bit 48.
	force := mcw&displayForceBit9020E != 0
	var displayFields uint64
	if force && c.M.cfg.Model9020E && c.stateZero9020() {
		displayFields = displaySelect9020E | displayForceBit9020E
	}
	mcw, display := mcw&^displayFields, mcw&displayFields
	if mcw&^(inhibitTimer|logOnCount|countField|faultControls|diagnoseSE1) != 0x0001000000000000 ||
		mcw&(logOnCount|faultControls) != 0 && !c.stateZero9020() {
		c.program(pgmSpecification)
	}
	c.setTimerInhibit9020(mcw&inhibitTimer != 0)
	state := &c.maintenance9020
	state.diagnosticSE1 = mcw&diagnoseSE1 != 0
	state.reverseSumParity = mcw&0x2000000000000000 != 0
	state.reverseMarkParity = mcw&0x1000000000000000 != 0
	state.reverseAddressParity = storageCycleFlags9020(mcw>>58) & badAddressParity9020
	state.countLogoutAt = 0
	if mcw&logOnCount != 0 {
		c.startCountLogout9020(uint16((mcw & countField) >> 32))
	}
	if display != 0 {
		c.forceDisplay9020E(display)
	}
	c.purgeTLB()
	c.ipageValid = false
}

// The 7201-02 End Op kernel starts the 11-bit FLT cycle counter. Its
// first cycle is still part of DIAG, so a count of one leaves the next
// instruction unexecuted. Later expirations are taken at instruction
// boundaries on the virtual CE clock (7201-02 FETOM §§4-20, 4-33).
func (c *CPU) startCountLogout9020(count uint16) {
	const cycle = 200 * time.Nanosecond
	state := &c.maintenance9020
	now := c.M.tod
	state.delayUntil = max(state.delayUntil, now+durationTOD(cycle))
	state.countLogoutAt = now + durationTOD(time.Duration(max(count, 1))*cycle)
}

func (c *CPU) countLogoutDue9020() bool {
	at := c.maintenance9020.countLogoutAt
	return at != 0 && c.M.tod >= at
}

// A diagnostic count requests logout directly, independently of the mask
// for automatic machine checks. Record the native CE state used by the
// maintenance program (A27-9020-01 figure 12-3, FAA D22A4500 770–777).
func (c *CPU) takeCountLogout9020() {
	c.maintenance9020.countLogoutAt = 0
	var check machineCheck9020
	switch c.interleaveMode9020() {
	case defeatInterleave9020:
		check.Logout[137-ceLogoutStart9020] = 0x10
	case reverseInterleave9020:
		check.Logout[167-ceLogoutStart9020] = 0x80
	}
	be.PutUint32(check.Logout[(38*4)-ceLogoutStart9020:], uint32(c.atr9020()>>8))
	be.PutUint32(check.Logout[(49*4)-ceLogoutStart9020:], c.M.ccr9020(20+uint32(c.Addr)))
	be.PutUint32(check.Logout[(50*4)-ceLogoutStart9020:], c.maintenance9020.darMask)
	be.PutUint32(check.Logout[(56*4)-ceLogoutStart9020:], c.maintenance9020.dar)
	c.takeMachineCheck9020(&check)
}
