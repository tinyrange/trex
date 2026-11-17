package s390

import (
	"encoding/binary"
	"fmt"
)

// SCHIBINI in the original AWSCHAN constructs 64-byte private entries at
// COMBUF's wrapped 16-bit offset 8000. The physical address is COMBUF+8000,
// not COMBUF-8000: the original far pointer has a zero offset.
const p390Subchannels = p390Combuf + 0x8000

func (p *P390) subchannel(c *CPU) []byte {
	id := c.GR[1]
	if id&0xffff0000 != 0x00010000 {
		c.program(pgmOperand)
	}
	n := id & 0xffff
	// The complete private table must fit the original 64K selector.
	if n >= 512 {
		return nil
	}
	s := p.Aperture[p390Subchannels+n*64 : p390Subchannels+(n+1)*64]
	if s[5]&1 == 0 || binary.LittleEndian.Uint32(s[0x34:]) == 0xffffffff {
		return nil
	}
	return s
}

// storeSubchannel exposes the architected SCHIB, never the OS/2 far pointers
// and driver-private fields following its status word.
func (p *P390) storeSubchannel(c *CPU, a uint32, b int) {
	c.privileged()
	if a&3 != 0 {
		c.program(pgmSpecification)
	}
	s := p.subchannel(c)
	if s == nil {
		c.PSW.CC = 3
		return
	}
	c.checkStore(a, 52, b)
	var out [52]byte
	copy(out[:24], s[:24])
	// Private PMCW has 24 bytes, followed by a four-byte monitor/ORB word;
	// architectural PMCW word six is reserved, not that private control word.
	copy(out[28:40], s[0x1c:0x28])
	for i, v := range out {
		c.storeByte(a+uint32(i), b, v)
	}
	c.PSW.CC = 0
}

func (p *P390) modifySubchannel(c *CPU, a uint32, b int) {
	c.privileged()
	if a&3 != 0 {
		c.program(pgmSpecification)
	}
	s := p.subchannel(c)
	var in [28]byte
	for i := range in {
		in[i] = c.fetchByte(a+uint32(i), b)
	}
	if binary.BigEndian.Uint32(in[4:])&0xc7000000 != 0 {
		c.program(pgmOperand)
	}
	if s == nil {
		c.PSW.CC = 3
		return
	}
	x := &p.interrupts[c.GR[1]&0xffff]
	if x.pending {
		c.PSW.CC = 1
		return
	}
	if x.fc != 0 {
		c.PSW.CC = 2
		return
	}
	// Only writable PMCW fields: device identity, installed paths, IOCB and
	// device-map pointers remain owned by the original OS/2 channel program.
	copy(s[:4], in[:4])
	s[4] = in[4] & 0x38
	s[5] = (s[5] & 3) | (in[5] & 0xfc)
	s[8] = in[8]
	copy(s[12:14], in[12:14])
	x.enabled = s[5]&0x80 != 0
	x.isc = s[4] >> 3 & 7
	x.intparm = binary.BigEndian.Uint32(s)
	c.PSW.CC = 0
}

func (p *P390) startSubchannel(c *CPU, a uint32, b int) {
	c.privileged()
	if a&3 != 0 {
		c.program(pgmSpecification)
	}
	s := p.subchannel(c)
	var orb [12]byte
	for i := range orb {
		orb[i] = c.fetchByte(a+uint32(i), b)
	}
	if s == nil || s[5]&0x80 == 0 {
		c.PSW.CC = 3
		return
	}
	x := &p.interrupts[c.GR[1]&0xffff]
	if x.pending {
		c.PSW.CC = 1
		return
	}
	if x.fc != 0 {
		c.PSW.CC = 2
		return
	}
	// Channel programs use the architectural CCW address. AWSCHAN
	// reads this private SCSW address before running its own CCW interpreter.
	copy(s[:4], orb[:4])
	clear(s[0x1c:0x28])
	s[0x1c] = orb[4] & 0xf0 // storage key
	s[0x1d] = orb[5] & 0xa0 // F: format-1; I: initial status
	copy(s[0x20:0x24], orb[8:12])
	binary.BigEndian.PutUint32(p.Aperture[p390Combuf+0xc:], binary.BigEndian.Uint32(orb[8:]))
	x.fc = fcStart
	p.channelInstruction(c, 0xb233, a)
}

// channelInstruction transfers ownership of COMBUF+10 to AWSINTF. The original
// OS2370I 061e..066b copies opcode +12, operand +14, and subchannel offset +1a
// into the OS/2 channel queue. AWSCHAN SET_CS writes the real reply at +10.
// No native DASD is substituted for that original channel implementation.
func (p *P390) channelInstruction(c *CPU, instruction uint16, operand uint32) {
	p.postChannel(c, instruction, operand, uint16(c.GR[1]))
}

func (p *P390) postChannel(c *CPU, instruction uint16, operand uint32, n uint16) {
	if p.IOPending {
		panic("p390: overlapping channel instruction")
	}
	p.IOPending, p.IOInstruction, p.ioSubchannel = true, instruction, n
	p.IORequests++
	base := p390Combuf + 0x10
	clear(p.Aperture[base : base+16])
	binary.BigEndian.PutUint16(p.Aperture[base+2:], instruction)
	binary.BigEndian.PutUint32(p.Aperture[base+4:], operand)
	binary.BigEndian.PutUint32(p.Aperture[base+8:], 0x00010000|uint32(uint16(0x8000+uint32(n)*64)))
	p.Aperture[0x100] |= 0x10
	p.InterruptPending, p.InterruptReason = true, 1
	c.hitBreak = true
}

// discardCPUAssist cancels the deferred CPU instruction, not the channel's
// architectural activity or the original host's catalogue. CPU reset cannot
// leave an old condition-code rendezvous blocking the reset CPU (AWSIPL's
// preparation barrier), or let its late reply modify the new execution state.
func (p *P390) discardCPUAssist() {
	if !p.IOPending {
		return
	}
	p.IOPending = false
	p.IOInstruction = 0
	p.ioSubchannel = 0
	p.IOAborted++
	clear(p.Aperture[p390Combuf+0x10 : p390Combuf+0x20])
	if p.InterruptReason == 1 {
		p.AcknowledgeInterrupt()
	}
}

func (p *P390) completeChannel() error {
	reply := p.Aperture[p390Combuf+0x10]
	if reply == 0 {
		return nil
	}
	if reply < 0xf0 || reply > 0xf3 {
		p.LastError = fmt.Sprintf("p390: unsupported channel reply %#02x for %04x", reply, p.IOInstruction)
		return fmt.Errorf("%s", p.LastError)
	}
	c := p.Machine.CPUs[0]
	c.PSW.CC = reply & 3
	if reply != 0xf0 && p.IOInstruction == 0xb233 {
		p.interrupts[p.ioSubchannel].fc = 0
	}
	p.IOPending = false
	p.IOCompletions++
	if p.ipl != nil {
		if reply != 0xf0 {
			return p.failIPL(fmt.Sprintf("host rejected IPL start, CC=%d", reply&3))
		}
		p.ipl.accepted = true
		return p.finishIPL()
	}
	p.RunReason = StopReason{Kind: "running"}
	if p.StepCount != 0 && p.StepRemaining == 0 {
		p.finishStep()
	}
	p.publishCPU()
	return nil
}

// completeHostIO consumes the asynchronous mailbox only at the monitor strobe.
// AWSINTF XACMPC (3d60) publishes the subchannel number at +22, SCSW at
// +24..2f, and flags at +21. IOCGO waits for byte +20 to become ff or f3.
func (p *P390) completeHostIO() error {
	packet := p.Aperture[p390Combuf+0x20 : p390Combuf+0x30]
	if packet[0] != 0 || packet[1]&1 == 0 {
		return nil
	}
	n := binary.BigEndian.Uint16(packet[2:])
	if n >= 512 {
		return fmt.Errorf("p390: host status subchannel %04x out of range", n)
	}
	s := p.Aperture[p390Subchannels+uint32(n)*64 : p390Subchannels+(uint32(n)+1)*64]
	if s[5]&0x81 != 0x81 {
		packet[0] = 0xf3
		return nil
	}
	// The host packet carries CC/status control, address and counts. It
	// deliberately omits key and ORB-derived F/I flags (XACMPC 3f01..4042).
	key, flags := s[0x1c]&0xf0, s[0x1d]&0xf8
	copy(s[0x1c:0x28], packet[4:16])
	s[0x1c] = key | (s[0x1c] & 7)
	s[0x1d] = flags | (s[0x1d] & 7)
	x := &p.interrupts[n]
	x.num = n
	x.devno = binary.BigEndian.Uint16(s[6:])
	x.key = key >> 4
	x.ccDeferred = s[0x1c] & 3
	x.ccwaddr = binary.BigEndian.Uint32(s[0x20:])
	x.devStatus, x.schStatus = s[0x24], s[0x25]
	x.residual = binary.BigEndian.Uint16(s[0x26:])
	x.intparm = binary.BigEndian.Uint32(s)
	x.isc = s[4] >> 3 & 7
	x.enabled = true
	w0 := binary.BigEndian.Uint32(s[0x1c:])
	x.fc = byte(w0>>12) & 7
	x.ac = byte(w0>>5) & 0x7f
	x.sc = byte(w0) & 0x1f
	x.pending = packet[7]&1 != 0
	x.irq = x.pending
	p.IOStatusReports++
	packet[0] = 0xff
	if p.ipl != nil && n == p.ipl.subchannel {
		return p.finishIPL()
	}
	return nil
}

func (m *Machine) pendingIO(cr6 uint32) *Subchannel {
	if m.p390 != nil {
		for i := range m.p390.interrupts {
			x := &m.p390.interrupts[i]
			if x.irq && x.pending && x.enabled && cr6&(0x80000000>>x.isc) != 0 {
				return x
			}
		}
		return nil
	}
	return m.CSS.pendingInterrupt(cr6)
}

func (p *P390) testSubchannel(c *CPU, a uint32, b int) {
	c.privileged()
	if a&3 != 0 {
		c.program(pgmSpecification)
	}
	s := p.subchannel(c)
	if s == nil {
		c.PSW.CC = 3
		return
	}
	c.checkStore(a, 64, b)
	var irb [64]byte
	copy(irb[:12], s[0x1c:0x28])
	irb[13] = 0x80
	for i, v := range irb {
		c.storeByte(a+uint32(i), b, v)
	}
	n := c.GR[1] & 0xffff
	x := &p.interrupts[n]
	c.PSW.CC = 1
	if !x.pending {
		return
	}
	c.PSW.CC = 0
	x.pending, x.irq = false, false
	x.fc, x.ac, x.sc = 0, 0, 0
	// Final status clears completed functions; retain the address and counts
	// for subsequent STSCH, exactly as the architectural CSS does.
	clear(s[0x1c:0x20])
}

// Clear/halt/resume are host assists, not calls to native emulated devices.
// AWSCHAN CHNXA dispatches B230/B231 to 5fdf, and B238 to 425f.
func (p *P390) controlSubchannel(c *CPU, instruction uint16) {
	c.privileged()
	s := p.subchannel(c)
	if s == nil || s[5]&0x80 == 0 {
		c.PSW.CC = 3
		return
	}
	x := &p.interrupts[c.GR[1]&0xffff]
	if instruction != 0xb230 && x.pending {
		c.PSW.CC = 1
		return
	}
	if instruction == 0xb238 && x.ac&acSuspended == 0 {
		c.PSW.CC = 2
		return
	}
	p.channelInstruction(c, instruction, 0)
}

func (p *P390) resetChannels() {
	p.interrupts = [512]Subchannel{}
	p.discardCPUAssist()
	// Keep the host's catalogue, OS/2 IOCB pointers and device-map references.
	// Clearing those would detach the original device managers on CPU reset.
	for n := 0; n < 512; n++ {
		s := p.Aperture[p390Subchannels+n*64 : p390Subchannels+(n+1)*64]
		if s[5]&1 == 0 {
			continue
		}
		s[4] = 0
		s[5] &= 3
		s[8] = 0x80
		clear(s[:4])
		clear(s[0x18:0x28])
	}
	clear(p.Aperture[p390Combuf+0x10 : p390Combuf+0x30])
}
