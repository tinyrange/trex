package s390

import (
	"encoding/binary"
	"fmt"
)

// IPL uses the original OS/2 host channel program. Completion of the manual
// request is deferred until the start reply AND terminal device status arrive.
// In particular, neither a successful SSCH reply nor intermediate channel-end
// status is sufficient to start executing the still-unloaded PSW.
type p390IPL struct {
	subchannel uint16
	stop       bool
	accepted   bool
}

func (p *P390) startIPL(clearStorage bool) error {
	c := p.Machine.CPUs[0]
	if !p.Initialized || !c.Stopped || p.IOPending {
		return fmt.Errorf("p390: IPL requires an initialized, stopped, idle CPU")
	}
	arg := binary.BigEndian.Uint32(p.Aperture[p390Combuf+0x34:])
	if arg&0x7fff0000 != 0 {
		return fmt.Errorf("p390: unsupported IPL device argument %08x", arg)
	}
	// The load-parameter facility is not yet implemented. Never silently drop
	// a parameter supplied by MANOPS. Its empty field is eight EBCDIC spaces.
	for _, b := range p.Aperture[p390Combuf+0x38 : p390Combuf+0x40] {
		if b != 0 && b != 0x40 {
			return fmt.Errorf("p390: nonblank IPL load parameter is unsupported")
		}
	}
	dev := uint16(arg)
	found := -1
	for n := 0; n < 512; n++ {
		s := p.Aperture[p390Subchannels+n*64 : p390Subchannels+(n+1)*64]
		if s[5]&1 != 0 && binary.LittleEndian.Uint32(s[0x34:]) != 0xffffffff && binary.BigEndian.Uint16(s[6:]) == dev {
			found = n
			break
		}
	}
	if found < 0 {
		return fmt.Errorf("p390: IPL device %04x is not installed", dev)
	}
	c.Reset(clearStorage)
	if clearStorage {
		clear(p.Machine.S.Mem)
		clear(p.Machine.S.Keys)
	}
	p.Machine.CSS.reset()
	p.resetChannels()
	// The initial format-0 READ transfers 24 bytes to absolute zero, replacing
	// this CCW itself with the IPL PSW and the next two CCWs before chaining.
	binary.BigEndian.PutUint64(p.Machine.S.Mem, 0x0200000060000018)
	p.Machine.S.Keys[0] |= 6 // reference and change
	s := p.Aperture[p390Subchannels+found*64 : p390Subchannels+(found+1)*64]
	s[5] |= 0x80 // IPL enables the selected subchannel in subclass zero.
	p.interrupts[found] = Subchannel{num: uint16(found), enabled: true, fc: fcStart}
	binary.BigEndian.PutUint16(p.Aperture[p390Combuf+0x30:], 0)
	p.ipl = &p390IPL{subchannel: uint16(found), stop: arg&0x80000000 != 0}
	p.StepRemaining = uint64(p.StepCount)
	p.RunReason = StopReason{Kind: "ipl-host-io"}
	// No synthetic ESA instruction or register change is needed to submit the
	// implied SSCH. AWSCHAN reads CAW at COMBUF+0c and the private SCSW at +20.
	binary.BigEndian.PutUint32(p.Aperture[p390Combuf+0xc:], 0)
	p.postChannel(c, 0xb233, 0, uint16(found))
	p.publishCPU()
	return nil
}

func (p *P390) failIPL(reason string) error {
	p.Machine.CPUs[0].Stopped = true
	p.RunReason = StopReason{Kind: "ipl-failed"}
	p.LastError = "p390: IPL failed: " + reason
	p.ipl = nil
	p.publishCPU()
	return fmt.Errorf("%s", p.LastError)
}

func (p *P390) finishIPL() error {
	load := p.ipl
	if load == nil || !load.accepted {
		return nil
	}
	x := &p.interrupts[load.subchannel]
	if !x.pending {
		return nil
	}
	s := p.Aperture[p390Subchannels+int(load.subchannel)*64 : p390Subchannels+(int(load.subchannel)+1)*64]
	// The host can accept SSCH synchronously, then report deferred CC3
	// (for example a catalogued device not claimed by its manager). This
	// is a failed start, not an endless zero-status IPL.
	if cc := s[0x1c] & 3; cc != 0 {
		return p.failIPL(fmt.Sprintf("deferred subchannel condition code %d", cc))
	}
	// Intermediate/channel-end-only status is not a completed IPL.
	if s[0x24]&0x04 == 0 && s[0x24]&0xf3 == 0 && s[0x25] == 0 {
		x.pending, x.irq = false, false
		return nil
	}
	if s[0x24] != 0x0c || s[0x25] != 0 {
		return p.failIPL(fmt.Sprintf("device status %02x, channel status %02x", s[0x24], s[0x25]))
	}
	c := p.Machine.CPUs[0]
	psw := binary.BigEndian.Uint64(c.S.Mem)
	if _, ok := c.decodePSW(psw); !ok {
		return p.failIPL(fmt.Sprintf("invalid loaded PSW %016x", psw))
	}
	if p.Machine.S370 {
		devno := binary.BigEndian.Uint16(s[6:])
		if c.S.Mem[1]&8 == 0 {
			binary.BigEndian.PutUint16(c.S.Mem[2:], devno)
			psw = binary.BigEndian.Uint64(c.S.Mem)
		} else {
			binary.BigEndian.PutUint32(c.S.Mem[0xb8:], uint32(devno))
		}
	} else {
		binary.BigEndian.PutUint32(c.S.Mem[0xb8:], 0x00010000|uint32(load.subchannel))
		binary.BigEndian.PutUint32(c.S.Mem[0xbc:], 0)
	}
	c.loadPSW(psw)
	c.next, c.pswChanged = c.PSW.IA, true
	c.hitBreak = false // host submission did not originate in CPU execution
	c.Stopped = load.stop
	c.purgeTLB()
	x.pending, x.irq = false, false
	x.fc, x.ac, x.sc = 0, 0, 0
	clear(s[0x1c:0x20])
	s[10] = 0x80 // last path used (LPUM), not path-not-operational mask
	p.ipl = nil
	p.RunReason = StopReason{Kind: "running"}
	if c.Stopped {
		p.RunReason.Kind = "stopped"
	}
	p.publishCPU()
	binary.BigEndian.PutUint16(p.Aperture[p390Combuf+0x30:], 0xff00)
	return nil
}
