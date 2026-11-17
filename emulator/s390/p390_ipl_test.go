package s390

import (
	"encoding/binary"
	"testing"
)

func newIPLTest(t *testing.T, command byte, stop bool) *P390 {
	t.Helper()
	p, err := NewP390(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	p.Initialized = true
	c := p.Machine.CPUs[0]
	c.Stopped = true
	c.GR[1] = 0x12345678 // device selection must not use or change R1
	c.AR[2], c.FPR[6] = 17, 0x1122334455667788
	c.Prefix, c.CR[7] = 0x4000, 0x12345000
	p.Machine.S.Mem[0x9000] = 0x5a
	p.Machine.S.Keys[9] = 0xa8
	s := p.Aperture[p390Subchannels+3*64 : p390Subchannels+4*64]
	s[5] = 3 // installed but disabled: IPL must enable it
	binary.BigEndian.PutUint16(s[6:], 0x123)
	p.Aperture[p390Combuf+0x33] = command
	arg := uint32(0x123)
	if stop {
		arg |= 0x80000000
	}
	binary.BigEndian.PutUint32(p.Aperture[p390Combuf+0x34:], arg)
	if err := p.manual(); err != nil {
		t.Fatal(err)
	}
	return p
}

func iplStatus(t *testing.T, p *P390, dev, channel byte) error {
	t.Helper()
	packet := []byte{0, 1, 0, 3, 0, 0, 0, 7, 0, 0, 0, 16, dev, channel, 0, 0}
	if err := p.WriteAperture(p390Combuf+0x20, packet); err != nil {
		t.Fatal(err)
	}
	return p.WriteAperture(0x101, []byte{4})
}

func iplAccept(t *testing.T, p *P390) error {
	t.Helper()
	p.AcknowledgeInterrupt()
	if err := p.WriteAperture(p390Combuf+0x10, []byte{0xf0}); err != nil {
		t.Fatal(err)
	}
	return p.WriteAperture(0x101, []byte{4})
}

func TestP390IPLWaitsForHostAndExecutesLoadedProgram(t *testing.T) {
	for _, clearStorage := range []bool{false, true} {
		for _, stop := range []bool{false, true} {
			command := byte(0x20)
			if clearStorage {
				command = 0x21
			}
			p := newIPLTest(t, command, stop)
			c := p.Machine.CPUs[0]
			if !c.Stopped || p.Running() || p.Aperture[p390Combuf+0x30] != 0 || !p.IOPending || binary.BigEndian.Uint64(c.S.Mem) != 0x0200000060000018 || binary.BigEndian.Uint32(p.Aperture[p390Combuf+0x18:]) != 0x000180c0 {
				t.Fatal("IPL did not submit the implied READ through the original host")
			}
			if c.Prefix != 0 || c.CR[7] != 0 {
				t.Fatal("IPL did not initial-reset the CPU")
			}
			if clearStorage {
				if c.GR[1] != 0 || c.AR[2] != 0 || c.FPR[6] != 0 || c.S.Mem[0x9000] != 0 || c.S.Keys[9] != 0 {
					t.Fatal("clear IPL retained state")
				}
			} else if c.GR[1] != 0x12345678 || c.AR[2] != 17 || c.FPR[6] != 0x1122334455667788 || c.S.Mem[0x9000] != 0x5a || c.S.Keys[9] != 0xa8 {
				t.Fatal("normal IPL cleared state")
			}
			if err := iplAccept(t, p); err != nil {
				t.Fatal(err)
			}
			p.Advance(100)
			if !c.Stopped || p.ipl == nil || c.Instructions != 0 || p.Aperture[p390Combuf+0x30] != 0 {
				t.Fatal("SSCH acceptance prematurely completed IPL")
			}
			if err := iplStatus(t, p, 8, 0); err != nil {
				t.Fatal(err)
			}
			if p.ipl == nil || !c.Stopped {
				t.Fatal("channel-end-only status completed IPL")
			}
			// Model only the host boundary: OS/2 has now placed the boot record/code.
			// The integration smoke must obtain these bytes from real AWSCHAN/AWSXAMP.
			binary.BigEndian.PutUint64(c.S.Mem, 0x0008000080008000)
			copy(c.S.Mem[0x8000:], []byte{0xa7, 0x28, 0, 17, 0x50, 0x20, 9, 0, 0x82, 0, 9, 0x20})
			binary.BigEndian.PutUint64(c.S.Mem[0x920:], 0x000a000000000000)
			if err := iplStatus(t, p, 0x0c, 0); err != nil {
				t.Fatal(err)
			}
			if p.ipl != nil || p.IOPending || p.Aperture[p390Combuf+0x30] != 0xff || c.Stopped != stop || p.interrupts[3].pending || p.Aperture[p390Subchannels+3*64+9] != 0 || p.Aperture[p390Subchannels+3*64+10] != 0x80 || binary.BigEndian.Uint32(c.S.Mem[0xb8:]) != 0x10003 || binary.BigEndian.Uint32(c.S.Mem[0xbc:]) != 0 {
				t.Fatal("terminal completion did not load PSW/device identity")
			}
			p.Advance(30)
			if stop {
				if c.Instructions != 0 {
					t.Fatal("Stop Yes executed IPL program")
				}
				p.Aperture[p390Combuf+0x33] = 0x12
				if err := p.manual(); err != nil {
					t.Fatal(err)
				}
				p.Advance(30)
			}
			if binary.BigEndian.Uint32(c.S.Mem[0x900:]) != 17 || p.RunReason.Kind != "disabled-wait" || c.Check {
				t.Fatalf("loaded program did not run: %v", p.RunReason)
			}
		}
	}
}

func TestP390IPLStatusBeforeStartReplyAndFailure(t *testing.T) {
	p := newIPLTest(t, 0x20, false)
	binary.BigEndian.PutUint64(p.Machine.S.Mem, 0x000a000000000000)
	if err := iplStatus(t, p, 0x0c, 0); err != nil {
		t.Fatal(err)
	}
	if p.ipl == nil || !p.IOPending || p.Aperture[p390Combuf+0x30] != 0 {
		t.Fatal("status bypassed start reply")
	}
	if err := iplAccept(t, p); err != nil || p.ipl != nil {
		t.Fatal("out-of-order completion lost", err)
	}
	for _, mode := range []string{"unit-check", "channel-check", "invalid-psw", "rejected-start"} {
		t.Run(mode, func(t *testing.T) {
			p := newIPLTest(t, 0x20, false)
			if mode == "rejected-start" {
				p.Aperture[p390Combuf+0x10] = 0xf3
				if err := p.WriteAperture(0x101, []byte{4}); err == nil {
					t.Fatal("rejected start succeeded")
				}
			} else {
				if err := iplAccept(t, p); err != nil {
					t.Fatal(err)
				}
				dev, channel := byte(0x0c), byte(0)
				binary.BigEndian.PutUint64(p.Machine.S.Mem, 0x000a000000000000)
				switch mode {
				case "unit-check":
					dev = 0x0e
				case "channel-check":
					channel = 0x20
				case "invalid-psw":
					binary.BigEndian.PutUint64(p.Machine.S.Mem, 0xffffffffffffffff)
				}
				if err := iplStatus(t, p, dev, channel); err == nil {
					t.Fatal("bad load succeeded")
				}
			}
			if !p.Machine.CPUs[0].Stopped || p.Aperture[p390Combuf+0x30] != 0 || p.LastError == "" || p.RunReason.Kind != "ipl-failed" {
				t.Fatal("failed IPL acknowledged or ran")
			}
		})
	}
}

func TestP390IPLRejectsUnknownDeviceAndLoadParameterBeforeMutation(t *testing.T) {
	p, _ := NewP390(1 << 20)
	p.Initialized = true
	c := p.Machine.CPUs[0]
	c.Stopped = true
	c.GR[7] = 123
	p.Aperture[p390Combuf+0x33] = 0x21
	if err := p.manual(); err == nil {
		t.Fatal("missing IPL device succeeded")
	}
	if p.IORequests != 0 || c.GR[7] != 123 {
		t.Fatal("bad IPL modified state")
	}
	p.Aperture[p390Combuf+0x38] = 0xc1
	if err := p.manual(); err == nil {
		t.Fatal("nonblank load parameter silently ignored")
	}
}

func TestP390IPLDeferredUnavailableDoesNotWaitForever(t *testing.T) {
	p := newIPLTest(t, 0x20, false)
	if err := iplAccept(t, p); err != nil {
		t.Fatal(err)
	}
	// Actual original AWSCHAN unavailable-manager status: CC3, alert/final
	// status, CCW address 8, untouched 24-byte read count, no device/channel
	// status. Successful synchronous SSCH acceptance does not supersede it.
	packet := []byte{0, 1, 0, 3, 3, 0, 0xff, 7, 0, 0, 0, 8, 0, 0, 0, 24}
	if err := p.WriteAperture(p390Combuf+0x20, packet); err != nil {
		t.Fatal(err)
	}
	if err := p.WriteAperture(0x101, []byte{4}); err == nil {
		t.Fatal("deferred CC3 did not fail IPL")
	}
	if p.ipl != nil || !p.Machine.CPUs[0].Stopped || p.RunReason.Kind != "ipl-failed" || p.Aperture[p390Combuf+0x30] != 0 || p.LastError == "" {
		t.Fatal("deferred unavailable device remained pending or reported success")
	}
}
