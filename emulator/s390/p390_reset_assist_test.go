package s390

import "testing"

func TestP390CPUResetAbortsDeferredInstructionNotChannelState(t *testing.T) {
	for _, tt := range []struct {
		name            string
		service, option byte
	}{
		{"normal", 2, 0}, {"initial", 6, 0}, {"clear", 4, 0}, {"cache-reset", 4, 0x80},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := newP390370Test(t)
			c := p.Machine.CPUs[0]
			s := p.Aperture[p390Subchannels+128 : p390Subchannels+192]
			copy(s[0x30:0x34], []byte{0, 0, 0x34, 0x12})
			// Real SIO stops at its original-host assist, with no supplied host reply.
			copy(c.S.Mem[0x8000:], []byte{0x9c, 0, 0, 9})
			be.PutUint32(c.S.Mem[0x48:], 0x3000)
			c.loadPSW(0x0008000000008000)
			c.Stopped = false
			p.Advance(10)
			if !p.IOPending || p.IORequests != 1 || p.IOCompletions != 0 {
				t.Fatal("no deferred SIO to reset")
			}
			beforeFC := p.interrupts[2].fc
			p.Aperture[p390Combuf+0x5f] = tt.option
			p390ServiceTest(t, p, tt.service)
			if p.IOPending || p.IOInstruction != 0 || p.IOAborted != 1 || p.IOCompletions != 0 || !c.Stopped || p.InterruptPending {
				t.Fatal("reset retained assist ownership or fabricated completion")
			}
			if p.interrupts[2].fc != beforeFC || s[5]&3 != 3 || string(s[0x30:0x34]) != string([]byte{0, 0, 0x34, 0x12}) {
				t.Fatal("CPU reset became a channel/catalog reset")
			}
			// A late reply must not commit its CC into the reset CPU.
			psw := c.PSW.Encode()
			if err := p.WriteAperture(p390Combuf+0x10, []byte{0xf3}); err != nil {
				t.Fatal(err)
			}
			if err := p.WriteAperture(0x101, []byte{4}); err != nil {
				t.Fatal(err)
			}
			if c.PSW.Encode() != psw || p.IOCompletions != 0 {
				t.Fatal("old host reply altered reset execution state")
			}
			// This is the original AWSIPL sequence that previously deadlocked: 22
			// must see an idle reset CPU, then explicit 24 resets channel activity.
			p390ManualTest(t, p, 0x22)
			p390ManualTest(t, p, 0x24)
			copy(c.S.Mem[0x8000:], []byte{0x9c, 0, 0, 9, 0x50, 0x10, 9, 0, 0x82, 0, 9, 0x20})
			be.PutUint32(c.S.Mem[0x48:], 0x3000)
			be.PutUint64(c.S.Mem[0x920:], 0x000a000000000000)
			c.GR[1] = 0x12345678
			c.loadPSW(0x0008000000008000)
			c.Stopped = false
			p.Advance(10)
			if !p.IOPending || p.IORequests != 2 || be.Uint32(c.S.Mem[0x900:]) != 0 {
				t.Fatal("fresh SIO did not wait for its own reply")
			}
			if err := p.WriteAperture(p390Combuf+0x10, []byte{0xf0}); err != nil {
				t.Fatal(err)
			}
			if err := p.WriteAperture(0x101, []byte{4}); err != nil {
				t.Fatal(err)
			}
			p.Advance(20)
			if be.Uint32(c.S.Mem[0x900:]) != 0x12345678 || p.IOCompletions != 1 || p.IOAborted != 1 || !c.PSW.Wait {
				t.Fatal("fresh execution did not resume independently of the canceled assist")
			}
		})
	}
}
