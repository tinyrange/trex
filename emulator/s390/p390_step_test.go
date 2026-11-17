package s390

import (
	"encoding/binary"
	"testing"
)

func p390ManualTest(t *testing.T, p *P390, command byte) {
	t.Helper()
	if err := p.WriteAperture(p390Combuf+0x30, []byte{0, 0, 0, command}); err != nil {
		t.Fatal(err)
	}
	if err := p.WriteAperture(0x101, []byte{2}); err != nil {
		t.Fatal(err)
	}
}

func TestP390InstructionStepStopsAtActualInstructionBoundary(t *testing.T) {
	p, err := NewP390(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	p.Initialized = true
	if err = p.Machine.Load([]Image{
		{Address: 0, Data: []byte{0, 8, 0, 0, 0x80, 0, 0x80, 0}},
		{Address: 0x8000, Data: []byte{0xa7, 0x18, 0, 17, 0x50, 0x10, 9, 0, 0xa7, 0x18, 0, 29, 0x50, 0x10, 9, 4, 0x82, 0, 9, 0x20}},
		{Address: 0x920, Data: []byte{0, 0x0a, 0, 0, 0, 0, 0, 0}},
	}, false); err != nil {
		t.Fatal(err)
	}
	c := p.Machine.CPUs[0]
	c.Stopped = true
	p.publishCPU()
	binary.BigEndian.PutUint32(p.Aperture[p390Combuf+0x34:], 1)
	p390ManualTest(t, p, 6)
	p390ManualTest(t, p, 0x12)
	p.Advance(50000)
	if c.Instructions != 1 || c.GR[1] != 17 || c.PSW.IA != 0x8004 || !c.Stopped || !p.InterruptPending || p.RunReason.Kind != "instruction-step" {
		t.Fatalf("first instruction did not stop precisely: %+v PC=%x count=%d", p.RunReason, c.PSW.IA, c.Instructions)
	}
	if binary.BigEndian.Uint32(p.Machine.S.Mem[0x900:]) != 0 || binary.BigEndian.Uint16(p.Aperture[p390Combuf+0x12:]) != 0x406 || p.IORequests != 0 {
		t.Fatal("step executed the following store or fabricated channel I/O")
	}
	p.AcknowledgeInterrupt()
	p390ManualTest(t, p, 0x12)
	p.Advance(50000)
	if c.Instructions != 2 || binary.BigEndian.Uint32(p.Machine.S.Mem[0x900:]) != 17 || c.PSW.IA != 0x8008 || !c.Stopped {
		t.Fatal("second step did not resume at saved architectural PSW")
	}
	p.AcknowledgeInterrupt()
	p390ManualTest(t, p, 8)
	p390ManualTest(t, p, 0x12)
	p.Advance(50000)
	if binary.BigEndian.Uint32(p.Machine.S.Mem[0x904:]) != 29 || c.Stopped || !c.PSW.Wait || p.InterruptPending || p.Aperture[p390Combuf+0x61]&1 != 0 || p.RunReason.Kind != "disabled-wait" {
		t.Fatalf("step reset did not restore continuous execution: %+v", p.RunReason)
	}
}

func TestP390SteppedSSCHWaitsForHostConditionCodeBeforeStop(t *testing.T) {
	p, err := NewP390(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	p.Initialized = true
	p.Aperture[p390Subchannels+5] = 0x83
	if err = p.Machine.Load([]Image{{Address: 0, Data: []byte{0, 8, 0, 0, 0x80, 0, 0x80, 0}}, {Address: 0x8000, Data: []byte{0xb2, 0x33, 9, 0x50, 0xa7, 0x28, 0, 17}}}, false); err != nil {
		t.Fatal(err)
	}
	c := p.Machine.CPUs[0]
	c.GR[1] = 0x10000
	c.Stopped = true
	p.publishCPU()
	binary.BigEndian.PutUint32(p.Aperture[p390Combuf+0x34:], 1)
	p390ManualTest(t, p, 6)
	p390ManualTest(t, p, 0x12)
	p.Advance(50000)
	if !p.IOPending || c.Stopped || p.StepRemaining != 0 || binary.BigEndian.Uint16(p.Aperture[p390Combuf+0x12:]) != 0xb233 {
		t.Fatal("step overwrote outstanding SSCH before original host reply")
	}
	p.AcknowledgeInterrupt()
	if err = p.WriteAperture(p390Combuf+0x10, []byte{0xf3}); err != nil {
		t.Fatal(err)
	}
	p.Advance(50000)
	if !p.IOPending || c.Stopped {
		t.Fatal("reply-byte write completed SSCH without strobe")
	}
	if err = p.WriteAperture(0x101, []byte{4}); err != nil {
		t.Fatal(err)
	}
	if p.IOPending || !c.Stopped || c.PSW.CC != 3 || c.Instructions != 1 || !p.InterruptPending || binary.BigEndian.Uint16(p.Aperture[p390Combuf+0x12:]) != 0x406 || p.IOCompletions != 1 {
		t.Fatal("host completion did not stop with actual CC before following instruction")
	}
}
