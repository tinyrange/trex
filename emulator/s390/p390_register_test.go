package s390

import (
	"encoding/binary"
	"testing"
)

// Every bank is consumed by a real ESA instruction. This catches a GUI-only
// mailbox image, a mistaken FPR word/doubleword mapping, and a PSW edit that
// changes the display but leaves the engine's execution address unchanged.
func TestP390MonitorRegisterBanksExecute(t *testing.T) {
	p, err := NewP390(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	p.Initialized = true
	program := []byte{
		0x50, 0x80, 0x09, 0x00, // ST R8,900
		0x60, 0x00, 0x09, 0x08, // STD F0,908
		0x60, 0x20, 0x09, 0x10, // STD F2,910
		0xb6, 0x0f, 0x0a, 0x00, // STCTL C0-C15,A00
		0x9b, 0x0f, 0x0a, 0x40, // STAM A0-A15,A40
		0xb2, 0x11, 0x0a, 0x80, // STPX A80
		0x82, 0x00, 0x09, 0x20, // LPSW disabled wait
	}
	if err = p.Machine.Load([]Image{{Address: 0, Data: []byte{0, 8, 0, 0, 0x80, 0, 0x70, 0}}, {Address: 0x8000, Data: program}, {Address: 0x4920, Data: []byte{0, 0x0a, 0, 0, 0, 0, 0, 0}}}, false); err != nil {
		t.Fatal(err)
	}
	c := p.Machine.CPUs[0]
	c.Stopped = true
	c.PSW.IA = 0x7000     // execution must use the committed PSW, not this address
	c.FPR[1] = 0xfeedface // not part of the legacy monitor's four HFP registers
	for r := 0; r < 16; r++ {
		binary.BigEndian.PutUint32(p.Aperture[p390Combuf+0x80+r*4:], uint32(0x100+r))
		binary.BigEndian.PutUint32(p.Aperture[p390Combuf+0xc0+r*4:], uint32(0x200+r))
		binary.BigEndian.PutUint32(p.Aperture[p390Combuf+0x100+r*4:], uint32(0x300+r))
	}
	binary.BigEndian.PutUint64(p.Aperture[p390Combuf+0x180:], 0x41123456789abcde)
	binary.BigEndian.PutUint64(p.Aperture[p390Combuf+0x188:], 0x4223456789abcdef)
	binary.BigEndian.PutUint32(p.Aperture[p390Combuf+0x34:], 0x403f)
	binary.BigEndian.PutUint64(p.Aperture[p390Combuf+0x38:], 0x0008000080008000)
	if err = p.WriteAperture(p390Combuf+0x30, []byte{0, 0, 0, 0x18}); err != nil {
		t.Fatal(err)
	}
	if err = p.WriteAperture(0x101, []byte{2}); err != nil {
		t.Fatal(err)
	}
	if !c.Stopped || c.FPR[1] != 0xfeedface {
		t.Fatal("edit resumed CPU or changed an unrepresented FP register")
	}
	c.Stopped = false
	p.Advance(100)
	mem := p.Machine.S.Mem[0x4000:] // prefix relocates all low-page operands
	if got := binary.BigEndian.Uint32(mem[0x900:]); got != 0x108 {
		t.Fatalf("GR store: %x reason=%+v psw=%v check=%v", got, p.RunReason, c.PSW, c.Check)
	}
	if got := binary.BigEndian.Uint64(mem[0x908:]); got != 0x41123456789abcde {
		t.Fatalf("FP0 store: %x", got)
	}
	if got := binary.BigEndian.Uint64(mem[0x910:]); got != 0x4223456789abcdef {
		t.Fatalf("FP2 store: %x", got)
	}
	for r := 0; r < 16; r++ {
		if got := binary.BigEndian.Uint32(mem[0xa00+r*4:]); got != uint32(0x200+r) {
			t.Fatalf("CR%d store: %x", r, got)
		}
		if got := binary.BigEndian.Uint32(mem[0xa40+r*4:]); got != uint32(0x300+r) {
			t.Fatalf("AR%d store: %x", r, got)
		}
	}
	if got := binary.BigEndian.Uint32(mem[0xa80:]); got != 0x4000 {
		t.Fatalf("prefix store: %x", got)
	}
	if c.Stopped || !c.PSW.Wait || c.Check {
		t.Fatalf("execution failed: %+v", p.RunReason)
	}
	// Snapshot must reflect actual CPU changes, not the old commit parameters.
	c.CR[7], c.AR[9], c.FPR[6] = 0x777, 0x999, 0x433456789abcdef0
	if err = p.WriteAperture(p390Combuf+0x30, []byte{0, 0, 0, 0x1a}); err != nil {
		t.Fatal(err)
	}
	if err = p.WriteAperture(0x101, []byte{2}); err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(p.Aperture[p390Combuf+0xdc:]) != 0x777 || binary.BigEndian.Uint32(p.Aperture[p390Combuf+0x124:]) != 0x999 || binary.BigEndian.Uint64(p.Aperture[p390Combuf+0x198:]) != c.FPR[6] {
		t.Fatal("snapshot did not publish live register banks")
	}
}

func TestP390MonitorRegisterEditRejectsAtomically(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mask    uint32
		psw     uint64
		running bool
	}{
		{"invalid PSW", 9, 0, false},
		{"invalid prefix", 0x100011, 0, false},
		{"unknown bank", 0x41, 0, false},
		{"unselected PSW", 1, 0x0008000080008000, false},
		{"running", 1, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewP390(1 << 20)
			if err != nil {
				t.Fatal(err)
			}
			c := p.Machine.CPUs[0]
			c.Stopped = !tc.running
			c.GR[8] = 123
			binary.BigEndian.PutUint32(p.Aperture[p390Combuf+0xa0:], 456)
			binary.BigEndian.PutUint32(p.Aperture[p390Combuf+0x34:], tc.mask)
			binary.BigEndian.PutUint64(p.Aperture[p390Combuf+0x38:], tc.psw)
			if err = p.WriteAperture(p390Combuf+0x30, []byte{0, 0, 0, 0x18}); err != nil {
				t.Fatal(err)
			}
			if err = p.WriteAperture(0x101, []byte{2}); err == nil {
				t.Fatal("invalid edit accepted")
			}
			if c.GR[8] != 123 || p.Aperture[p390Combuf+0x30] != 0 {
				t.Fatal("failed edit partially committed or acknowledged")
			}
		})
	}
}

func TestP390OperatorExternalInterruptUsesArchitecturalMasking(t *testing.T) {
	p, err := NewP390(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	p.Initialized = true
	// A masked enabled-wait PSW must not execute the handler yet. Only the
	// operator interrupt-key subclass is enabled, excluding timer conditions.
	if err = p.Machine.Load([]Image{
		{Address: 0, Data: []byte{0, 0x0a, 0, 0, 0, 0, 0, 0}},
		{Address: 0x58, Data: []byte{0, 8, 0, 0, 0x80, 0, 0x80, 0}},
		{Address: 0x8000, Data: []byte{0xa7, 0x18, 0, 17, 0x50, 0x10, 9, 0, 0x82, 0, 9, 0x20}},
		{Address: 0x920, Data: []byte{0, 0x0a, 0, 0, 0, 0, 0, 0}},
	}, false); err != nil {
		t.Fatal(err)
	}
	c := p.Machine.CPUs[0]
	c.CR[0] = 0x40
	c.Stopped = true
	if err = p.WriteAperture(0x101, []byte{1}); err != nil {
		t.Fatal(err)
	}
	if c.extPending&extInterruptKey == 0 || !c.Stopped || p.InterruptPending || p.Aperture[0x101]&1 != 0 {
		t.Fatal("operator strobe did not queue an independent architectural condition")
	}
	c.Stopped = false
	p.Machine.Run(10)
	if c.extPending&extInterruptKey == 0 || binary.BigEndian.Uint32(p.Machine.S.Mem[0x900:]) != 0 {
		t.Fatal("PSW mask did not defer operator interrupt")
	}
	c.PSW.Ext = true
	c.CR[0] = 0
	p.Machine.Run(10)
	if c.extPending&extInterruptKey == 0 {
		t.Fatal("CR0 mask did not defer operator interrupt")
	}
	c.CR[0] = 0x40
	p.Advance(20)
	if c.Check || binary.BigEndian.Uint32(p.Machine.S.Mem[0x900:]) != 17 || binary.BigEndian.Uint16(p.Machine.S.Mem[0x86:]) != 0x40 || c.extPending&extInterruptKey != 0 {
		t.Fatalf("operator interrupt did not execute actual handler: %+v", p.RunReason)
	}
	if p.IORequests != 0 || p.InterruptPending {
		t.Fatal("operator interrupt fabricated an OS/2 host instruction")
	}
}
