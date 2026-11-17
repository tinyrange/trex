package s390

import (
	"encoding/binary"
	"testing"
)

func TestP390InitializeResetsArchitecturalCPU(t *testing.T) {
	p, err := NewP390(32 << 20)
	if err != nil {
		t.Fatal(err)
	}
	c := p.Machine.CPUs[0]
	c.GR[7] = 0x12345678
	c.Stopped = false
	p.Machine.S.Mem[0x800] = 0x55
	if err = p.WriteAperture(p390Mailbox, []byte{0, 0, 0, 2}); err != nil {
		t.Fatal(err)
	}
	if p.Initialized || c.GR[7] == 0 {
		t.Fatal("request executed before start strobe")
	}
	if err = p.WriteAperture(0x103, []byte{0x60}); err != nil {
		t.Fatal(err)
	}
	if !p.Initialized || !c.Stopped || c.GR[7] != 0x12345678 || p.Machine.S.Mem[0x800] != 0x55 {
		t.Fatal("normal reset did not stop CPU while retaining registers/storage")
	}
	if p.Aperture[p390Mailbox] != 0xff || binary.BigEndian.Uint16(p.Aperture[p390Combuf+6:]) != 0x100 {
		t.Fatal("monitor version/completion was not published")
	}
	if err = p.WriteAperture(p390Mailbox, []byte{0, 0, 0, 6}); err != nil {
		t.Fatal(err)
	}
	if err = p.WriteAperture(0x103, []byte{0x60}); err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint32(p.Aperture[p390Mailbox+4:]); got != 32<<20-1 {
		t.Fatalf("storage top=%#x", got)
	}
	if err = p.WriteAperture(p390Mailbox, []byte{0, 0, 0, 0x7f}); err != nil {
		t.Fatal(err)
	}
	if err = p.WriteAperture(0x103, []byte{0x60}); err == nil || p.Aperture[p390Mailbox] != 0 {
		t.Fatal("unknown operation was acknowledged")
	}
}

func TestP390WindowSharesEngineStorageAndInvalidatesCode(t *testing.T) {
	p, err := NewP390(32 << 20)
	if err != nil {
		t.Fatal(err)
	}
	// Program an independent host window; communication area stays private.
	desc := make([]byte, 4)
	binary.LittleEndian.PutUint32(desc, 0x8000)
	if err = p.WriteAperture(0x220, desc); err != nil {
		t.Fatal(err)
	}
	// LHI r1,17; ST r1,0x900; disabled-wait PSW reached via LPSW 0x920.
	program := []byte{0xa7, 0x18, 0, 17, 0x50, 0x10, 0x09, 0, 0x82, 0, 0x09, 0x20}
	if err = p.WriteAperture(0x40000, program); err != nil {
		t.Fatal(err)
	}
	images := []Image{{Address: 0, Data: []byte{0, 8, 0, 0, 0x80, 0, 0x80, 0}}, {Address: 0x920, Data: []byte{0, 0x0a, 0, 0, 0, 0, 0, 0}}}
	if err = p.Machine.Load(images, false); err != nil {
		t.Fatal(err)
	}
	p.Machine.Run(10)
	if got := binary.BigEndian.Uint32(p.Machine.S.Mem[0x900:]); got != 17 {
		t.Fatalf("engine did not execute host-written storage: %d", got)
	}
	// Change the cached instruction through the aperture and execute again.
	if err = p.WriteAperture(0x40002, []byte{0, 29}); err != nil {
		t.Fatal(err)
	}
	if err = p.Machine.Load(images, false); err != nil {
		t.Fatal(err)
	}
	p.Machine.Run(10)
	if got := binary.BigEndian.Uint32(p.Machine.S.Mem[0x900:]); got != 29 {
		t.Fatalf("stale code after external write: %d", got)
	}
	var out [4]byte
	if err = p.ReadAperture(0x40900, out[:]); err != nil {
		t.Fatal(err)
	}
	// This window maps 0x8900, not 0x900: prove remapping changes the view.
	binary.LittleEndian.PutUint32(desc, 0)
	if err = p.WriteAperture(0x220, desc); err != nil {
		t.Fatal(err)
	}
	if err = p.ReadAperture(0x40900, out[:]); err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(out[:]) != 29 {
		t.Fatal("window remap does not observe CPU stores")
	}
	binary.LittleEndian.PutUint32(desc, 0xffffffff)
	if err = p.WriteAperture(0x220, desc); err != nil {
		t.Fatal(err)
	}
	if err = p.ReadAperture(0x40000, out[:]); err == nil {
		t.Fatal("out-of-range window was silently readable")
	}
}

func TestP390ManualStartExecutesAndPublishesArchitecture(t *testing.T) {
	p, err := NewP390(32 << 20)
	if err != nil {
		t.Fatal(err)
	}
	write := func(off uint32, data []byte) {
		t.Helper()
		if err := p.WriteAperture(off, data); err != nil {
			t.Fatal(err)
		}
	}
	write(p390Mailbox, []byte{0, 0, 0, 2})
	write(0x103, []byte{0x60})
	descriptor := make([]byte, 4)
	binary.LittleEndian.PutUint32(descriptor, 0)
	write(0x220, descriptor)
	write(0x48000, []byte{0xa7, 0x18, 0, 17, 0x50, 0x10, 9, 0, 0x82, 0, 9, 0x20})
	write(0x40920, []byte{0, 0x0a, 0, 0, 0, 0, 0, 0})
	write(p390Combuf+8, []byte{0, 8, 0, 0, 0x80, 0, 0x80, 0})
	write(p390Combuf+0x30, []byte{0, 0, 0, 0x12})
	write(0x100, []byte{0, 2})
	if !p.Running() || p.Aperture[p390Combuf+0x63]&4 != 0 {
		t.Fatal("START did not release real CPU")
	}
	p.Advance(100)
	if !p.Running() || !p.Machine.CPUs[0].PSW.Wait || p.Aperture[p390Combuf+0x63]&4 != 0 || p.RunReason.Kind != "disabled-wait" {
		t.Fatalf("wait was confused with an architectural stop: %v", p.RunReason)
	}
	if got := binary.BigEndian.Uint32(p.Machine.S.Mem[0x900:]); got != 17 {
		t.Fatalf("store result=%d", got)
	}
	if got := binary.BigEndian.Uint32(p.Aperture[p390Combuf+0x84:]); got != 17 {
		t.Fatalf("published GPR1=%d", got)
	}
	p.Machine.CPUs[0].Stopped = false
	write(p390Combuf+0x30, []byte{0, 0, 0, 0x14})
	write(0x100, []byte{0, 2})
	if p.Running() || binary.BigEndian.Uint16(p.Aperture[p390Combuf+0x30:]) == 0 {
		t.Fatal("manual STOP did not complete")
	}
}

func TestP390RegisterSnapshotRestartAndReset(t *testing.T) {
	p, err := NewP390(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	write := func(off uint32, b []byte) {
		t.Helper()
		if err := p.WriteAperture(off, b); err != nil {
			t.Fatal(err)
		}
	}
	manual := func(cmd byte) { t.Helper(); write(p390Combuf+0x30, []byte{0, 0, 0, cmd}); write(0x100, []byte{0, 2}) }
	write(p390Mailbox, []byte{0, 0, 0, 2})
	write(0x103, []byte{0x60})
	c := p.Machine.CPUs[0]
	c.GR[5] = 0x12345678
	c.PSW.IA = 0x456
	manual(0x1a)
	if binary.BigEndian.Uint32(p.Aperture[p390Combuf+0x94:]) != c.GR[5] || binary.BigEndian.Uint64(p.Aperture[p390Combuf+0x48:]) != c.PSW.Encode() || p.Aperture[p390Combuf+0x30] != 0xff {
		t.Fatal("register snapshot did not satisfy original driver ABI")
	}
	// Restart interruption saves the old PSW at prefix+8 and loads prefix+0.
	old := c.PSW.Encode()
	binary.BigEndian.PutUint64(p.Machine.S.Mem, 0x0008000080008000)
	copy(p.Machine.S.Mem[0x8000:], []byte{0xa7, 0x18, 0, 29, 0x50, 0x10, 9, 0, 0x82, 0, 9, 0x20})
	binary.BigEndian.PutUint64(p.Machine.S.Mem[0x920:], 0x000a000000000000)
	manual(0x30)
	if c.Stopped || binary.BigEndian.Uint64(p.Machine.S.Mem[8:]) != old {
		t.Fatal("restart did not take architectural interruption")
	}
	p.Advance(10)
	if binary.BigEndian.Uint32(p.Machine.S.Mem[0x900:]) != 29 || p.InterruptPending || p.Aperture[p390Combuf+0x63]&4 != 0 || !c.PSW.Wait {
		t.Fatal("execution/wait state not published, or fabricated host interrupt")
	}
	p.AcknowledgeInterrupt()
	if p.InterruptPending || p.Aperture[0x100]&0x10 != 0 {
		t.Fatal("interrupt acknowledgment did not release latch")
	}
	p.ResetAdapter()
	if p.Initialized || !c.Stopped || binary.BigEndian.Uint32(p.Machine.S.Mem[0x900:]) != 29 {
		t.Fatal("hardware reset did not halt and retain main storage")
	}
	if p.Operations[len(p.Operations)-1].Command != 0x30 {
		t.Fatal("reset destroyed bounded request evidence")
	}
}

func TestP390DirectKeyArraySharesArchitecturalStorageKeys(t *testing.T) {
	p, err := NewP390(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	// LHI r0,A8; L r1,940; SSKE r0,r1; ISKE r2,r1; ST r2,900; LPSW 920.
	program := []byte{0xa7, 8, 0, 0xa8, 0x58, 0x10, 9, 0x40, 0xb2, 0x2b, 0, 1, 0xb2, 0x29, 0, 0x21, 0x50, 0x20, 9, 0, 0x82, 0, 9, 0x20}
	err = p.Machine.Load([]Image{{Address: 0, Data: []byte{0, 8, 0, 0, 0x80, 0, 0x80, 0}}, {Address: 0x8000, Data: program}, {Address: 0x940, Data: []byte{0, 1, 0, 0}}, {Address: 0x920, Data: []byte{0, 0x0a, 0, 0, 0, 0, 0, 0}}}, false)
	if err != nil {
		t.Fatal(err)
	}
	p.Machine.Run(100)
	var key [1]byte
	if err = p.ReadAperture(0x10010, key[:]); err != nil {
		t.Fatal(err)
	}
	if key[0] != 0xa8 || binary.BigEndian.Uint32(p.Machine.S.Mem[0x900:]) != 0xa8 {
		t.Fatal("PCI key view did not observe SSKE/ISKE")
	}
	if err = p.WriteAperture(0x10010, []byte{0x58}); err != nil {
		t.Fatal(err)
	}
	// Execute ISKE again to observe an original-host key change, not merely
	// compare two aliases of a byte slice.
	c := p.Machine.CPUs[0]
	c.Stopped = false
	c.PSW.Wait = false
	c.PSW.IA = 0x800c
	c.next = c.PSW.IA
	c.pswChanged = true
	p.Machine.Run(100)
	if binary.BigEndian.Uint32(p.Machine.S.Mem[0x900:]) != 0x58 {
		t.Fatal("ISKE did not observe PCI key-array write")
	}
}

func TestP390ManualRegisterBankEditAffectsExecution(t *testing.T) {
	p, err := NewP390(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	p.Initialized = true
	err = p.Machine.Load([]Image{{Address: 0, Data: []byte{0, 8, 0, 0, 0x80, 0, 0x80, 0}}, {Address: 0x8000, Data: []byte{0x50, 0x80, 9, 0, 0x82, 0, 9, 0x20}}, {Address: 0x920, Data: []byte{0, 0x0a, 0, 0, 0, 0, 0, 0}}}, false)
	if err != nil {
		t.Fatal(err)
	}
	c := p.Machine.CPUs[0]
	c.Stopped = true
	c.GR[9] = 29
	binary.BigEndian.PutUint32(p.Aperture[p390Combuf+0xa0:], 0x12345678)
	binary.BigEndian.PutUint32(p.Aperture[p390Combuf+0xa4:], 0xffffffff) // bank selection includes R9 as well as R8
	binary.BigEndian.PutUint32(p.Aperture[p390Combuf+0x34:], 1)
	if err = p.WriteAperture(p390Combuf+0x30, []byte{0, 0, 0, 0x18}); err != nil {
		t.Fatal(err)
	}
	if err = p.WriteAperture(0x101, []byte{2}); err != nil {
		t.Fatal(err)
	}
	if c.GR[9] != 0xffffffff || p.Aperture[p390Combuf+0x30] != 0xff {
		t.Fatal("register-bank edit did not load the complete GPR image or acknowledge")
	}
	c.Stopped = false
	p.Advance(10)
	if binary.BigEndian.Uint32(p.Machine.S.Mem[0x900:]) != 0x12345678 {
		t.Fatal("edited register was only a GUI image, not architectural CPU state")
	}
}
