package s390

import (
	"encoding/binary"
	"testing"
)

func p390ServiceTest(t *testing.T, p *P390, command byte) {
	t.Helper()
	if err := p.WriteAperture(p390Mailbox, []byte{0, 0, 0, command}); err != nil {
		t.Fatal(err)
	}
	if err := p.WriteAperture(0x103, []byte{0x60}); err != nil {
		t.Fatal(err)
	}
	if p.Aperture[p390Mailbox] != 0xff {
		t.Fatal("service not completed")
	}
}

func TestP390NormalResetRetainsExecutableStateAndInitialResetRetainsDataBanks(t *testing.T) {
	p, err := NewP390(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	p390ServiceTest(t, p, 2)
	c := p.Machine.CPUs[0]
	// Resume must execute the preserved PSW and GR through the retained prefix,
	// not merely leave the register-dialog copy looking unchanged.
	copy(p.Machine.S.Mem[0x8000:], []byte{0x50, 0x10, 9, 0, 0x82, 0, 9, 0x20})
	binary.BigEndian.PutUint64(p.Machine.S.Mem[0x4920:], 0x000a000000000000)
	c.PSW = PSW{Amode31: true, IA: 0x8000}
	c.Prefix = 0x4000
	c.GR[1], c.AR[9], c.FPR[2] = 0x12345678, 0xaabbccdd, 0x4120000000000000
	c.CR[7], c.FPC, c.ClockComparator = 0x76543000, 0x80000000, 123456
	c.setCPUTimer(987654)
	c.Stopped, c.Check = false, true
	c.extPending, c.emergency = extInterruptKey, 1
	p390ServiceTest(t, p, 2)
	if !c.Stopped || c.Check || c.extPending != 0 || c.emergency != 0 || c.Prefix != 0x4000 || c.PSW.IA != 0x8000 || c.CR[7] != 0x76543000 || c.FPC != 0x80000000 || c.ClockComparator != 123456 || c.timerValue != 987654 {
		t.Fatal("CPU normal reset did not distinguish retained state from pending conditions")
	}
	p390ManualTest(t, p, 0x12)
	p.Advance(100)
	if binary.BigEndian.Uint32(p.Machine.S.Mem[0x4900:]) != 0x12345678 || !c.PSW.Wait || c.Check {
		t.Fatalf("normal reset did not resume preserved executable state: %v", p.RunReason)
	}
	p390ServiceTest(t, p, 6)
	if !c.Stopped || c.Check || c.PSW.IA != 0 || c.PSW.Wait || c.Prefix != 0 || c.FPC != 0 || c.ClockComparator != 0 || c.timerValue != 0 || c.CR[0] != 0xe0 || c.CR[7] != 0 || c.CR[14] != 0xc2000000 {
		t.Fatal("initial reset did not initialize control state")
	}
	if c.GR[1] != 0x12345678 || c.AR[9] != 0xaabbccdd || c.FPR[2] != 0x4120000000000000 || binary.BigEndian.Uint32(p.Machine.S.Mem[0x4900:]) != 0x12345678 {
		t.Fatal("initial reset incorrectly cleared data banks or storage")
	}
	if binary.BigEndian.Uint32(p.Aperture[p390Combuf+0x84:]) != c.GR[1] || binary.BigEndian.Uint32(p.Aperture[p390Mailbox+4:]) != 1<<20-1 {
		t.Fatal("initial-reset response did not publish actual state/storage top")
	}
}

func TestP390ClearResetClearsStorageKeysAndBanksButRetainsHostCatalog(t *testing.T) {
	p, err := NewP390(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	p390ServiceTest(t, p, 2)
	c := p.Machine.CPUs[0]
	p.Machine.S.Mem[0x900] = 0x55
	p.Machine.S.Keys[1] = 0xa8
	c.GR[1], c.AR[2], c.FPR[4] = 123, 456, 789
	c.Prefix, c.Check = 0x4000, true
	// This is an original OS/2 far pointer, not architectural storage.
	binary.LittleEndian.PutUint32(p.Aperture[p390Subchannels+0x30:], 0x12340000)
	p390ServiceTest(t, p, 4)
	p390ServiceTest(t, p, 2)
	p390ManualTest(t, p, 0x24)
	if p.Machine.S.Mem[0x900] != 0 || p.Machine.S.Keys[1] != 0 || c.GR[1] != 0 || c.AR[2] != 0 || c.FPR[4] != 0 || c.Prefix != 0 || c.Check || !c.Stopped {
		t.Fatal("system clear reset acknowledged without clearing architectural state")
	}
	if binary.LittleEndian.Uint32(p.Aperture[p390Subchannels+0x30:]) != 0x12340000 || !p.Initialized {
		t.Fatal("system reset detached original device managers")
	}
	// The overloaded cache-setting form must NOT clear storage/data banks.
	p.Machine.S.Mem[0x900] = 0x77
	c.GR[1] = 29
	p.Aperture[p390Combuf+0x5e] = 0x20
	p.Aperture[p390Combuf+0x5f] = 0x80
	p390ServiceTest(t, p, 4)
	if p.Machine.S.Mem[0x900] != 0x77 || c.GR[1] != 29 || p.CacheMegabytes != 2 {
		t.Fatal("cache configuration took storage-clear form")
	}
}
