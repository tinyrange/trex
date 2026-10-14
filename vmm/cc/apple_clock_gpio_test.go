package cc

import "testing"

func TestAppleClocksUseSuppliedCounter(t *testing.T) {
	ticks := uint64(1000)
	clock := func() (uint64, uint64, error) { return ticks, 100, nil }
	rtc := pl031{address: 0x20050000, clock: clock, start: ticks, value: 100, last: 100, control: 1}
	if e := rtc.Write(0x20050004, 4, 102); e != nil {
		t.Fatal(e)
	}
	ticks += 350
	if v, e := rtc.Read(0x20050000, 4); e != nil || v != 103 {
		t.Fatal(v, e)
	}
	if v, _ := rtc.Read(0x20050014, 4); v != 1 {
		t.Fatal("skipped alarm match")
	}
	if v, _ := rtc.Read(0x20050018, 4); v != 0 {
		t.Fatal("masked alarm delivered")
	}
	rtc.Write(0x20050010, 4, 1)
	if v, _ := rtc.Read(0x20050018, 4); v != 1 {
		t.Fatal("alarm mask")
	}
	rtc.Write(0x2005001c, 4, 1)
	if v, _ := rtc.Read(0x20050014, 4); v != 0 {
		t.Fatal("clear alarm")
	}
	rtc.Write(0x2005000c, 4, 0)
	ticks += 500
	if v, _ := rtc.Read(0x20050000, 4); v != 103 {
		t.Fatal("stopped RTC advanced")
	}
	avp := avpRTC{address: 0x30240000, clock: clock, start: ticks, epoch: 1000000}
	ticks += 125
	if v, e := avp.Read(0x30240000, 8); e != nil || v != 2250000 {
		t.Fatal(v, e)
	}
	if e := avp.Write(0x30240020, 8, 6); e != nil {
		t.Fatal(e)
	}
	if v, _ := avp.Read(0x30240030, 8); v != 0 {
		t.Fatal("invented host clock change")
	}
}
func TestPL061MaskedGPIOAndRawInterrupt(t *testing.T) {
	d := pl061{address: 0x20060000}
	d.Write(0x20060400, 1, 1)
	d.Write(0x20060004, 1, 0xff)
	if v, _ := d.Read(0x200603fc, 1); v != 1 {
		t.Fatal("masked output")
	}
	if v, _ := d.Read(0x20060008, 4); v != 0 {
		t.Fatal("data mask")
	}
	d.Write(0x20060400, 1, 0)
	if v, _ := d.Read(0x200603fc, 1); v != 0 {
		t.Fatal("input stayed latched")
	}
	d.Write(0x20060404, 1, 2)
	if v, _ := d.Read(0x20060414, 1); v != 2 {
		t.Fatal("raw status masked")
	}
	if v, _ := d.Read(0x20060418, 1); v != 0 {
		t.Fatal("masked status")
	}
	d.Write(0x20060410, 1, 2)
	if v, _ := d.Read(0x20060418, 1); v != 2 {
		t.Fatal("unmasked low-level input")
	}
}
