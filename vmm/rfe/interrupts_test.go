package rfe

import (
	"context"
	"testing"
	"time"
)

func TestPICSpecialMaskAllowsPriorityBelowMaskedInServiceIRQ(t *testing.T) {
	p := pic{mask: 1, isr: 1, irr: 2}
	if p.pending() != 8 {
		t.Fatal("normal fully nested mode ignored ISR priority")
	}
	p.out(false, 0x68)
	if p.pending() != 1 {
		t.Fatal("special mask did not remove masked ISR from priority")
	}
	p.out(false, 0x48)
	if p.pending() != 8 {
		t.Fatal("special mask disable failed")
	}
	p.readISR, p.autoEOI, p.specialMask = true, true, true
	p.out(false, 0x11)
	if p.readISR || p.autoEOI || p.specialMask || p.irr != 0 || p.isr != 0 {
		t.Fatal("ICW1 retained old operational state")
	}
}
func TestPITLatchCannotBeOverwrittenHalfwayThroughRead(t *testing.T) {
	raw, err := newCPU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c := raw.(*cpu)
	defer c.Close()
	c.deviceOut(0x43, 0x34)
	c.deviceOut(0x40, 0x34)
	c.deviceOut(0x40, 0x12)
	c.pit.readPhase = 1 // An independent unlatched read was halfway complete.
	c.deviceOut(0x43, 0)
	latched := c.pit.latch
	lo, _ := c.deviceIn(0x40)
	c.deviceOut(0x43, 0)
	hi, _ := c.deviceIn(0x40)
	if uint16(lo)|uint16(hi)<<8 != latched || c.pit.latched || c.pit.readPhase != 1 {
		t.Fatal("latch command overwrote unread high byte or changed live read phase")
	}
	c.deviceIn(0x40)
	if c.pit.readPhase != 0 {
		t.Fatal("live high-byte phase was lost")
	}
}
func TestPITMode3DecrementsTwicePerInputClock(t *testing.T) {
	start := time.Unix(1, 0)
	p := timer{reload: 10, mode: 3, start: start}
	if p.count(start) != 10 || p.count(start.Add(time.Second)) != 6 {
		t.Fatal("mode 3 did not count twice per input clock")
	}
	p.mode = 2
	if p.count(start.Add(time.Second)) != 8 {
		t.Fatal("mode 2 count")
	}
}
