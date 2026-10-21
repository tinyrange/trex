package cc

import (
	starvalue "github.com/tinyrange/trex/script/value"
	"testing"
	"time"
)

func TestDMAReadPerformancePublication(t *testing.T) {
	p, _ := dmaTestPC(t)
	held := holdDMA(t, p)
	p.performance = &pcPerformance{IO: make(map[string]*latencyCounter)}
	dmaPRD(p, 0, 0x40000, 1024, true)
	dmaCommand(t, p, false, 2)
	dmaStart(t, p, false)
	awaitDMA(t, held.entered)
	if err := p.completeIDEDMARead(false); err != nil {
		t.Fatal(err)
	}
	if p.performance.Read.Count != 0 {
		t.Fatal("unfinished storage counted as completed")
	}
	held.unblock()
	awaitDMA(t, p.dmaRead.done)
	// Simulate an independently delayed coordinator after the worker is joined.
	p.dmaRead.started = time.Now().Add(-30 * time.Millisecond)
	p.dmaRead.finished = p.dmaRead.started.Add(10 * time.Millisecond)
	if err := p.completeIDEDMARead(false); err != nil {
		t.Fatal(err)
	}
	s := p.performance
	if _, err := starvalue.Starlark(s.Read.value()); err != nil {
		t.Fatal(err)
	}
	if s.Read.Count != 1 || s.Read.Bytes != 1024 || s.Read.Nanoseconds != uint64(10*time.Millisecond) {
		t.Fatalf("read: %+v", s.Read)
	}
	if s.ReadDelivery.Count != 1 || s.ReadDelivery.Nanoseconds < uint64(20*time.Millisecond) {
		t.Fatalf("delivery: %+v", s.ReadDelivery)
	}
	if err := p.completeIDEDMARead(false); err != nil {
		t.Fatal(err)
	}
	if s.Read.Count != 1 {
		t.Fatal("counted the same completion twice")
	}
}
