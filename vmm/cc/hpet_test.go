package cc

import (
	"context"
	"j5.nz/cc/hypervisor"
	"testing"
	"time"
)

func TestHPETCounterAndPeriodicInterrupt(t *testing.T) {
	now := time.Unix(100, 0)
	var edges []bool
	h := &hpet{started: now, setIRQ: func(irq uint32, level bool) error {
		if irq != 20 {
			t.Fatalf("IRQ %d", irq)
		}
		edges = append(edges, level)
		return nil
	}}
	write := func(reg, value uint64) {
		t.Helper()
		if err := h.write(reg, value, ^uint64(0), now); err != nil {
			t.Fatal(err)
		}
	}
	write(0xf0, 100)
	now = now.Add(time.Second)
	if h.counter(now) != 100 {
		t.Fatal("disabled counter advanced")
	}
	write(0x100, 20<<9|2|4|8|64)
	write(0x108, 200)
	write(0x108, 50)
	if h.read(0x108, now) != 200 || h.timers[0].period != 50 {
		t.Fatal("period write replaced initial match")
	}
	write(0x10, 1)
	now = now.Add(time.Microsecond)
	if err := h.poll(now); err != nil {
		t.Fatal(err)
	}
	if h.status != 1 || len(edges) != 1 || !edges[0] || h.timers[0].match != 250 {
		t.Fatalf("first expiry: %+v %v", h, edges)
	}
	now = now.Add(1500 * time.Nanosecond)
	if err := h.poll(now); err != nil {
		t.Fatal(err)
	}
	if len(edges) != 1 || h.timers[0].match != 400 {
		t.Fatal("latched level was pulsed or missed periods not advanced")
	}
	write(0x20, 1)
	if len(edges) != 2 || edges[1] || h.status != 0 {
		t.Fatal("W1C failed to lower IRQ")
	}
	write(0x10, 0)
	frozen := h.counter(now)
	now = now.Add(time.Second)
	if h.counter(now) != frozen {
		t.Fatal("counter failed to freeze")
	}
	write(0x10, 1)
	now = now.Add(10 * time.Nanosecond)
	if h.counter(now) != frozen+1 {
		t.Fatal("counter failed to resume")
	}
}

func TestHPETEdgeAndWrap(t *testing.T) {
	now := time.Unix(100, 0)
	var edges []bool
	h := &hpet{started: now, setIRQ: func(_ uint32, level bool) error { edges = append(edges, level); return nil }}
	for _, w := range [][2]uint64{{0xf0, 0xfffffff0}, {0x100, 20<<9 | 256 | 4}, {0x108, 0x10}, {0x10, 1}} {
		if err := h.write(w[0], w[1], ^uint64(0), now); err != nil {
			t.Fatal(err)
		}
	}
	if got := h.timers[0].next.Sub(now); got != 160*time.Nanosecond {
		t.Fatalf("wrap deadline %v", got)
	}
	if err := h.poll(now.Add(160 * time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	if len(edges) != 2 || !edges[0] || edges[1] || h.status != 0 {
		t.Fatalf("edge delivery %v status %x", edges, h.status)
	}
	if err := h.poll(now.Add(320 * time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	if len(edges) != 4 || !edges[2] || edges[3] {
		t.Fatal("missing comparator edge after counter rollover")
	}
	now = now.Add(time.Microsecond)
	if err := h.write(0x108, 1, ^uint64(0), now); err != nil {
		t.Fatal(err)
	}
	if h.timers[0].next.Sub(now) < 40*time.Second {
		t.Fatal("past comparator fired immediately")
	}
}

func TestHPETSplitRegistersAndMasks(t *testing.T) {
	now := time.Unix(100, 0)
	h := &hpet{setIRQ: func(uint32, bool) error { return nil }}
	for _, w := range [][3]uint64{{0xf0, 0x1234567800000000, 0xffffffff00000000}, {0xf0, 0xabcdef01, 0xffffffff}, {0, 0, ^uint64(0)}, {0x100, ^uint64(0), ^uint64(0)}} {
		if err := h.write(w[0], w[1], w[2], now); err != nil {
			t.Fatal(err)
		}
	}
	if h.counter(now) != 0x12345678abcdef01 {
		t.Fatalf("split counter %x", h.counter(now))
	}
	if h.read(0, now) != hpetCapabilities {
		t.Fatal("capabilities writable")
	}
	if h.read(0x100, now)&(1<<14) != 0 || h.read(0x100, now)>>32 != 0xf00000 {
		t.Fatal("unsupported FSB or route capabilities")
	}
}

// The native runner must wake for HPET even while RTC register C is latched.
// Only SetIRQ may run concurrently; the timer latch is published on return.
type hpetRunCPU struct {
	hypervisor.X86
	irq chan uint32
}

func (c *hpetRunCPU) SetIRQ(irq uint32, level bool) error {
	if level {
		c.irq <- irq
	}
	return nil
}
func (c *hpetRunCPU) RunUntil(ctx context.Context, _ func(hypervisor.X86Exit) (bool, error)) (hypervisor.X86Exit, error) {
	select {
	case irq := <-c.irq:
		return hypervisor.X86Exit{Reason: hypervisor.X86ExitIO, Port: uint16(irq)}, nil
	case <-ctx.Done():
		return hypervisor.X86Exit{}, ctx.Err()
	}
}
func TestHPETWakesWithLatchedRTC(t *testing.T) {
	c := &hpetRunCPU{irq: make(chan uint32, 1)}
	now := time.Now()
	h := &hpet{config: 1, started: now, setIRQ: c.SetIRQ}
	h.timers[0] = hpetTimer{config: 20<<9 | 6, match: 200000, next: now.Add(2 * time.Millisecond)}
	p := &pc{cpu: c, now: time.Now, hpet: h, rtcIRQ: true, rtcNext: now.Add(time.Hour)}
	p.cmos[0xa], p.cmos[0xb] = 6, 0x40
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ex, err := p.run(ctx)
	if err != nil || ex.Port != 20 || h.status != 1 || !h.timers[0].asserted {
		t.Fatalf("exit %+v error %v HPET %+v", ex, err, h)
	}
}

func TestHPETSharedLevelRemainsAsserted(t *testing.T) {
	now := time.Unix(100, 0)
	var edges []bool
	h := &hpet{config: 1, started: now, setIRQ: func(_ uint32, v bool) error { edges = append(edges, v); return nil }}
	for i := 0; i < 2; i++ {
		h.timers[i] = hpetTimer{config: 20<<9 | 6, next: now}
	}
	if err := h.poll(now); err != nil {
		t.Fatal(err)
	}
	if len(edges) != 1 || !edges[0] || h.status != 3 {
		t.Fatalf("shared IRQ %v status %d", edges, h.status)
	}
	if err := h.write(0x20, 1, ^uint64(0), now); err != nil {
		t.Fatal(err)
	}
	if len(edges) != 1 {
		t.Fatal("acknowledging one comparator lowered shared IRQ")
	}
	if err := h.write(0x20, 2, ^uint64(0), now); err != nil {
		t.Fatal(err)
	}
	if len(edges) != 2 || edges[1] {
		t.Fatal("last acknowledgement did not lower IRQ")
	}
}

func TestHPETResetComparators(t *testing.T) {
	h := newHPET(time.Unix(0, 0), func(uint32, bool) error { return nil })
	for i := range h.timers {
		if h.timers[i].match != ^uint64(0) {
			t.Fatal("comparator did not reset to all ones")
		}
	}
}
