package rfe

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

func warmNativeSpin(t *testing.T, c *cpu) {
	t.Helper()
	longest := uint64(0)
	for i := 0; i < 160; i++ {
		before := c.core.Retired
		if err := c.jit.Run(4096); err != nil {
			t.Fatal(err)
		}
		n := c.core.Retired - before
		if n == 0 || n > 4096 {
			t.Fatal("unbounded native progress", n)
		}
		if n > longest {
			longest = n
		}
	}
	// Hosts without the foreign-call bridge retain a 64-instruction
	// compatibility quantum; both must amortize the old 16-instruction leaf.
	if longest <= 16 || c.jit.Stats()["linked"] == 0 {
		t.Fatal("hot loop never amortized a native scheduling slice", longest, c.jit.Stats())
	}
}
func TestNativeSessionBoundedProgressAndAsyncIRQ(t *testing.T) {
	c := jitCPU(t, 16, []byte{0x40, 0xeb, 0xfd})
	warmNativeSpin(t, c)
	// A pulse arriving while the native dispatcher owns the CPU must be
	// observed at its next bounded scheduling return, even with no guest I/O.
	binary.LittleEndian.PutUint16(c.ram[8*4:], 0x7000)
	binary.LittleEndian.PutUint16(c.ram[8*4+2:], 0)
	copy(c.ram[0x7000:], []byte{0xe6, 0xf2})
	c.system.IDTR.Base = 0
	c.pics[0].base, c.pics[0].mask = 8, 0xfe
	c.core.Flags |= 1 << 9
	pulse := time.AfterFunc(2*time.Millisecond, func() { c.SetIRQ(0, true); c.SetIRQ(0, false) })
	defer pulse.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ex, err := c.Run(ctx)
	if err != nil || ex.Port != 0xf2 || c.system.InterruptCounts[8] != 1 {
		t.Fatal("native loop starved IRQ", ex, err, c.system.InterruptCounts[8])
	}
}
func TestNativeSessionObservesCancellation(t *testing.T) {
	c := jitCPU(t, 16, []byte{0x40, 0xeb, 0xfd})
	warmNativeSpin(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.Run(ctx)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatal("native loop starved cancellation", err, time.Since(start))
	}
}
func TestTrackedLegacyTLBSeesGuestAndBorrowedTableWrites(t *testing.T) {
	c := jitCPU(t, 32, []byte{0xeb, 0xfe})
	c.system.CR[0], c.system.CR[3] = 0x80010011, 0x1000
	c.Write(0x1000, 4, 0x2067)
	c.Write(0x2004, 4, 0x3067)
	c.Write(0x3000, 4, 0x11223344)
	c.Write(0x7000, 4, 0x55667788)
	check := func(want uint64) {
		t.Helper()
		for i := 0; i < 3; i++ {
			v, err := c.system.Read(0x1000, 4, false)
			if err != nil || v != want {
				t.Fatal("stale architectural translation", v, want, err)
			}
		}
	}
	check(0x11223344)
	c.BeforeRAMWrite(0x2004, 4)
	binary.LittleEndian.PutUint32(c.ram[0x2004:], 0x7067)
	check(0x55667788)
	c.Write(0x2004, 4, 0x3067)
	check(0x11223344)
}
