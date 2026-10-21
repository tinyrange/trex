package rfe

import (
	"context"
	"testing"
	"time"
)

func TestNativeLeafBatchCommitsClockAndStopsAtRDTSCSTIAndIO(t *testing.T) {
	code := []byte{0x40, 0x49, 0x75, 0xfc, 0x0f, 0x31, 0xfb, 0x43, 0xe6, 0xf2}
	actual, expected := jitCPU(t, 16, code), jitCPU(t, 16, code)
	referenceToPort(t, expected)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := actual.Run(ctx); err != nil {
		t.Fatal(err)
	}
	equalJITState(t, actual, expected)
	for _, c := range []*cpu{actual, expected} {
		c.pending = nil
		c.core.PC = 0x1000
		c.core.R[1] = 256
	}
	before := actual.core.Retired
	for expected.core.PC != 0x1006 {
		if err := expected.core.Step(); err != nil {
			t.Fatal(err)
		}
	}
	for n := 0; actual.core.PC != 0x1006 && n < 16; n++ {
		prior := actual.core.Retired
		if err := actual.jit.Run(4096); err != nil {
			t.Fatal(err)
		}
		if actual.core.Retired-prior > 4096 || actual.pending != nil || actual.system.IRQShadow != 0 {
			t.Fatal("batch crossed budget or architectural boundary")
		}
	}
	equalJITState(t, actual, expected)
	if actual.core.Retired <= before+16 {
		t.Fatal("ordinary leaves were not batched")
	}
	for _, target := range []uint64{0x1007, 0x1008, 0x100a} {
		if err := expected.core.Step(); err != nil {
			t.Fatal(err)
		}
		if err := actual.jit.Run(4096); err != nil {
			t.Fatal(err)
		}
		if actual.core.PC != target {
			t.Fatal("batch skipped architectural/shadow edge", actual.core.PC, target)
		}
		equalJITState(t, actual, expected)
		if actual.system.IRQShadow != expected.system.IRQShadow {
			t.Fatal("STI shadow was skipped")
		}
	}
	if actual.pending == nil || actual.pending.Port != 0xf2 {
		t.Fatal("I/O boundary lost")
	}
}
