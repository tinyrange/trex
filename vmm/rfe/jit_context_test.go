package rfe

import (
	"context"
	"testing"
	"time"
)

// The same linear PC is not the same translation when CS changes code size.
// Switching between already-hot modes must preserve both native variants,
// while running through the real PC scheduler and architectural reference.
func TestJITModeSwitchPreservesHotNativeVariants(t *testing.T) {
	code := []byte{0x40, 0x49, 0x75, 0xfc, 0xe6, 0xf2}
	actual, expected := jitCPU(t, 32, code), jitCPU(t, 32, code)
	promotions := uint64(0)
	for pass := 0; pass < 20; pass++ {
		for _, c := range []*cpu{actual, expected} {
			c.pending = nil
			c.core.PC = 0x1000
			c.core.R[1] = 256
			if pass%2 == 0 {
				c.system.Segments[1].Flags &^= 1 << 14
			} else {
				c.system.Segments[1].Flags |= 1 << 14
			}
		}
		referenceToPort(t, expected)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, err := actual.Run(ctx)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		equalJITState(t, actual, expected)
		stats := actual.jit.Stats()
		if pass == 1 {
			promotions = stats["promotions"]
		}
		if pass > 1 && stats["promotions"] != promotions {
			t.Fatalf("mode switch recompiled a hot variant: %v", stats)
		}
	}
	stats := actual.jit.Stats()
	if stats["native16"] == 0 || stats["native32"] == 0 || stats["invalidations"] != 0 || stats["compile_failures"] != 0 {
		t.Fatal("native mode identity/reuse", stats)
	}
}
