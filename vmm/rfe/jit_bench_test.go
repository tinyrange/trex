package rfe

import (
	"context"
	"strconv"
	"testing"
)

// BenchmarkPCExecution measures warmed architectural execution, not process
// startup, native-arena construction, image building or scripted UI sleeps.
// Both tiers run the same CPU/device loop and retire real guest ALU, RAM,
// stack and branch instructions. No guest opcode is replaced by a host routine.
func BenchmarkPCExecution(b *testing.B) {
	cases := []struct {
		bits int
		code []byte
	}{
		{16, []byte{0x40, 0x01, 0x07, 0x50, 0x5a, 0x49, 0x75, 0xf8, 0xe6, 0xf2}},
		{32, []byte{0x40, 0x01, 0x03, 0x50, 0x5a, 0x49, 0x75, 0xf8, 0xe6, 0xf2}},
		{64, []byte{0x48, 0xff, 0xc0, 0x48, 0x01, 0x03, 0x50, 0x5a, 0x48, 0xff, 0xc9, 0x75, 0xf3, 0xe6, 0xf2}},
	}
	for _, test := range cases {
		for _, tier := range []string{"interpreter", "native"} {
			b.Run(strconv.Itoa(test.bits)+"/"+tier, func(b *testing.B) {
				c := jitCPU(b, test.bits, test.code)
				if tier == "interpreter" {
					if err := c.jit.Close(); err != nil {
						b.Fatal(err)
					}
					c.jit = nil
				}
				ctx := context.Background()
				run := func() {
					c.pending = nil
					c.core.PC = 0x1000
					c.core.R[1] = 256
					if _, err := c.Run(ctx); err != nil {
						b.Fatal(err)
					}
					if c.pending == nil || c.pending.Port != 0xf2 {
						b.Fatal("guest did not finish its loop")
					}
				}
				run() // identical initialization/warmup excluded from measurement
				before := c.core.Retired
				nativeBefore := uint64(0)
				if c.jit != nil {
					nativeBefore = c.jit.Stats()["native"]
				}
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					run()
				}
				b.StopTimer()
				retired := c.core.Retired - before
				b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(retired), "ns/guest-insn")
				b.ReportMetric(float64(retired)/b.Elapsed().Seconds()/1e6, "guest-MIPS")
				if c.jit != nil {
					native := c.jit.Stats()["native"] - nativeBefore
					if native == 0 {
						b.Fatal("native benchmark executed no native code")
					}
					b.ReportMetric(float64(native)*100/float64(retired), "native-%")
				}
			})
		}
	}
}
