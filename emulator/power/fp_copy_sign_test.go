package power

import "testing"

func TestFloatingCopySignPreservesPayloadAndStatus(t *testing.T) {
	for _, tt := range []struct{ sign, magnitude, want uint64 }{
		{0x8000000000000000, 0, 0x8000000000000000},
		{0, 0x8000000000000000, 0},
		{0xbff0000000000000, 0x3ff8000000000000, 0xbff8000000000000},
		{0x3ff0000000000000, 0xfff0000000000000, 0x7ff0000000000000},
		{0xfff0000000000000, 1, 0x8000000000000001},
		{0x7ff0000000000001, 0xfff0000000000123, 0x7ff0000000000123},
		{0xfff8000000000012, 0x7ff8000000000456, 0xfff8000000000456},
	} {
		for _, target := range []uint32{0, 1, 2} { // including both source aliases
			for _, record := range []uint32{0, 1} {
				w := uint32(63<<26) | target<<21 | 1<<16 | 2<<11 | 8<<1 | record
				m := machineWith(t, w)
				c := m.CPUs[0]
				c.MSR |= MSRFP | MSRFE0 | MSRFE1
				c.FPR[1], c.FPR[2] = tt.sign, tt.magnitude
				c.FPSCR, c.CR = 0xe901f0f8, 0x12345678 // enabled invalid and sticky summaries
				wantCR := uint32(0x12345678)
				if record != 0 {
					wantCR = 0x1e345678
				}
				if r := runUntilStop(t, m, 1); r.Kind != "budget" || c.FPR[target] != tt.want || c.FPSCR != 0xe901f0f8 || c.CR != wantCR {
					t.Fatalf("%+v target%d Rc%d: stop%v value%x fpscr%x cr%x", tt, target, record, r, c.FPR[target], c.FPSCR, c.CR)
				}
			}
		}
	}
}

func TestFloatingCopySignRequiresFP(t *testing.T) {
	m := machineWith(t, 0xfc010011) // actual IPL instruction, with Rc
	c := m.CPUs[0]
	c.FPR[0], c.FPR[1], c.FPSCR, c.CR = 123, 1<<63, 0xf0000000, 0x12345678
	if r := runUntilStop(t, m, 1); r.Kind != "interrupt" || c.PC != VecFPUnavailable || c.FPR[0] != 123 || c.FPSCR != 0xf0000000 || c.CR != 0x12345678 {
		t.Fatal(r, c.PC, c.FPR[0], c.FPSCR, c.CR)
	}
}
