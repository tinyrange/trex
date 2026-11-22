package power

import (
	"math"
	"testing"
)

func TestRoundIntegralMinus(t *testing.T) {
	for _, tc := range []struct {
		in, out uint64
		class   uint64
	}{
		{0x40835d5e038ea148, math.Float64bits(619), 4},
		{math.Float64bits(2.75), math.Float64bits(2), 4},
		{math.Float64bits(-2.25), math.Float64bits(-3), 8},
		{0, 0, 2}, {1 << 63, 1 << 63, 0x12},
		{1, 0, 2}, {1<<63 | 1, math.Float64bits(-1), 8},
		{math.Float64bits(0x1p53), math.Float64bits(0x1p53), 4},
		{math.Float64bits(-0x1p53), math.Float64bits(-0x1p53), 8},
		{0x7fefffffffffffff, 0x7fefffffffffffff, 4},
		{0x7ff0000000000000, 0x7ff0000000000000, 5},
		{0xfff0000000000000, 0xfff0000000000000, 9},
		{0xfff8000000000123, 0xfff8000000000123, 0x11},
	} {
		for rn := uint64(0); rn < 4; rn++ {
			for _, sticky := range []uint64{0, fpsXX | fpsFX | fpsFEX} {
				m := machineWith(t, 0xffe013d1) // frim. f31,f2
				c := m.CPUs[0]
				c.MSR |= MSRFP | MSRFE0 | MSRFE1
				c.FPR[2] = tc.in
				c.FPSCR = rn | sticky | fpsXE | fpsFR | fpsFI | fpsFPRF
				stop := runUntilStop(t, m, 1)
				wantStatus := rn | sticky | fpsXE | tc.class<<12
				if stop.Kind != "budget" || c.FPR[31] != tc.out || c.FPR[2] != tc.in || c.FPSCR != wantStatus || (c.CR>>24)&15 != uint32(wantStatus>>28)&15 {
					t.Fatalf("in=%016x rn=%d: %v result=%016x status=%x want=%x CR=%x", tc.in, rn, stop, c.FPR[31], c.FPSCR, wantStatus, c.CR)
				}
			}
		}
	}
}

func TestRoundIntegralPlus(t *testing.T) {
	for _, tc := range []struct {
		input, result float64
		class         uint64
	}{
		{0, 0, 2}, {math.Copysign(0, -1), math.Copysign(0, -1), 0x12},
		{2.25, 3, 4}, {-2.75, -2, 8},
		{math.SmallestNonzeroFloat64, 1, 4}, {-math.SmallestNonzeroFloat64, math.Copysign(0, -1), 0x12},
		{math.Inf(1), math.Inf(1), 5}, {math.Inf(-1), math.Inf(-1), 9},
	} {
		for rn := range uint64(4) {
			m := machineWith(t, 0xfc200b90) // frip f1,f1
			c := m.CPUs[0]
			c.MSR |= MSRFP
			c.FPR[1] = math.Float64bits(tc.input)
			c.FPSCR = fpsFR | fpsFI | fpsFPRF | fpsXX | rn
			result := runUntilStop(t, m, 1)
			if result.Kind != "budget" || c.FPR[1] != math.Float64bits(tc.result) || c.FPSCR != fpsXX|rn|tc.class<<12 {
				t.Fatalf("input %g RN %d: %v, FPR %x, FPSCR %x", tc.input, rn, result, c.FPR[1], c.FPSCR)
			}
		}
	}
}

func TestRoundIntegralSignalingNaN(t *testing.T) {
	for _, opcode := range []uint32{488, 456, 424, 392} {
		for _, enable := range []uint64{0, fpsVE} {
			for _, delivery := range []uint64{0, MSRFE0, MSRFE1, MSRFE0 | MSRFE1} {
				m := machineWith(t, fpForm(2, 2, opcode, true)) // overlapping source/destination
				c := m.CPUs[0]
				c.MSR |= MSRFP | delivery
				c.FPR[2] = 0xfff0000000000123
				c.FPSCR = enable | fpsFR | fpsFI | 4<<12
				stop := runUntilStop(t, m, 1)
				wantResult, wantClass := uint64(0xfff8000000000123), uint64(0x11)
				wantStatus := enable | fpsVXSNAN | fpsVX | fpsFX
				if enable != 0 {
					wantResult, wantClass = 0xfff0000000000123, 4
					wantStatus |= fpsFEX
				}
				wantStatus |= wantClass << 12
				trapped := enable != 0 && delivery != 0
				if (stop.Kind == "interrupt") != trapped || trapped && c.SRR1&ProgFP == 0 || c.FPR[2] != wantResult || c.FPSCR != wantStatus || (c.CR>>24)&15 != uint32(wantStatus>>28)&15 {
					t.Fatal(enable, delivery, stop, c.FPR[2], c.FPSCR, wantStatus, c.CR)
				}
			}
		}
	}
	m := machineWith(t, 0xffe013d0)
	c := m.CPUs[0]
	c.FPR[31], c.FPSCR = 123, 456
	if stop := runUntilStop(t, m, 1); stop.Kind != "interrupt" || c.PC != VecFPUnavailable || c.FPR[31] != 123 || c.FPSCR != 456 {
		t.Fatal("unavailable instruction changed state", stop, c.FPR[31], c.FPSCR)
	}
}

func TestRoundIntegralZero(t *testing.T) {
	for _, tc := range []struct {
		in, out uint64
		class   uint64
	}{
		{math.Float64bits(2.75), math.Float64bits(2), 4},
		{math.Float64bits(-2.25), math.Float64bits(-2), 8},
		{0, 0, 2}, {1 << 63, 1 << 63, 0x12},
		{1, 0, 2}, {1<<63 | 1, 1 << 63, 0x12},
		{0x4330000000000000, 0x4330000000000000, 4}, // native IPL routine's large-input branch
		{0x7fefffffffffffff, 0x7fefffffffffffff, 4},
		{0x7ff0000000000000, 0x7ff0000000000000, 5},
		{0xfff0000000000000, 0xfff0000000000000, 9},
		{0xfff8000000000123, 0xfff8000000000123, 0x11},
	} {
		for rn := uint64(0); rn < 4; rn++ {
			m := machineWith(t, fpForm(31, 2, 424, true))
			c := m.CPUs[0]
			c.MSR |= MSRFP | MSRFE0 | MSRFE1
			c.FPR[2] = tc.in
			c.FPSCR = rn | fpsXX | fpsFX | fpsXE | fpsFR | fpsFI | fpsFPRF
			want := rn | fpsXX | fpsFX | fpsXE | tc.class<<12
			if r := runUntilStop(t, m, 1); r.Kind != "budget" || c.FPR[31] != tc.out || c.FPSCR != want || (c.CR>>24)&15 != uint32(want>>28)&15 {
				t.Fatal(tc, rn, r, c.FPR[31], c.FPSCR, want, c.CR)
			}
		}
	}
}

func TestRoundIntegralNearestAway(t *testing.T) {
	for _, tc := range []struct {
		in, out uint64
		class   uint64
	}{
		{math.Float64bits(2.5), math.Float64bits(3), 4},
		{math.Float64bits(-2.5), math.Float64bits(-3), 8},
		{math.Float64bits(1.5), math.Float64bits(2), 4},
		{math.Float64bits(-1.5), math.Float64bits(-2), 8},
		{math.Float64bits(0.5), math.Float64bits(1), 4},
		{math.Float64bits(-0.5), math.Float64bits(-1), 8},
		{math.Float64bits(math.Nextafter(0.5, 0)), 0, 2},
		{math.Float64bits(math.Nextafter(-0.5, 0)), 1 << 63, 0x12},
		{math.Float64bits(math.Nextafter(0.5, 1)), math.Float64bits(1), 4},
		{math.Float64bits(math.Nextafter(-0.5, -1)), math.Float64bits(-1), 8},
		{0, 0, 2}, {1 << 63, 1 << 63, 0x12},
		{1, 0, 2}, {1<<63 | 1, 1 << 63, 0x12},
		{math.Float64bits(0x1p52 - 0.5), math.Float64bits(0x1p52), 4},
		{math.Float64bits(0x1p52 + 1), math.Float64bits(0x1p52 + 1), 4},
		{0x7ff0000000000000, 0x7ff0000000000000, 5},
		{0xfff0000000000000, 0xfff0000000000000, 9},
		{0xfff8000000000123, 0xfff8000000000123, 0x11},
	} {
		for rn := uint64(0); rn < 4; rn++ {
			m := machineWith(t, fpForm(31, 2, 392, true))
			c := m.CPUs[0]
			c.MSR |= MSRFP | MSRFE0 | MSRFE1
			c.FPR[2] = tc.in
			c.FPSCR = rn | fpsXX | fpsFX | fpsXE | fpsFR | fpsFI | fpsFPRF
			want := rn | fpsXX | fpsFX | fpsXE | tc.class<<12
			if r := runUntilStop(t, m, 1); r.Kind != "budget" || c.FPR[31] != tc.out || c.FPR[2] != tc.in || c.FPSCR != want || (c.CR>>24)&15 != uint32(want>>28)&15 {
				t.Fatal(tc, rn, r, c.FPR[31], c.FPSCR, want, c.CR)
			}
		}
	}
	m := machineWith(t, fpForm(31, 2, 392, false))
	c := m.CPUs[0]
	c.FPR[31], c.FPSCR = 123, 456
	if r := runUntilStop(t, m, 1); r.Kind != "interrupt" || c.PC != VecFPUnavailable || c.FPR[31] != 123 || c.FPSCR != 456 {
		t.Fatal(r, c.FPR[31], c.FPSCR)
	}
}
