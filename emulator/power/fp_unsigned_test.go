package power

import (
	"math"
	"math/big"
	"testing"
)

func fpForm(t, b, xo uint32, record bool) uint32 {
	w := uint32(63<<26) | t<<21 | b<<11 | xo<<1
	if record {
		w |= 1
	}
	return w
}

func TestUnsignedToFloatRoundingAndStatus(t *testing.T) {
	modes := []big.RoundingMode{big.ToNearestEven, big.ToZero, big.ToPositiveInf, big.ToNegativeInf}
	for rn, mode := range modes {
		for _, input := range []uint64{0, 1, 127, 1 << 53, 1<<53 + 1, 1<<53 + 3, 1<<63 + 1025, ^uint64(0)} {
			m := machineWith(t, fpForm(3, 2, 974, true))
			c := m.CPUs[0]
			c.MSR |= MSRFP
			c.FPSCR = uint64(rn) | fpsFR | fpsFI
			c.FPR[2] = input
			ref := new(big.Float).SetPrec(53).SetMode(mode).SetInt(new(big.Int).SetUint64(input))
			want, _ := ref.Float64()
			stop := runUntilStop(t, m, 1)
			if stop.Kind != "budget" || c.FPR[3] != math.Float64bits(want) || c.FPSCR&3 != uint64(rn) {
				t.Fatal(rn, input, stop, c.FPR[3], math.Float64bits(want))
			}
			inexact, up := ref.Acc() != big.Exact, ref.Acc() == big.Above
			if (c.FPSCR&fpsFI != 0) != inexact || (c.FPSCR&fpsFR != 0) != up || (c.FPSCR&fpsXX != 0) != inexact || (c.FPSCR&fpsFX != 0) != inexact {
				t.Fatal("rounding flags", rn, input, c.FPSCR, ref.Acc())
			}
			class := uint64(4)
			if input == 0 {
				class = 2
			}
			if c.FPSCR&fpsFPRF != class<<12 || (c.CR>>24)&15 != uint32(c.FPSCR>>28)&15 {
				t.Fatal("class or CR1", c.FPSCR, c.CR)
			}
		}
	}
}

func TestFloatToUnsignedZeroBoundsAndInvalid(t *testing.T) {
	for _, tc := range []struct {
		input            float64
		want             uint64
		invalid, inexact bool
	}{
		{0, 0, false, false}, {math.Copysign(0, -1), 0, false, false}, {-0.75, 0, false, true},
		{123.75, 123, false, true}, {0x1p63, 1 << 63, false, false},
		{math.Nextafter(0x1p64, 0), 0xfffffffffffff800, false, false},
		{-1, 0, true, false}, {0x1p64, ^uint64(0), true, false},
		{math.Inf(1), ^uint64(0), true, false}, {math.Inf(-1), 0, true, false}, {math.NaN(), 0, true, false},
	} {
		m := machineWith(t, fpForm(0, 1, 943, false))
		c := m.CPUs[0]
		c.MSR |= MSRFP
		c.FPSCR = 2 | fpsFR | fpsFI // RN=+infinity must not affect truncation.
		c.FPR[1] = math.Float64bits(tc.input)
		stop := runUntilStop(t, m, 1)
		if stop.Kind != "budget" || c.FPR[0] != tc.want || (c.FPSCR&fpsVXCVI != 0) != tc.invalid || (c.FPSCR&fpsFI != 0) != tc.inexact || c.FPSCR&fpsFR != 0 {
			t.Fatal(tc, stop, c.FPR[0], c.FPSCR)
		}
	}
	for _, delivery := range []uint64{0, 1 << 11} {
		m := machineWith(t, fpForm(0, 1, 943, true))
		c := m.CPUs[0]
		c.MSR |= MSRFP | delivery
		c.FPSCR = fpsVE
		c.FPR[0], c.FPR[1] = 123, 0x7ff0000000000001 // signaling NaN
		stop := runUntilStop(t, m, 1)
		if c.FPR[0] != 123 || c.FPSCR&(fpsVXCVI|fpsVXSNAN|fpsVX|fpsFEX|fpsFX) != (fpsVXCVI|fpsVXSNAN|fpsVX|fpsFEX|fpsFX) {
			t.Fatal("enabled invalid", stop, c.FPR[0], c.FPSCR)
		}
		if delivery != 0 && (stop.Kind != "interrupt" || c.PC != VecProgram || c.SRR1&ProgFP == 0) || delivery == 0 && stop.Kind != "budget" {
			t.Fatal("exception delivery", stop, c.PC)
		}
	}
}

func TestUnsignedConversionInexactTrapAndStatusClear(t *testing.T) {
	m := machineWith(t, fpForm(3, 2, 974, false))
	c := m.CPUs[0]
	c.MSR |= MSRFP | 1<<11
	c.FPSCR = fpsXE
	c.FPR[2] = 1<<53 + 1
	if stop := runUntilStop(t, m, 1); stop.Kind != "interrupt" || c.SRR1&ProgFP == 0 || c.FPR[3] != math.Float64bits(1<<53) || c.FPSCR&fpsFEX == 0 {
		t.Fatal(stop, c.FPR[3], c.FPSCR)
	}
	m = machineWith(t, 0xfee0008c) // mtfsb0 23 clears VXCVI and derived summaries.
	c = m.CPUs[0]
	c.MSR |= MSRFP
	c.FPSCR = fpsVXCVI | fpsVX | fpsFEX | fpsVE | fpsFX
	runUntilStop(t, m, 1)
	if c.FPSCR != fpsVE|fpsFX {
		t.Fatal(c.FPSCR)
	}
	// Sticky enabled status is still visible, but an exact operation does
	// not raise a new exception merely because an earlier one was recorded.
	m = machineWith(t, fpForm(3, 2, 974, false))
	c = m.CPUs[0]
	c.MSR |= MSRFP | MSRFE0
	c.FPSCR = fpsXE | fpsXX | fpsFEX
	c.FPR[2] = 127
	if stop := runUntilStop(t, m, 1); stop.Kind != "budget" || c.FPR[3] != math.Float64bits(127) || c.FPSCR&fpsFEX == 0 {
		t.Fatal(stop, c.FPR[3], c.FPSCR)
	}
}

func TestNativeUnsignedConversionPipeline(t *testing.T) {
	m := machineWith(t, 0x7c5f0166, 0xfc60179c, 0xfc230072, 0xfee0008c, 0xfc000f5e, 0x7c030066, 0xfc00048e, 0x7c000066)
	c := m.CPUs[0]
	c.MSR |= MSRFP | 1<<11 | 1<<8
	c.GPR[31] = 127
	c.FPR[1] = 0x3fe55810624dd2f2
	c.FPSCR = 0xf0
	if stop := runUntilStop(t, m, 8); stop.Kind != "budget" || c.GPR[3] != 84 || c.GPR[0] != c.FPSCR || c.FPSCR&fpsVXCVI != 0 {
		t.Fatal(stop, c.GPR[3], c.GPR[0], c.FPSCR)
	}
}

func TestUnsignedWordConversionZero(t *testing.T) {
	for _, tc := range []struct {
		bits, result, flags uint64
	}{
		{0, 0, 0}, {1 << 63, 0, 0},
		{math.Float64bits(0xffffffff), 0xffffffff, 0},
		{math.Float64bits(0x1p32 - 0.5), 0xffffffff, fpsFI | fpsXX},
		{math.Float64bits(0x1p32), 0xffffffff, fpsVXCVI | fpsVX},
		{math.Float64bits(0x1p64), 0xffffffff, fpsVXCVI | fpsVX},
		{math.Float64bits(123.75), 123, fpsFI | fpsXX},
		{math.Float64bits(-0.75), 0, fpsFI | fpsXX},
		{math.Float64bits(-1), 0, fpsVXCVI | fpsVX},
		{0x7ff0000000000000, 0xffffffff, fpsVXCVI | fpsVX},
		{0xfff0000000000000, 0, fpsVXCVI | fpsVX},
		{0x7ff8000000000123, 0, fpsVXCVI | fpsVX},
		{0xfff0000000000123, 0, fpsVXCVI | fpsVX | fpsVXSNAN},
	} {
		for rn := uint64(0); rn < 4; rn++ {
			for _, target := range []uint32{0, 1} {
				m := machineWith(t, fpForm(target, 1, 143, true))
				c := m.CPUs[0]
				c.MSR |= MSRFP
				c.FPR[1] = tc.bits
				c.FPSCR = rn | fpsFR | fpsFI | 4<<12
				want := rn | 4<<12 | tc.flags
				if tc.flags != 0 {
					want |= fpsFX
				}
				if r := runUntilStop(t, m, 1); r.Kind != "budget" || c.FPR[target] != tc.result || c.FPSCR != want || (c.CR>>24)&15 != uint32(want>>28)&15 {
					t.Fatal(tc, rn, target, r, c.FPR[target], c.FPSCR, want, c.CR)
				}
			}
		}
	}
}

func TestUnsignedWordConversionEnabledExceptions(t *testing.T) {
	for _, tc := range []struct {
		bits, enable, flags uint64
		invalid             bool
	}{
		{0x7ff0000000000123, fpsVE, fpsVXCVI | fpsVXSNAN | fpsVX, true},
		{math.Float64bits(0x1p32), fpsVE, fpsVXCVI | fpsVX, true},
		{math.Float64bits(7.25), fpsXE, fpsFI | fpsXX, false},
	} {
		for _, delivery := range []uint64{0, MSRFE0, MSRFE1, MSRFE0 | MSRFE1} {
			m := machineWith(t, fpForm(1, 1, 143, true))
			c := m.CPUs[0]
			c.MSR |= MSRFP | delivery
			c.FPR[1], c.FPSCR = tc.bits, tc.enable|fpsFR|fpsFI|4<<12
			result := uint64(7)
			if tc.invalid {
				result = tc.bits
			}
			want := tc.enable | tc.flags | fpsFX | fpsFEX | 4<<12
			r := runUntilStop(t, m, 1)
			if (r.Kind == "interrupt") != (delivery != 0) || delivery != 0 && c.SRR1&ProgFP == 0 || c.FPR[1] != result || c.FPSCR != want || (c.CR>>24)&15 != uint32(want>>28)&15 {
				t.Fatal(tc, delivery, r, c.FPR[1], result, c.FPSCR, want)
			}
		}
	}
	m := machineWith(t, fpForm(0, 1, 143, false))
	c := m.CPUs[0]
	c.FPR[0], c.FPSCR = 123, 456
	if r := runUntilStop(t, m, 1); r.Kind != "interrupt" || c.PC != VecFPUnavailable || c.FPR[0] != 123 || c.FPSCR != 456 {
		t.Fatal(r, c.FPR[0], c.FPSCR)
	}
}

func TestUnsignedWordConversionRoundingModes(t *testing.T) {
	inexact, increment, invalid := fpsXX|fpsFI, fpsXX|fpsFI|fpsFR, fpsVXCVI|fpsVX
	for _, tc := range []struct {
		input   float64
		results [4]uint64
		flags   [4]uint64
	}{
		{2.5, [4]uint64{2, 2, 3, 2}, [4]uint64{inexact, inexact, increment, inexact}},
		{3.5, [4]uint64{4, 3, 4, 3}, [4]uint64{increment, inexact, increment, inexact}},
		{0.5, [4]uint64{0, 0, 1, 0}, [4]uint64{inexact, inexact, increment, inexact}},
		{-0.5, [4]uint64{}, [4]uint64{inexact, inexact, inexact, invalid}},
		{-0.75, [4]uint64{}, [4]uint64{invalid, inexact, inexact, invalid}},
		{0x1p32 - 0.5, [4]uint64{0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff}, [4]uint64{invalid, inexact, invalid, inexact}},
		{0x1p32 - 0.75, [4]uint64{0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff}, [4]uint64{inexact, inexact, invalid, inexact}},
		{0xffffffff, [4]uint64{0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff}, [4]uint64{}},
		{math.Inf(1), [4]uint64{0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff}, [4]uint64{invalid, invalid, invalid, invalid}},
		{math.Float64frombits(0xfff0000000000123), [4]uint64{}, [4]uint64{invalid | fpsVXSNAN, invalid | fpsVXSNAN, invalid | fpsVXSNAN, invalid | fpsVXSNAN}},
	} {
		for rn := uint64(0); rn < 4; rn++ {
			for _, target := range []uint32{0, 1} {
				m := machineWith(t, fpForm(target, 1, 142, true))
				c := m.CPUs[0]
				c.MSR |= MSRFP
				c.FPR[1] = math.Float64bits(tc.input)
				c.FPSCR = rn | fpsFR | fpsFI | 4<<12
				want := rn | tc.flags[rn] | 4<<12
				if tc.flags[rn] != 0 {
					want |= fpsFX
				}
				if r := runUntilStop(t, m, 1); r.Kind != "budget" || c.FPR[target] != tc.results[rn] || c.FPSCR != want || (c.CR>>24)&15 != uint32(want>>28)&15 {
					t.Fatal(tc.input, rn, target, r, c.FPR[target], tc.results[rn], c.FPSCR, want, c.CR)
				}
			}
		}
	}
}
