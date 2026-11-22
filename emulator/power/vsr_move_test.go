package power

import (
	"encoding/binary"
	"math"
	"testing"
)

func TestMoveToVSRUsesBankAvailabilityAndFPAlias(t *testing.T) {
	for _, tc := range []struct {
		idx     uint32
		enabled uint64
	}{{3, MSRFP}, {35, MSRVEC}} {
		m := machineWith(t, xForm(tc.idx&31, 0, 0, 179, tc.idx >= 32))
		c := m.CPUs[0]
		c.MSR |= tc.enabled           // Neither form requires MSR.VSX.
		c.GPR[0] = 0x8000000000000001 // RA0 names GPR0, not constant zero.
		c.VSR[tc.idx] = [2]uint64{123, 456}
		c.CR, c.XER, c.FPSCR = 0x12345678, 0xabcdef, 0x9876
		stop := runUntilStop(t, m, 1)
		if stop.Kind != "budget" || c.VSR[tc.idx][0] != c.GPR[0] || c.CR != 0x12345678 || c.XER != 0xabcdef || c.FPSCR != 0x9876 {
			t.Fatal(stop, c.VSR[tc.idx], c.CR, c.XER, c.FPSCR)
		}
		if tc.idx < 32 && c.FPR[tc.idx] != c.GPR[0] {
			t.Fatal("FPR alias not updated")
		}
	}
	// The real ICU allocation path immediately converts the moved integer.
	m := machineWith(t, 0x7c660166, 63<<26|2<<21|3<<11|846<<1)
	c := m.CPUs[0]
	c.MSR |= MSRFP
	c.GPR[6] = 127
	if stop := runUntilStop(t, m, 2); stop.Kind != "budget" || c.FPR[2] != math.Float64bits(127) {
		t.Fatal(stop, c.FPR[2])
	}
}

func TestMoveFromVSRReadsScalarConversionAndStatus(t *testing.T) {
	// A native compiler conversion helper uses fctidz, mfvsrd, mffs and
	// another mfvsrd. Neither move may read a stale copy of the FPR alias.
	for _, input := range []float64{-12.75, 0, 123.75} {
		m := machineWith(t, 0xfc000e5e, 0x7c030066, 0xfc00048e, 0x7c000066)
		c := m.CPUs[0]
		c.MSR |= MSRFP
		c.FPR[1] = math.Float64bits(input)
		c.FPSCR = 0xf0
		c.VSR[0][0] = 0xdeadbeef
		stop := runUntilStop(t, m, 4)
		if stop.Kind != "budget" || c.GPR[3] != uint64(int64(input)) || c.GPR[0] != 0xf0 {
			t.Fatal(input, stop, c.GPR[3], c.GPR[0])
		}
	}
	// Upper-bank reads require VEC, without FP or VSX availability.
	m := machineWith(t, xForm(3, 0, 0, 51, true))
	c := m.CPUs[0]
	c.MSR |= MSRVEC
	c.VSR[35][0] = 0x123456789abcdef0
	if stop := runUntilStop(t, m, 1); stop.Kind != "budget" || c.GPR[0] != c.VSR[35][0] {
		t.Fatal(stop, c.GPR[0])
	}
}

func TestVSRMemoryTransfersShareFPRDoubleword(t *testing.T) {
	m := machineWith(t, xForm(3, 4, 5, 844, false), xForm(3, 6, 0, 51, false), xForm(3, 4, 7, 972, false))
	c := m.CPUs[0]
	c.MSR |= MSRFP | MSRVSX
	c.GPR[4], c.GPR[5], c.GPR[7] = 0x2000, 0, 16
	binary.BigEndian.PutUint64(m.Mem[0x2000:], math.Float64bits(123))
	binary.BigEndian.PutUint64(m.Mem[0x2008:], 0xfeedface)
	runUntilStop(t, m, 2)
	if c.FPR[3] != math.Float64bits(123) || c.GPR[6] != c.FPR[3] {
		t.Fatal("vector load did not reach scalar alias")
	}
	c.FPR[3] = math.Float64bits(456)
	runUntilStop(t, m, 1)
	if binary.BigEndian.Uint64(m.Mem[0x2010:]) != c.FPR[3] || binary.BigEndian.Uint64(m.Mem[0x2018:]) != 0xfeedface {
		t.Fatal("vector store did not read current scalar alias")
	}
}

func TestMoveToVSRUnavailablePreservesDestination(t *testing.T) {
	for _, xo := range []uint32{51, 179} {
		for _, tc := range []struct {
			idx    uint32
			other  uint64
			vector uint64
		}{{3, MSRVEC | MSRVSX, VecFPUnavailable}, {35, MSRFP | MSRVSX, VecVecUnavail}} {
			m := machineWith(t, xForm(tc.idx&31, 6, 0, xo, tc.idx >= 32))
			c := m.CPUs[0]
			c.MSR |= tc.other
			c.VSR[tc.idx] = [2]uint64{123, 456}
			c.FPR[3] = 789
			c.GPR[6] = 127
			stop := runUntilStop(t, m, 1)
			if stop.Kind != "interrupt" || c.PC != tc.vector || c.SRR0 != 0x1000 || c.VSR[tc.idx] != [2]uint64{123, 456} || c.FPR[3] != 789 || c.GPR[6] != 127 {
				t.Fatal(stop, c.PC, c.VSR[tc.idx], c.FPR[3])
			}
		}
	}
}
