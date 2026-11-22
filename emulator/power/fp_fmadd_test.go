package power

import (
	"math"
	"testing"
)

func TestFMAddRoundsOnlyAfterAddition(t *testing.T) {
	// A DAXPY loop accumulates into the addend register.
	const fmadd = uint32(63<<26 | 3<<21 | 3<<11 | 4<<6 | 29<<1) // fmadd f3,f0,f4,f3
	for _, tc := range []struct {
		name                    string
		factor, x, addend, want float64
	}{
		{"cancellation", 1 + 0x1p-27, 1 - 0x1p-27, -1, -0x1p-54},
		{"product overflow", math.MaxFloat64, 2, -math.MaxFloat64, math.MaxFloat64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := machineWith(t, fmadd)
			c := m.CPUs[0]
			c.MSR |= MSRFP
			c.FPR[0] = math.Float64bits(tc.factor)
			c.FPR[4] = math.Float64bits(tc.x)
			c.FPR[3] = math.Float64bits(tc.addend)
			if r := runUntilStop(t, m, 1); r.Kind != "budget" {
				t.Fatal(r)
			}
			if got := c.FPR[3]; got != math.Float64bits(tc.want) {
				t.Fatalf("fmadd = %016x, want %016x", got, math.Float64bits(tc.want))
			}
		})
	}
}
