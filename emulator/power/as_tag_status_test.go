package power

import "testing"

func TestASTagStatusToConditionField(t *testing.T) {
	for field := uint32(0); field < 8; field++ {
		for tags := uint64(0); tags < 8; tags++ {
			m := machineWith(t, xForm(field<<2, 0, 0, 544, false))
			m.as = true
			c := m.CPUs[0]
			c.MSR |= MSRTA | MSRPR
			c.XER = 0xa5a5ff5a&^(uint64(7)<<20) | tags<<20
			c.CR = 0x89abcdef
			xer, registers := c.XER, c.GPR
			shift := 28 - field*4
			want := uint32(0x89abcdef)&^(uint32(15)<<shift) | uint32(tags)<<shift
			if r := runUntilStop(t, m, 1); r.Kind != "budget" || c.CR != want || c.XER != xer || c.GPR != registers {
				t.Fatal(field, tags, r, c.CR, want, c.XER, xer)
			}
		}
	}
}

func TestASTagStatusRequiresValidTagsActiveForm(t *testing.T) {
	for _, tt := range []struct {
		as, ta bool
		word   uint32
	}{
		{false, true, 0x7c000440}, {true, false, 0x7c000440},
		{true, true, 0x7c000441}, {true, true, 0x7c200440},
		{true, true, 0x7c010440}, {true, true, 0x7c000c40},
	} {
		m := machineWith(t, tt.word)
		m.as = tt.as
		c := m.CPUs[0]
		if tt.ta {
			c.MSR |= MSRTA
		}
		c.CR, c.XER = 0x12345678, 0x76543210
		if r := runUntilStop(t, m, 1); r.Kind != "interrupt" || c.SRR1&ProgIllegal == 0 || c.CR != 0x12345678 || c.XER != 0x76543210 {
			t.Fatal(tt, r, c.CR, c.XER, c.SRR1)
		}
	}
}
