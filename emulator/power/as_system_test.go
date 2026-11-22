package power

import (
	"encoding/binary"
	"testing"
)

// IBM PowerPC AS Books I/III (1999), not the later ISA 3.0 SCV facility:
// https://wiki.raptorcs.com/w/images/f/f6/Book3tags.pdf, pp.12,62,71.
func TestASVectoredCallAndReturn(t *testing.T) {
	m := NewMachine(Config{Memory: 1 << 20, Extensions: []string{"as"}})
	m.IdentitySegments = true
	m.StopAllInterrupts = false
	const base = uint64(0xffffffffff003000)
	for _, mapping := range []struct{ ea, real uint64 }{{0x1000, 0x1000}, {base, 0x2000}} {
		if err := m.MapPage(mapping.ea>>28, 0, mapping.ea&0xfffffff, 12, PTE{Real: mapping.real, Execute: true}); err != nil {
			t.Fatal(err)
		}
	}
	for level := uint32(0); level < 128; level++ {
		c := m.CPUs[0]
		before := MSRSF | MSRTA | MSREE | MSRRI | MSRME | MSRFP | MSRPR | MSRIR | MSRDR | MSRFE0 | MSRFE1 | MSRVEC | MSRVSX | 1<<61 | 1<<10 | 1<<9
		c.PC, c.MSR, c.SRR0, c.SRR1 = 0x1000, before, 0xabc, 0xdef
		c.CR, c.XER, c.LR, c.CTR = 0x12345678, 0x87654321, 0x55, 0x66
		binary.BigEndian.PutUint32(m.Mem[0x1000:], 0x44000001|level<<5)
		binary.BigEndian.PutUint32(m.Mem[0x2000+level*32:], 0x4c0000a4) // rfscv
		if r := runUntilStop(t, m, 1); r.Kind != "budget" || c.PC != base+uint64(level)*32 || c.LR != 0x1004 || c.CTR != before {
			t.Fatalf("scv%d: %v pc%x lr%x ctr%x", level, r, c.PC, c.LR, c.CTR)
		}
		if c.MSR != before&^(MSRFP|MSRPR|1<<61|1<<10|1<<9) || c.SRR0 != 0xabc || c.SRR1 != 0xdef || c.CR != 0x12345678 || c.XER != 0x87654321 {
			t.Fatalf("scv%d altered preserved state: %+v", level, c)
		}
		if r := runUntilStop(t, m, 1); r.Kind != "budget" || c.PC != 0x1004 || c.MSR != before || c.SRR0 != 0xabc || c.SRR1 != 0xdef {
			t.Fatalf("rfscv%d: %v pc%x msr%x", level, r, c.PC, c.MSR)
		}
	}
}

func TestASVectoredCallGuardsAndTranslation(t *testing.T) {
	for _, word := range []uint32{0x44000081, 0x4c0000a4} {
		for _, as := range []bool{false, true} {
			for _, ta := range []bool{false, true} {
				m := machineWith(t, word)
				m.as = as
				c := m.CPUs[0]
				if ta {
					c.MSR |= MSRTA
				}
				if as && ta {
					continue
				}
				c.LR, c.CTR = 0x1234, 0x5678
				r := runUntilStop(t, m, 1)
				if r.Kind != "interrupt" || c.SRR1&ProgIllegal == 0 || c.LR != 0x1234 || c.CTR != 0x5678 {
					t.Fatal(word, as, ta, r, c.SRR1)
				}
			}
		}
	}
	m := machineWith(t, 0x4c0000a4)
	m.as = true
	c := m.CPUs[0]
	c.MSR |= MSRTA | MSRPR
	if r := runUntilStop(t, m, 1); r.Kind != "interrupt" || c.SRR1&ProgPrivileged == 0 {
		t.Fatal("rfscv problem-state guard", r, c.SRR1)
	}
	m = machineWith(t, 0x44000081)
	m.as = true
	c = m.CPUs[0]
	c.MSR |= MSRTA
	runUntilStop(t, m, 1)
	if r := runUntilStop(t, m, 1); r.Kind != "interrupt" || c.SRR0 != 0xffffffffff003080 || c.PC != VecInstrSegment {
		t.Fatal("SCV vector must use instruction translation", r, c.SRR0, c.PC)
	}
}

func TestASLogicalAddressTraps(t *testing.T) {
	for _, tt := range []struct {
		a, b           uint64
		trap28, trap30 bool
	}{
		{0, 0, false, false}, {0x200, 0x100, false, false},
		{0x100, 0x200, false, true},
		{0x100, 0x1000100, false, true},
		{0xdd6a1d7d2d00ffa0, 0xdd6a1d7d2d001000, false, false}, // native IPL site
		{0xdd6a1d7d2d001000, 0xdd6a1d7d2d00ffa0, true, true},
		{0xb000100002000001, 0xb000100003000001, true, true},
		{0xb000100003000001, 0xb000100002000001, true, true},
		{0, 0xb000100002000001, true, true},
	} {
		for _, to := range []uint32{28, 30} {
			for _, ta := range []bool{false, true} {
				m := machineWith(t, xForm(to, 5, 6, 68, false))
				m.as = true
				c := m.CPUs[0]
				c.GPR[5], c.GPR[6] = tt.a, tt.b
				want := true // ordinary TO28/30 is unconditional
				if ta {
					c.MSR |= MSRTA
					want = tt.trap28
					if to == 30 {
						want = tt.trap30
					}
				}
				runUntilStop(t, m, 1)
				if (c.PC == VecProgram && c.SRR1&ProgTrap != 0) != want {
					t.Fatalf("td%d %x/%x TA%v: pc%x srr1%x want trap%v", to, tt.a, tt.b, ta, c.PC, c.SRR1, want)
				}
			}
		}
	}
}

func TestPower9ASIndexedSLSTrap(t *testing.T) {
	const base = uint64(0xf310df222b006000)
	for _, tt := range []struct {
		name                    string
		addr                    uint64
		as, ta, older, wantTrap bool
	}{
		{"table entry 386", base + 80 + 386*40, true, true, false, false},
		{"zero offset", base, true, true, false, false},
		{"different segment", base + (1 << 24), true, true, false, true},
		{"ordinary processor", base + 80, false, false, false, true},
		{"tags inactive", base + 80, true, false, false, true},
		{"older AS processor", base + 80, true, true, true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// td 29,r3,r6; cmpla; selir: index a 40-byte table entry.
			m := machineWith(t, 0x7fa33088, 0x7c233080, 0x78031b9a)
			m.as = tt.as
			if tt.older {
				m.cfg.PVR = 0x00350000
			}
			c := m.CPUs[0]
			if tt.ta {
				c.MSR |= MSRTA
			}
			c.GPR[3], c.GPR[6] = tt.addr, base
			runUntilStop(t, m, 3)
			if tt.wantTrap {
				if c.PC != VecProgram || c.SRR0 != 0x1000 || c.SRR1&ProgTrap == 0 {
					t.Fatalf("expected original trap, pc=%x srr0=%x srr1=%x", c.PC, c.SRR0, c.SRR1)
				}
			} else if c.PC != 0x100c || c.GPR[3] != tt.addr {
				t.Fatalf("in-segment address lost: pc=%x result=%x", c.PC, c.GPR[3])
			}
		})
	}
}

func TestPower9ASZeroBaseLengthCheck(t *testing.T) {
	// A nonzero length with a zero base and limit selects the out-of-buffer
	// branch before attempting a store.
	for _, length := range []uint64{0, 3, 12, 0xffffff, 0x1000000} {
		m := machineWith(t, 0x7fa6e088, 0x7c26e080, 0x7806339a, 0x7c263840, 0x41810178)
		m.as = true
		c := m.CPUs[0]
		c.MSR |= MSRTA
		c.GPR[6] = length
		runUntilStop(t, m, 5)
		wantPC := uint64(0x1188)
		switch length {
		case 0:
			wantPC = 0x1014
		case 0x1000000:
			wantPC = VecProgram
		}
		if c.PC != wantPC || c.GPR[6] != length {
			t.Fatalf("zero base + %#x: PC=%#x length=%#x, want PC=%#x", length, c.PC, c.GPR[6], wantPC)
		}
	}
}

func TestASTrapKeepsTagsActive(t *testing.T) {
	m := machineWith(t, xForm(30, 5, 6, 68, false))
	m.as = true
	c := m.CPUs[0]
	c.MSR |= MSRTA
	c.GPR[5], c.GPR[6] = 1, 2
	runUntilStop(t, m, 1)
	if c.MSR&MSRTA == 0 || c.SRR1&MSRTA == 0 {
		t.Fatal("program interrupt cleared tags-active mode", c.MSR, c.SRR1)
	}
	for _, to := range []uint32{28, 30} {
		m = machineWith(t, xForm(to, 5, 6, 4, false))
		m.as = true
		c = m.CPUs[0]
		c.MSR |= MSRTA
		runUntilStop(t, m, 1)
		if c.SRR1&ProgIllegal == 0 {
			t.Fatal("tags-active tw must reject reserved logical-address options", to, c.SRR1)
		}
	}
}
