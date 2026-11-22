package power

import "testing"

func TestDecimalShortToLong(t *testing.T) {
	for _, tc := range []struct {
		input uint32
		want  uint64
		class uint64
	}{
		{0xa23003d0, 0xa2300000000003d0, 8}, // −7.50, retaining the quantum
		{0x22500000, 0x2238000000000000, 2},
		{0xa2500000, 0xa238000000000000, 0x12},
		{1, 0x20a4000000000001, 4},          // smallest short subnormal is normal in long
		{0x6e500000, 0x2238000000900000, 4}, // seven-digit coefficient
		{0xf9f00033, 0xf800000000000033, 9},
		{0x7df00001, 0x7c00000000000001, 0x11},
		{0xfe00036e, 0xfe0000000000006e, 1}, // signaling NaN, redundant declet
	} {
		for _, rc := range []uint32{0, 1} {
			m := machineWith(t, 0xefe00a04|rc) // QC2UTIL1: dctdp f31,f1
			c := m.CPUs[0]
			c.MSR |= MSRFP | MSRFE0 | MSRFE1
			c.FPR[1] = 0xdeadbeef00000000 | uint64(tc.input)
			c.FPSCR = fpsFX | fpsFR | fpsFI | fpsVE
			c.CR = 0x12345678
			stop := runUntilStop(t, m, 1)
			wantCR := uint32(0x12345678)
			if rc != 0 {
				wantCR = 0x18345678
			}
			if stop.Kind != "budget" || c.FPR[31] != tc.want || c.FPSCR != fpsFX|fpsVE|tc.class<<12 || c.CR != wantCR {
				t.Errorf("dctdp input %08x Rc=%d: %s result %016x FPSCR %x CR %x", tc.input, rc, stop.Kind, c.FPR[31], c.FPSCR, c.CR)
			}
		}
	}
}

func TestDecimalCompareUnordered(t *testing.T) {
	for _, tc := range []struct {
		quad         bool
		a, al, b, bl uint64
		want         uint32
		signaling    bool
	}{
		{false, 0xa2300000000003d0, 0, 0x22300000000003d0, 0, 8, false},
		{false, 0x2238000000000001, 0, 0x2234000000000010, 0, 2, false}, // 1 and 1.0
		{false, 0x8000000000000000, 0, 0x2238000000000000, 0, 2, false},
		{false, 0x7800000000000000, 0, 0x2238000000000000, 0, 4, false},
		{false, 0x7c00000000000000, 0, 0x7800000000000000, 0, 1, false},
		{true, 0x2208000000000000, 0x3ff, 0x2208000000000000, 0xff, 2, false}, // redundant DPD for 999
		{true, 0x2208000000000000, 1, 0x2208000000000000, 2, 8, false},
		{true, 0x2208000000000001, 0, 0x2208000000000000, 0x0fffffffffffffff, 4, false},
		{true, 0xfe00000000000000, 9, 0x2208000000000000, 0, 1, true},
	} {
		op := uint32(59)
		if tc.quad {
			op = 63
		}
		w := op<<26 | 2<<23 | 4<<16 | 6<<11 | 642<<1
		m := machineWith(t, w)
		c := m.CPUs[0]
		c.MSR |= MSRFP
		c.CR = 0xabcd1234
		c.FPSCR = fpsFR | fpsFI | 1<<16
		c.FPR[4], c.FPR[5], c.FPR[6], c.FPR[7] = tc.a, tc.al, tc.b, tc.bl
		stop := runUntilStop(t, m, 1)
		wantFPS := fpsFR | fpsFI | 1<<16 | uint64(tc.want)<<12
		if tc.signaling {
			wantFPS |= fpsVX | fpsFX | fpsVXSNAN
		}
		if stop.Kind != "budget" || c.CR != 0xab0d1234|tc.want<<20 || c.FPSCR != wantFPS {
			t.Errorf("dcmpu quad=%t %x:%x vs %x:%x: %s CR %x FPSCR %x want %x", tc.quad, tc.a, tc.al, tc.b, tc.bl, stop.Kind, c.CR, c.FPSCR, wantFPS)
		}
	}
}

func TestDecimalQuantize(t *testing.T) {
	const cents = uint64(0x2230000000000000)
	const tenths = uint64(0x2234000000000000)
	for _, tc := range []struct {
		quantum, input, want uint64
		mode                 uint32
		drn                  uint64
		flags                uint64
	}{
		{tenths, cents | 0xa5, tenths | 0x12, 0, 0, fpsFI | fpsXX | fpsFX},         // 1.25 -> 1.2
		{tenths, cents | 0xb5, tenths | 0x14, 0, 0, fpsFI | fpsFR | fpsXX | fpsFX}, // 1.35 -> 1.4
		{tenths, cents | 0xa5, tenths | 0x13, 2, 0, fpsFI | fpsFR | fpsXX | fpsFX},
		{tenths, cents | 0xa5, tenths | 0x12, 1, 0, fpsFI | fpsXX | fpsFX},
		{tenths, cents | 0xa5, tenths | 0x13, 3, 2, fpsFI | fpsFR | fpsXX | fpsFX},
		{cents, tenths | 0x12, cents | 0xa0, 0, 0, 0}, // 1.2 -> 1.20
		{0, 0x2238000000000001, 0x7c00000000000000, 0, 0, fpsVXCVI | fpsVX | fpsFX},
		{0x7c00000000000011, 0xfe00000000000042, 0xfc00000000000042, 0, 0, fpsVXSNAN | fpsVX | fpsFX},
	} {
		w := uint32(59<<26|1<<21|2<<16|31<<11|3<<1) | tc.mode<<9
		m := machineWith(t, w)
		c := m.CPUs[0]
		c.MSR |= MSRFP
		c.FPSCR = tc.drn << 32
		c.FPR[2], c.FPR[31] = tc.quantum, tc.input
		stop := runUntilStop(t, m, 1)
		class := uint64(4)
		if tc.want>>58&31 == 31 {
			class = 0x11
		}
		if wantStatus := tc.drn<<32 | class<<12 | tc.flags; stop.Kind != "budget" || c.FPR[1] != tc.want || c.FPSCR != wantStatus {
			t.Errorf("dqua %x %x RMC%d DRN%d: %s %016x/%x, want %016x/%x", tc.quantum, tc.input, tc.mode, tc.drn, stop.Kind, c.FPR[1], c.FPSCR, tc.want, wantStatus)
		}
	}
}

func TestDecimalQuantizeQuadPreservesPrecision(t *testing.T) {
	m := machineWith(t, 63<<26|4<<21|2<<16|4<<11|3<<1)
	c := m.CPUs[0]
	c.MSR |= MSRFP
	// Same quantum, 33 trailing digits are all 9. The preferred
	// representation has the two redundant bits in every declet clear.
	c.FPR[2] = 0x2208000000000000
	c.FPR[4], c.FPR[5] = 0x22083fffffffffff, 0xffffffffffffffff
	var rawHi, rawLo uint64
	for i := 0; i < 11; i++ {
		rawHi, rawLo = rawHi<<10|rawLo>>54, rawLo<<10|0xff
	}
	rawHi |= 0x2208000000000000
	if stop := runUntilStop(t, m, 1); stop.Kind != "budget" || c.FPR[4] != rawHi || c.FPR[5] != rawLo {
		t.Fatalf("dquaq produced %x:%x, expected %x:%x (%s)", c.FPR[4], c.FPR[5], rawHi, rawLo, stop.Kind)
	}
}

func TestDecimalRoundToShort(t *testing.T) {
	// Encode a decimal64 with a zero leading digit and an independent raw
	// DPD continuation. The operands below fit in the trailing 15 digits.
	long := func(exponent int, dpd uint64) uint64 {
		biased := uint64(exponent + 398)
		return biased>>8<<61 | (biased&255)<<50 | dpd
	}
	const lost = fpsFX | fpsFI | fpsXX
	for _, tc := range []struct {
		name                       string
		src, control, want, status uint64
		class                      uint64
		trap                       bool
	}{
		{"negative exact quantum", 0xa2300000000003d0, 0, 0xa23003d0, 0, 8, false},
		{"signed zero high quantum", 1<<63 | long(200, 0), 0, 0xc3f00000, 0, 0x12, false},
		{"signaling payload truncation", 0xfe00000ffff0036e, fpsVE, 0xfe00006e, 0, 1, false},
		{"infinity payload", 0x7800000000100001, 0, 0x78000001, 0, 5, false},
		{"exact smallest short", long(-101, 1), 0, 1, 0, 0x14, false},
		{"subnormal half even", long(-102, 0x25), 0, 2, lost | fpsUX, 0x14, false},
		{"subnormal half odd", long(-102, 0x35), 0, 4, lost | fpsUX | fpsFR, 0x14, false},
		{"single rounding below normal", long(-109, uint64(encodeDeclet[99])<<40|0xff<<30|uint64(encodeDeclet[949])<<20|0xff<<10|0xff), 0, 0x0003fcff, lost | fpsUX, 0x14, false},
		{"rounds to normal", long(-102, 0xff<<10|0xff|9<<20), 0, 0x04000000, lost | fpsUX | fpsFR, 4, false},
		{"clamp exponent", long(91, 1), 0, 0x43f00010, 0, 4, false},
		{"overflow to infinity", long(97, 1), 0, 0x78000000, lost | fpsOX | fpsFR, 5, false},
		{"overflow largest finite", long(97, 1), 1 << 32, 0x77f3fcff, lost | fpsOX, 4, false},
		{"enabled overflow wraps", long(97, 1), fpsOE, long(-95, 1), fpsFX | fpsFEX | fpsOX, 4, true},
		{"enabled exact tiny wraps", long(-101, 1), fpsUE, long(91, 1), fpsFX | fpsFEX | fpsUX, 4, true},
		{"enabled inexact", long(-102, 0x35), fpsXE, 4, lost | fpsUX | fpsFR | fpsFEX, 0x14, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := machineWith(t, 59<<26|1<<21|2<<11|770<<1)
			c := m.CPUs[0]
			c.MSR |= MSRFP | MSRFE0
			c.FPR[2], c.FPSCR = tc.src, tc.control|fpsFI|fpsFR
			runUntilStop(t, m, 1)
			wantFPS := tc.status | tc.control | tc.class<<12
			if c.FPR[1] != tc.want || c.FPSCR != wantFPS || (c.SRR0 == 0x1000) != tc.trap {
				t.Errorf("result %016x FPSCR %x SRR0 %x, want %016x FPSCR %x trap %t", c.FPR[1], c.FPSCR, c.SRR0, tc.want, wantFPS, tc.trap)
			}
		})
	}
}
