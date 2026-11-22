package power

import (
	"math/big"
	"math/rand"
	"strconv"
	"strings"
	"testing"
)

func TestASDecimalTestClearSign(t *testing.T) {
	for _, payload := range []uint64{0, 0x1234567890123450, 0xfffffffffffffff0} {
		for nibble := uint64(0); nibble < 16; nibble++ {
			for _, alias := range []bool{false, true} {
				for _, so := range []uint64{0, XERSO} {
					ra := uint32(10)
					if alias {
						ra = 3
					}
					m := machineWith(t, xForm(3, ra, 0, 93, true))
					m.as = true
					c := m.CPUs[0]
					c.MSR |= MSRTA | MSRPR
					for i := range c.GPR {
						c.GPR[i] = uint64(i) * 0x1020304050607
					}
					c.GPR[3] = payload | nibble
					c.XER = 0x123456782fabcdef&^XERSO | so
					c.CR = 0x12345678
					xer, registers := c.XER, c.GPR
					condition := uint64(4)
					if nibble == 0xb || nibble == 0xd {
						condition = 8
					}
					registers[ra] = payload
					wantXER := xer&^(XERCA|uint64(15)<<24) | condition<<24
					wantCR := uint32(0x02345678) | uint32(condition|so>>31)<<28
					if r := runUntilStop(t, m, 1); r.Kind != "budget" || c.GPR != registers || c.XER != wantXER || c.CR != wantCR {
						t.Fatalf("payload%x sign%x alias%v SO%x: %v GPR%x XER%x/%x CR%x/%x", payload, nibble, alias, so, r, c.GPR, c.XER, wantXER, c.CR, wantCR)
					}
				}
			}
		}
	}
}

func TestASDecimalSignSelection(t *testing.T) {
	// Test two signs, materialize each positive
	// predicate through XER[37], then compare the predicates. The CR1
	// compare between the selects and xor. must not disturb those GPRs.
	for first := uint64(0); first < 16; first++ {
		for second := uint64(0); second < 16; second++ {
			m := machineWith(t, 0x7c6a00bb, 0x38600001, 0x7863029c,
				0x7cc800bb, 0x39200001, 0x7929029c, 0x28a70000, 0x7c6b4a79)
			m.as = true
			c := m.CPUs[0]
			c.MSR |= MSRTA
			c.GPR[3], c.GPR[6], c.GPR[7] = 0x8093406740|first, 0x10485760|second, 1
			positive := func(sign uint64) uint64 {
				if sign == 0xb || sign == 0xd {
					return 0
				}
				return 1
			}
			a, b := positive(first), positive(second)
			if r := runUntilStop(t, m, 8); r.Kind != "budget" || c.GPR[3] != a || c.GPR[9] != b || c.GPR[11] != a^b || c.GPR[10] != 0x8093406740 || c.GPR[8] != 0x10485760 || c.CRBit(2) != (a == b) {
				t.Fatal(first, second, r, c.GPR, c.CR)
			}
		}
	}
}

func TestASDecimalTestClearSignGuards(t *testing.T) {
	for _, tt := range []struct {
		as, ta bool
		word   uint32
	}{
		{false, true, 0x7c6a00bb}, {true, false, 0x7c6a00bb},
		{true, true, 0x7c6a00ba}, {true, true, 0x7c6a08bb},
	} {
		m := machineWith(t, tt.word)
		m.as = tt.as
		c := m.CPUs[0]
		if tt.ta {
			c.MSR |= MSRTA
		}
		c.GPR[3], c.GPR[10], c.CR, c.XER = 0x123d, 0xabcd, 0x12345678, 0x76543210
		if r := runUntilStop(t, m, 1); r.Kind != "interrupt" || c.SRR1&ProgIllegal == 0 || c.GPR[3] != 0x123d || c.GPR[10] != 0xabcd || c.CR != 0x12345678 || c.XER != 0x76543210 {
			t.Fatal(tt, r, c.GPR, c.CR, c.XER)
		}
	}
}

func TestASDecimalCarryArithmetic(t *testing.T) {
	rng := rand.New(rand.NewSource(54))
	for _, xo := range []uint32{8, 10} {
		for _, alias := range []uint32{3, 4, 5} {
			m := machineWith(t, xForm(alias, 4, 5, xo, false))
			m.as = true
			c := m.CPUs[0]
			c.MSR |= MSRTA
			for i := 0; i < 2000; i++ {
				a, b := rng.Uint64(), rng.Uint64()
				c.GPR[4], c.GPR[5] = a, b
				c.XER = rng.Uint64() & ((1 << 48) - 1)
				before := c.XER
				left, carry := a, uint64(0)
				if xo == 8 {
					left, carry = ^a, 1
				}
				var dc uint64
				for digit := uint(0); digit < 16; digit++ {
					sum := (left >> (4 * digit) & 15) + (b >> (4 * digit) & 15) + carry
					carry = sum >> 4
					dc |= carry << digit
				}
				c.exec(xForm(alias, 4, 5, xo, false))
				want := dc << 32
				if dc != 0 {
					want |= 1 << 23
				}
				mask := uint64(0xffff)<<32 | 1<<23
				if c.XER&mask != want || c.XER&XERCA != carry<<29 {
					t.Fatalf("xo%d alias%d a%x b%x: XER%x DC/DS want%x CA%d", xo, alias, a, b, c.XER, want, carry)
				}
				// OC is defined for addition and unspecified for subtraction.
				changed := mask | XERCA | XERCA32
				if xo == 10 {
					changed |= 1 << 28
					boundary := uint(11)
					if a>>48 != 0 {
						boundary = 5
					}
					if c.XER>>28&1 != dc>>boundary&1 {
						t.Fatal("offset carry differs from digit-boundary oracle", a, b, c.XER, dc)
					}
				}
				if c.XER&^changed != before&^changed {
					t.Fatal("unrelated XER bits changed", xo, c.XER, before)
				}
			}
		}
	}
}

func TestASDecimalSixesAllCarries(t *testing.T) {
	m := machineWith(t, 0x7c07007a)
	m.as = true
	c := m.CPUs[0]
	c.MSR |= MSRTA | MSRPR
	for dc := uint64(0); dc < 65536; dc++ {
		c.XER = dc<<32 | 0xdeadbeef
		c.CR = 0x12345678
		xer, cr := c.XER, c.CR
		var want uint64
		for digit := uint(0); digit < 16; digit++ {
			if dc&(1<<(15-digit)) == 0 {
				want |= uint64(6) << (60 - 4*digit)
			}
		}
		c.exec(0x7c07007a)
		if c.GPR[7] != want || c.XER != xer || c.CR != cr {
			t.Fatal(dc, c.GPR[7], want, c.XER, xer, c.CR, cr)
		}
	}
}

func TestASDecimalOffsetCarry(t *testing.T) {
	for _, tt := range []struct{ a, b, want uint64 }{
		{0xffffffffffff, 1, 1}, {0xfffffffffffe, 1, 0},
		{0x1234000000ffffff, 1, 1}, {0x1234000000fffffe, 1, 0},
		{0, 0xffffffffffffffff, 0},
		{0x1234000000800000, 0xffffffffffffffff, 1},
	} {
		for _, immediate := range []bool{false, true} {
			m := machineWith(t)
			m.as = true
			c := m.CPUs[0]
			c.MSR |= MSRTA
			c.GPR[4], c.GPR[5], c.XER = tt.a, tt.b, 1<<28
			word := xForm(4, 4, 5, 10, false)
			if immediate {
				word = 12<<26 | 4<<21 | 4<<16 | uint32(tt.b&0xffff)
			}
			c.exec(word)
			if c.XER>>28&1 != tt.want {
				t.Fatal(tt, immediate, c.XER)
			}
		}
	}
}

func TestASDecimalFieldsAreNotGeneralCarryFlags(t *testing.T) {
	for _, mode := range []struct{ as, ta bool }{{false, false}, {true, false}, {true, true}} {
		// Extended arithmetic and immediates preserve DC/DS. Ordinary
		// addc/subfc also preserve these fields outside tags-active AS.
		words := []uint32{xForm(3, 4, 5, 138, false), xForm(3, 4, 5, 136, false), 12<<26 | 3<<21 | 4<<16 | 1}
		if !mode.as || !mode.ta {
			words = append(words, xForm(3, 4, 5, 10, false), xForm(3, 4, 5, 8, false))
		}
		for _, word := range words {
			m := machineWith(t, word)
			m.as = mode.as
			c := m.CPUs[0]
			if mode.ta {
				c.MSR |= MSRTA
			}
			c.GPR[4], c.GPR[5], c.XER = ^uint64(0), 1, 0xa55a00800000
			mask := uint64(0xffff)<<32 | 1<<23
			before := c.XER & mask
			if r := runUntilStop(t, m, 1); r.Kind != "budget" || c.XER&mask != before {
				t.Fatal(mode, word, r, c.XER, before)
			}
		}
	}
}

func TestASDecimalSixesGuards(t *testing.T) {
	for _, tt := range []struct {
		as, ta bool
		word   uint32
	}{
		{false, true, 0x7c07007a}, {true, false, 0x7c07007a},
		{true, true, 0x7c07007b}, {true, true, 0x7c27007a},
		{true, true, 0x7c07087a},
	} {
		m := machineWith(t, tt.word)
		m.as = tt.as
		c := m.CPUs[0]
		if tt.ta {
			c.MSR |= MSRTA
		}
		c.GPR[7], c.CR, c.XER = 0x123d, 0x12345678, 0x76543210
		if r := runUntilStop(t, m, 1); r.Kind != "interrupt" || c.SRR1&ProgIllegal == 0 || c.GPR[7] != 0x123d || c.CR != 0x12345678 || c.XER != 0x76543210 {
			t.Fatal(tt, r, c.GPR, c.CR, c.XER)
		}
	}
}

func TestASDecimalDoublewordPairAddition(t *testing.T) {
	// Packed positive addition uses addc's DC for dsixes, and CA
	// through an AS select to propagate between the two packed words.
	words := []uint32{0x7c840214, 0x7c630214, 0x7c843014, 0x78280118,
		0x7c07007a, 0x7c872050, 0x7ca54214, 0x7c632814,
		0x7c07007a, 0x7c671850, 0x6084000f}
	packed := func(decimal string) (uint64, uint64) {
		hex := strings.Repeat("0", 31-len(decimal)) + decimal + "0"
		hi, err := strconv.ParseUint(hex[:16], 16, 64)
		if err != nil {
			t.Fatal(err)
		}
		lo, err := strconv.ParseUint(hex[16:], 16, 64)
		if err != nil {
			t.Fatal(err)
		}
		return hi, lo
	}
	for _, inputs := range [][2]string{
		{"0", "0"}, {"999999999999999", "1"},
		{"999999999999999999999999999999", "1"},
		{"8486552065800", "111"}, {"1234567890123456", "9876543210987654"},
	} {
		m := machineWith(t, words...)
		m.as = true
		c := m.CPUs[0]
		c.MSR |= MSRTA
		c.GPR[0] = 0x6666666666666666
		c.GPR[3], c.GPR[4] = packed(inputs[0])
		c.GPR[5], c.GPR[6] = packed(inputs[1])
		a, _ := new(big.Int).SetString(inputs[0], 10)
		b, _ := new(big.Int).SetString(inputs[1], 10)
		hi, lo := packed(new(big.Int).Add(a, b).String())
		if r := runUntilStop(t, m, uint64(len(words))); r.Kind != "budget" || c.GPR[3] != hi || c.GPR[4] != lo|15 {
			t.Fatalf("%v: %v got%x:%x want%x:%x", inputs, r, c.GPR[3], c.GPR[4], hi, lo|15)
		}
	}
}
