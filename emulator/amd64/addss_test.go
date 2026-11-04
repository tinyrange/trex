package amd64

import (
	"encoding/binary"
	"github.com/tinyrange/trex/emulator/cpu"
	"math"
	"math/big"
	"math/rand"
	"testing"
)

func TestADDSS(t *testing.T) {
	for _, tc := range []struct {
		a, b      uint32
		rc        uint64
		want      uint32
		precision bool
	}{
		{0x3f800000, 0x40000000, 0, 0x40400000, false},
		{0, 0xc0000000, 0, 0xc0000000, false},
		{0x80000000, 0x80000000, 0, 0x80000000, false},
		{0x80000000, 0, 0, 0, false}, {0x80000000, 0, 1, 0x80000000, false},
		{0x3f800000, 0xbf800000, 0, 0, false}, {0x3f800000, 0xbf800000, 1, 0x80000000, false},
		{0x3f800001, 0xbf800000, 0, 0x34000000, false},
		{0x3f800000, 0x33800000, 0, 0x3f800000, true},
		{0x3f800001, 0x33800000, 0, 0x3f800002, true},
		{0x3f800000, 0x33800000, 2, 0x3f800001, true},
		{0x3f800000, 0xb3000000, 1, 0x3f7fffff, true},
		{0x3f800000, 0x00800000, 2, 0x3f800001, true},
		{0x3f800000, 0x80800000, 1, 0x3f7fffff, true},
		{0xbf800000, 0x80800000, 1, 0xbf800001, true},
		{0xbf800000, 0x00800000, 3, 0xbf7fffff, true},
	} {
		for _, code := range []string{"f30f58c1", "f30f5802"} {
			c, m := codeMemory(t, code)
			c.xmm[0] = [16]byte{0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
			binary.LittleEndian.PutUint32(c.xmm[0][:4], tc.a)
			binary.LittleEndian.PutUint32(c.xmm[1][:4], tc.b)
			c.registers[2] = 0x200000003
			if err := m.Map(c.registers[2], c.xmm[1][:4], cpu.Read); err != nil {
				t.Fatal(err)
			}
			before := c.xmm[0]
			control := uint64(0x1f80) | tc.rc<<13
			c.setMXCSR(control)
			c.flags = flagCarry
			if _, err := c.Step(m); err != nil {
				t.Fatal(err)
			}
			if got := binary.LittleEndian.Uint32(c.xmm[0][:4]); got != tc.want {
				t.Fatalf("%x/%x rc%d got%x want%x", tc.a, tc.b, tc.rc, got, tc.want)
			}
			for i := 4; i < 16; i++ {
				if c.xmm[0][i] != before[i] {
					t.Fatal("upper lane changed")
				}
			}
			if tc.precision {
				control |= 1 << 5
			}
			if c.readMXCSR() != control || c.flags != flagCarry {
				t.Fatal("flags")
			}
		}
	}
}
func TestADDSSStops(t *testing.T) {
	for _, tc := range []struct {
		a, b    uint32
		control uint64
	}{
		{0x3f800000, 0x33800000, 0xf80}, // Unmasked precision.
		{1, 0x3f800000, 0x1f80}, {0x7f800000, 0x3f800000, 0x1f80},
		{0x7fc00000, 0x3f800000, 0x1f80}, {0x7f7fffff, 0x7f7fffff, 0x1f80},
		{0x00800001, 0x80800000, 0x1f80}, // Unsupported subnormal result.
	} {
		c, m := codeMemory(t, "f30f58c1")
		binary.LittleEndian.PutUint32(c.xmm[0][:4], tc.a)
		binary.LittleEndian.PutUint32(c.xmm[1][:4], tc.b)
		c.setMXCSR(tc.control)
		before, pc := c.xmm[0], c.PC()
		if _, err := c.Step(m); err == nil {
			t.Fatal("expected stop")
		}
		if c.xmm[0] != before || c.PC() != pc {
			t.Fatal("stop changed destination/PC")
		}
	}
}

func TestADDSSUnmappedSource(t *testing.T) {
	c, m := codeMemory(t, "f30f5802")
	c.registers[2] = 0x200000003
	c.setMXCSR(0x1f80)
	before, pc := c.xmm, c.PC()
	if _, err := c.Step(m); err == nil || c.xmm != before || c.PC() != pc || c.readMXCSR() != 0x1f80 {
		t.Fatal("memory fault changed scalar state")
	}
}

// Independent high-precision oracle covers exponent alignment, cancellation and
// all rounding directions; it does not reproduce the guard/sticky algorithm.
func TestADDSSFiniteRoundingOracle(t *testing.T) {
	random := rand.New(rand.NewSource(771))
	modes := []big.RoundingMode{big.ToNearestEven, big.ToNegativeInf, big.ToPositiveInf, big.ToZero}
	for i := 0; i < 4000; i++ {
		a, b := random.Uint32(), random.Uint32()
		normal := func(v uint32) bool { e := v >> 23 & 255; return e != 0 && e != 255 }
		if !normal(a) || !normal(b) {
			continue
		}
		left := new(big.Float).SetPrec(512).SetFloat64(float64(math.Float32frombits(a)))
		right := new(big.Float).SetPrec(512).SetFloat64(float64(math.Float32frombits(b)))
		exact := new(big.Float).SetPrec(512).Add(left, right)
		for rc, mode := range modes {
			rounded := new(big.Float).SetPrec(24).SetMode(mode).Set(exact)
			value, _ := rounded.Float32()
			want := math.Float32bits(value)
			if !normal(want) {
				continue
			}
			c := new(CPU)
			control := uint64(0x1f80) | uint64(rc)<<13
			c.setMXCSR(control)
			got, err := c.addSingle(a, b)
			if err != nil || got != want {
				t.Fatalf("%x + %x mode%d: got%x want%x err%v", a, b, rc, got, want, err)
			}
			if rounded.Cmp(exact) != 0 {
				control |= 32
			}
			if c.readMXCSR() != control {
				t.Fatalf("precision flag for %x+%x mode%d", a, b, rc)
			}
		}
	}
}
