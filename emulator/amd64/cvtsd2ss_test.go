package amd64

import (
	"encoding/binary"
	"math"
	"testing"
)

func TestCVTSD2SS(t *testing.T) {
	for mode := uint64(0); mode < 4; mode++ {
		c, m := codeMemory(t, "f2 0f 5a c1")
		for i := range c.xmm[0] {
			c.xmm[0][i] = 0xaa
		}
		binary.LittleEndian.PutUint64(c.xmm[1][:8], math.Float64bits(1+math.Ldexp(1, -24)))
		c.setMXCSR(0x1f80 | mode<<13)
		if _, err := c.Step(m); err != nil {
			t.Fatal(err)
		}
		want := uint32(0x3f800000)
		if mode == 2 {
			want++
		}
		if binary.LittleEndian.Uint32(c.xmm[0][:4]) != want || c.readMXCSR()&(1<<5) == 0 {
			t.Fatal("wrong rounding/precision")
		}
		for _, b := range c.xmm[0][4:] {
			if b != 0xaa {
				t.Fatal("clobbered upper lanes")
			}
		}
	}
	c := new(CPU)
	c.setMXCSR(0xf80)
	if _, err := c.doubleToSingle(math.Float64bits(1.1)); err == nil {
		t.Fatal("missed unmasked precision")
	}
	if got, err := c.doubleToSingle(1 << 63); err != nil || got != 1<<31 {
		t.Fatal("negative zero")
	}
	if _, err := c.doubleToSingle(math.Float64bits(math.Inf(1))); err == nil {
		t.Fatal("accepted unmodeled infinity")
	}
}
