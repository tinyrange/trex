package amd64

import (
	"encoding/binary"
	"math"
	"testing"
)

func TestCVTSS2SD(t *testing.T) {
	c, m := codeMemory(t, "f3 0f 5a c1")
	binary.LittleEndian.PutUint32(c.xmm[1][:4], math.Float32bits(-1.25))
	for i := range c.xmm[0] {
		c.xmm[0][i] = 0xaa
	}
	if _, err := c.Step(m); err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint64(c.xmm[0][:8]) != math.Float64bits(-1.25) {
		t.Fatal("conversion")
	}
	for _, b := range c.xmm[0][8:] {
		if b != 0xaa {
			t.Fatal("upper lane clobbered")
		}
	}
}
