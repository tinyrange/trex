/*
 * S370 CPU test cases.
 *
 * Copyright 2024, Richard Cornwell
 *                 Original test cases by Ken Shirriff
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (thLoe "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

// Adapted from rcornwell/S370 emu/cpu/cpu_test.go at
// da2e3f45a1ac73cf16814933546e6183f3136451.
// All 116 upstream tests and the decimal vectors are retained. See README.md
// for provenance, harness adaptations, and reviewed differences.
package s390

import (
	"encoding/hex"
	"math"
	"math/rand"
	"testing"
)

const (
	testCycles int    = 1000
	HDMASK     uint64 = 0xffffffff80000000
	FDMASK     uint64 = 0x00000000ffffffff
)

// Get a short floating point register.
func (cw *cornwellFixture) getFloatShort(num int) uint32 {
	v := cw.c.FPR[num&0x6]
	if (num & 1) == 0 {
		v >>= 32
	}
	return uint32(v & LMASKL)
}

// Set a short floating point register.
func (cw *cornwellFixture) setFloatShort(num int, v uint32) {
	n := num & 6
	if (num & 1) == 0 {
		cw.c.FPR[n] = (uint64(v) << 32) | (cw.c.FPR[n] & LMASKL)
	} else {
		cw.c.FPR[n] = (cw.c.FPR[n] & HMASKL) | uint64(v)
	}
}

// Get load floating point register.
func (cw *cornwellFixture) getFloatLong(num int) uint64 {
	return cw.c.FPR[num]
}

// Get load floating point register.
func (cw *cornwellFixture) setFloatLong(num int, v uint64) {
	cw.c.FPR[num] = v
}

// Convert a floating point value to a 64-bit FP register.
func (cw *cornwellFixture) floatToFpreg(num int, val float64) bool {
	var sign uint64

	// Quick exit if zero
	if val == 0 {
		cw.setFloatLong(num, 0)
		return true
	}

	// Extract sign
	if val < 0 {
		sign = MSIGNL
		val = -val
	}

	char := 64
	// Determine exponent
	for val >= 1 && char < 128 {
		char++
		val /= 16
	}

	for val < 1/16. && char >= 0 {
		char--
		val *= 16
	}

	if char < 0 || char >= 128 {
		return false
	}

	val *= 1 << 24
	f := sign | (uint64(char) << 56) | (uint64(val) << 32)
	f |= uint64((val - float64(uint32(val))) * float64((uint64(1) << 32)))
	cw.setFloatLong(num, f)
	return true
}

// load floating point short register as float64.
func (cw *cornwellFixture) cnvtShortFloat(num int) float64 {
	t64 := cw.getFloatLong(num)
	e := float64((t64>>56)&0x7f) - 64.0
	d := float64(0x00ffffff00000000 & t64)
	d *= math.Exp2(-56.0 + 4.0*e)
	if (MSIGNL & t64) != 0 {
		d *= -1.0
	}
	return d
}

// load floating point long register as float64.
func (cw *cornwellFixture) cnvtLongFloat(num int) float64 {
	t64 := cw.getFloatLong(num)
	e := float64((t64>>56)&0x7f) - 64.0
	d := float64(MMASKL & t64)
	d *= math.Exp2(-56.0 + 4.0*e)
	if (MSIGNL & t64) != 0 {
		d *= -1.0
	}
	return d
}

func (cw *cornwellFixture) TestFloatConv(t *testing.T) {
	err := cw.floatToFpreg(0, 0.0)
	if !err {
		t.Error("Unable to convert 0.0")
	}
	r := cw.getFloatLong(0)
	if r != 0 {
		t.Errorf("Wrong conversion of 0.0 got: %016x", r)
	}
	err = cw.floatToFpreg(0, 1.0)
	if !err {
		t.Error("Unable to convert 1.0")
	}
	r = cw.getFloatLong(0)
	if r != 0x4110000000000000 {
		t.Errorf("Wrong conversion of 1.0 got: %016x", r)
	}
	err = cw.floatToFpreg(0, 0.5)
	if !err {
		t.Error("Unable to convert 0.5")
	}
	r = cw.getFloatLong(0)
	if r != 0x4080000000000000 {
		t.Errorf("Wrong conversion of 0.5 got: %016x", r)
	}
	err = cw.floatToFpreg(0, 1.0/64.0)
	if !err {
		t.Error("Unable to convert 1/64")
	}
	r = cw.getFloatLong(0)
	if r != 0x3f40000000000000 {
		t.Errorf("Wrong conversion of 1/64 got: %016x", r)
	}
	err = cw.floatToFpreg(0, -15.0)
	if !err {
		t.Error("Unable to convert -15.0")
	}
	r = cw.getFloatLong(0)
	if r != 0xc1f0000000000000 {
		t.Errorf("Wrong conversion of -15.0 got: %016x", r)
	}
}

func (cw *cornwellFixture) TestShortConv(t *testing.T) {
	cw.setFloatShort(0, 0xff000000)
	cw.setFloatShort(1, 0)
	r := cw.cnvtShortFloat(0)
	if r != 0.0 {
		t.Errorf("Wrong conversion of 0.0 got: %f", r)
	}
	cw.setFloatShort(0, 0x41100000)
	r = cw.cnvtShortFloat(0)
	cw.setFloatShort(1, 0)
	if r != 1.0 {
		t.Errorf("Wrong conversion of 1.0 got: %f", r)
	}
	cw.setFloatShort(0, 0x40800000)
	r = cw.cnvtShortFloat(0)
	if r != 0.5 {
		t.Errorf("Wrong conversion of 0.5 got: %f", r)
	}
	cw.setFloatShort(0, 0x3f400000)
	r = cw.cnvtShortFloat(0)
	if r != (1.0 / 64.0) {
		t.Errorf("Wrong conversion of 1.0/64.0 got: %f", r)
	}
	cw.setFloatShort(0, 0xc1f00000)
	r = cw.cnvtShortFloat(0)
	if r != -15.0 {
		t.Errorf("Wrong conversion of -15.0 got: %f", r)
	}

	rnum := rand.New(rand.NewSource(125))
	for range testCycles {
		f := rnum.NormFloat64()
		scale := rnum.Intn(100) - 50
		f = math.Ldexp(f, scale)
		err := cw.floatToFpreg(0, f)
		if !err {
			t.Errorf("Unable to set register to %f", f)
		}
		r := cw.cnvtShortFloat(0)
		ratio := math.Abs((r - f) / f)
		if ratio > 0.000001 {
			t.Errorf("Conversion short failed got: %f expected: %f", r, f)
		}
	}
}

func (cw *cornwellFixture) TestLongConv(t *testing.T) {
	cw.setFloatShort(0, 0xff000000)
	cw.setFloatShort(1, 0)
	r := cw.cnvtLongFloat(0)
	if r != 0.0 {
		t.Errorf("Wrong conversion of 0.0 got: %f", r)
	}
	cw.setFloatShort(0, 0x41100000)
	r = cw.cnvtLongFloat(0)
	if r != 1.0 {
		t.Errorf("Wrong conversion of 1.0 got: %f", r)
	}
	cw.setFloatShort(0, 0x40800000)
	r = cw.cnvtLongFloat(0)
	if r != 0.5 {
		t.Errorf("Wrong conversion of 0.5 got: %f", r)
	}
	cw.setFloatShort(0, 0x3f400000)
	r = cw.cnvtLongFloat(0)
	if r != (1.0 / 64.0) {
		t.Errorf("Wrong conversion of 1.0/64.0 got: %f", r)
	}
	cw.setFloatShort(0, 0xc1f00000)
	r = cw.cnvtLongFloat(0)
	if r != -15.0 {
		t.Errorf("Wrong conversion of -15.0 got: %f", r)
	}

	rnum := rand.New(rand.NewSource(125))
	for range testCycles {
		f := rnum.NormFloat64()
		scale := rnum.Intn(100) - 50
		f = math.Ldexp(f, scale)
		err := cw.floatToFpreg(0, f)
		if !err {
			t.Errorf("Unable to set register to %f", f)
		}
		r := cw.cnvtLongFloat(0)
		ratio := math.Abs((r - f) / f)
		if ratio > 0.000001 {
			t.Errorf("Conversion long failed got: %f expected: %f", r, f)
		}
	}
}

// Roughly test characteristics of random number generator.
func (cw *cornwellFixture) TestRandFloat(t *testing.T) {
	pos := 0
	neg := 0
	big := 0
	small := 0

	// Test add logical with random values
	rnum := rand.New(rand.NewSource(125))
	for range testCycles {
		f := rnum.NormFloat64()
		scale := rnum.Intn(100) - 50
		f = math.Ldexp(f, scale)
		if f < 0.0 {
			neg++
		} else {
			pos++
		}
		if math.Abs(f) > math.Pow(2.0, 20.0) {
			big++
		} else if math.Abs(f) < math.Pow(2.0, -20.0) {
			small++
		}
	}

	if big < 200 {
		t.Errorf("Less then 200 big numbers: %d", big)
	}
	if small < 200 {
		t.Errorf("Less then 200 small numbers: %d", small)
	}
	if pos < 400 {
		t.Errorf("Less then 400 pos numbers: %d", pos)
	}
	if neg < 400 {
		t.Errorf("Less then 400 neg numbers: %d", neg)
	}
}

// Test LR instruction.
func (cw *cornwellFixture) TestCycleLR(t *testing.T) {
	cw.setup()
	cw.setMemory(0x400, 0x18310000) // LR 3,1
	cw.c.GR[1] = 0x12345678
	cw.testInst(0)
	if cw.c.GR[3] != 0x12345678 {
		t.Errorf("LR register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], 0x12345678)
	}
	if cw.c.GR[1] != 0x12345678 {
		t.Errorf("LR register 1 was incorrect got: %08x wanted: %08x", cw.c.GR[1], 0x12345678)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("LR CC changed got: %x wanted: %x", cw.c.PSW.CC, 3)
	}
}

// Test LTR instruction.
func (cw *cornwellFixture) TestCycleLTR(t *testing.T) {
	cw.setup()
	cw.setMemory(0x400, 0x12340000) // LTR 3,4
	// Test negative number
	cw.c.GR[4] = 0xcdef1234
	cw.testInst(0)
	if cw.c.GR[3] != 0xcdef1234 {
		t.Errorf("LTR register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], 0x12345678)
	}
	if cw.c.GR[4] != 0xcdef1234 {
		t.Errorf("LTR register 4 was incorrect got: %08x wanted: %08x", cw.c.GR[4], 0xcdef1234)
	}
	if cw.c.PSW.CC != 1 {
		t.Errorf("LTR CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}

	// Test zero
	cw.c.GR[4] = 0x00000000
	cw.testInst(0)
	if cw.c.GR[3] != 0x00000000 {
		t.Errorf("LTR register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], 0x00000000)
	}
	if cw.c.GR[4] != 0x00000000 {
		t.Errorf("LTR register 4 was incorrect got: %08x wanted: %08x", cw.c.GR[4], 0x00000000)
	}
	if cw.c.PSW.CC != 0 {
		t.Errorf("LTR CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}

	// Test positive
	cw.c.GR[4] = 0x12345678
	cw.testInst(0)
	if cw.c.GR[3] != 0x12345678 {
		t.Errorf("LTR register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], 0x12345678)
	}
	if cw.c.GR[4] != 0x12345678 {
		t.Errorf("LTR register 4 was incorrect got: %08x wanted: %08x", cw.c.GR[4], 0x12345678)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("LTR CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}
}

// Test LCR instruction.
func (cw *cornwellFixture) TestCycleLCR(t *testing.T) {
	cw.setup()
	cw.setMemory(0x400, 0x13340000) // LCR 3,4

	// Test positive
	cw.c.GR[4] = 0x00001000
	cw.testInst(0)
	if cw.c.GR[3] != 0xfffff000 {
		t.Errorf("LCR register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], 0xfffff000)
	}
	if cw.c.GR[4] != 0x00001000 {
		t.Errorf("LCR register 4 was incorrect got: %08x wanted: %08x", cw.c.GR[4], 0x00001000)
	}
	if cw.c.PSW.CC != 1 {
		t.Errorf("LCR CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}

	// Test negative number
	cw.c.GR[4] = 0xffffffff
	cw.testInst(0)
	if cw.c.GR[3] != 0x00000001 {
		t.Errorf("LCR register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], 0x00000001)
	}
	if cw.c.GR[4] != 0xffffffff {
		t.Errorf("LCR register 4 was incorrect got: %08x wanted: %08x", cw.c.GR[4], 0xffffffff)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("LCR CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}

	// Test zero
	cw.c.GR[4] = 0x00000000
	cw.testInst(0)
	if cw.c.GR[3] != 0x00000000 {
		t.Errorf("LCR register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], 0x00000000)
	}
	if cw.c.GR[4] != 0x00000000 {
		t.Errorf("LCR register 4 was incorrect got: %08x wanted: %08x", cw.c.GR[4], 0x00000000)
	}
	if cw.c.PSW.CC != 0 {
		t.Errorf("LCR CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}

	// Test overflow
	cw.c.GR[4] = 0x80000000
	cw.testInst(0)
	if cw.c.GR[3] != 0x80000000 {
		t.Errorf("LCR register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], 0x80000000)
	}
	if cw.c.GR[4] != 0x80000000 {
		t.Errorf("LCR register 4 was incorrect got: %08x wanted: %08x", cw.c.GR[4], 0x80000000)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("LCR CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}
}

// Test LPR instruction.
func (cw *cornwellFixture) TestCycleLPR(t *testing.T) {
	cw.setup()
	cw.setMemory(0x400, 0x10340000) // LPR 3,4

	// Test positive
	cw.c.GR[4] = 0x00000001
	cw.testInst(0)
	if cw.c.GR[3] != 0x00000001 {
		t.Errorf("LPR register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], 0x00000001)
	}
	if cw.c.GR[4] != 0x00000001 {
		t.Errorf("LPR register 4 was incorrect got: %08x wanted: %08x", cw.c.GR[4], 0x00000001)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("LPR CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}

	// Test negative number
	cw.c.GR[4] = 0xffffffff
	cw.testInst(0)
	if cw.c.GR[3] != 0x00000001 {
		t.Errorf("LPR register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], 0x00000001)
	}
	if cw.c.GR[4] != 0xffffffff {
		t.Errorf("LPR register 4 was incorrect got: %08x wanted: %08x", cw.c.GR[4], 0xffffffff)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("LPR CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}

	// Test zero
	cw.c.GR[4] = 0x00000000
	cw.testInst(0)
	if cw.c.GR[3] != 0x00000000 {
		t.Errorf("LPR register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], 0x00000000)
	}
	if cw.c.GR[4] != 0x00000000 {
		t.Errorf("LPR register 4 was incorrect got: %08x wanted: %08x", cw.c.GR[4], 0x00000000)
	}
	if cw.c.PSW.CC != 0 {
		t.Errorf("LPR CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}

	// Test overflow
	cw.c.GR[4] = 0x80000000
	cw.testInst(0)
	if cw.c.GR[3] != 0x80000000 {
		t.Errorf("LPR register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], 0x80000000)
	}
	if cw.c.GR[4] != 0x80000000 {
		t.Errorf("LPR register 4 was incorrect got: %08x wanted: %08x", cw.c.GR[4], 0x80000000)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("LPR CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}
}

// Test LNR instruction.
func (cw *cornwellFixture) TestCycleLNR(t *testing.T) {
	cw.setup()
	cw.setMemory(0x400, 0x11340000) // LNR 3,4

	// Test positive
	cw.c.GR[4] = 0x00000001
	cw.testInst(0)
	if cw.c.GR[3] != 0xffffffff {
		t.Errorf("LNR register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], 0xffffffff)
	}
	if cw.c.GR[4] != 0x00000001 {
		t.Errorf("LNR register 4 was incorrect got: %08x wanted: %08x", cw.c.GR[4], 0x00000001)
	}
	if cw.c.PSW.CC != 1 {
		t.Errorf("LNR CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}

	// Test negative number
	cw.c.GR[4] = 0xffffffff
	cw.testInst(0)
	if cw.c.GR[3] != 0xffffffff {
		t.Errorf("LNR register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], 0xffffffff)
	}
	if cw.c.GR[4] != 0xffffffff {
		t.Errorf("LNR register 4 was incorrect got: %08x wanted: %08x", cw.c.GR[4], 0xffffffff)
	}
	if cw.c.PSW.CC != 1 {
		t.Errorf("LNR CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}

	// Test zero
	cw.c.GR[4] = 0x00000000
	cw.testInst(0)
	if cw.c.GR[3] != 0x00000000 {
		t.Errorf("LNR register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], 0x00000000)
	}
	if cw.c.GR[4] != 0x00000000 {
		t.Errorf("LNR register 4 was incorrect got: %08x wanted: %08x", cw.c.GR[4], 0x00000000)
	}
	if cw.c.PSW.CC != 0 {
		t.Errorf("LNR CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}

	// Test overflow
	cw.c.GR[4] = 0x80000000
	cw.testInst(0)
	if cw.c.GR[3] != 0x80000000 {
		t.Errorf("LNR register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], 0x80000000)
	}
	if cw.c.GR[4] != 0x80000000 {
		t.Errorf("LNR register 4 was incorrect got: %08x wanted: %08x", cw.c.GR[4], 0x80000000)
	}
	if cw.c.PSW.CC != 1 {
		t.Errorf("LNR CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}
}

// Test L instruction.
func (cw *cornwellFixture) TestCycleL(t *testing.T) {
	cw.setup()
	cw.c.GR[3] = 0xffffffff
	cw.c.GR[4] = 0x1000
	cw.c.GR[5] = 0x200
	cw.setMemory(0x1b84, 0x12345678)
	cw.setMemory(0x400, 0x58345984) // L 3,984(4,5)
	cw.testInst(0)
	if cw.c.GR[3] != 0x12345678 {
		t.Errorf("L register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], 0x12345678)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("L CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	// Test negative number
	cw.c.PSW.CC = 3
	cw.c.GR[3] = 0xffffffff
	cw.c.GR[4] = 0x1000
	cw.c.GR[5] = 0x200
	cw.setMemory(0x1b84, 0x92345678)
	cw.setMemory(0x400, 0x58345984) // L 3,984(4,5)
	cw.testInst(0)
	if cw.c.GR[3] != 0x92345678 {
		t.Errorf("L register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], 0x92345678)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("L CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	// Test zero
	cw.c.PSW.CC = 3
	cw.c.GR[3] = 0xffffffff
	cw.c.GR[4] = 0x1000
	cw.c.GR[5] = 0x200
	cw.setMemory(0x1984, 0x00000000)
	cw.setMemory(0x400, 0x58340984) // L 3,984(4)
	cw.testInst(0)
	if cw.c.GR[3] != 0x00000000 {
		t.Errorf("L register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], 0x00000000)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("L CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	// Test load off alignment
	cw.c.PSW.CC = 3
	cw.c.GR[3] = 0xffffffff
	cw.c.GR[4] = 0x1001
	cw.c.GR[5] = 0x200
	cw.setMemory(0x1b84, 0xff123456)
	cw.setMemory(0x1b88, 0x78ffffff)
	cw.setMemory(0x400, 0x58345984) // L 3,984(4,5)
	cw.testInst(0)

	if cw.c.GR[3] != 0x12345678 {
		t.Errorf("L register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], 0x12345678)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("L CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	cw.c.PSW.CC = 3
	cw.c.GR[3] = 0xffffffff
	cw.c.GR[4] = 0x1002
	cw.c.GR[5] = 0x200
	cw.setMemory(0x1984, 0xffff1234)
	cw.setMemory(0x1988, 0x5678ffff)
	cw.setMemory(0x400, 0x58340984) // L 3,984(4)
	cw.testInst(0)

	if cw.c.GR[3] != 0x12345678 {
		t.Errorf("L register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], 0x12345678)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("L CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}
	cw.c.GR[3] = 0xffffffff
	cw.c.GR[4] = 0x1003
	cw.c.GR[5] = 0x200
	cw.setMemory(0x1984, 0xffffff12)
	cw.setMemory(0x1988, 0x345678ff)
	cw.setMemory(0x400, 0x58304984) // L 3,984(4)
	cw.testInst(0)

	if cw.c.GR[3] != 0x12345678 {
		t.Errorf("L register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], 0x12345678)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("L CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}
}

// Test Add register.
func (cw *cornwellFixture) TestCycleA(t *testing.T) {
	cw.setup()
	cw.setMemory(0x400, 0x1A120000) // AR 1,2

	// Test positive
	cw.c.GR[1] = 0x12345678
	cw.c.GR[2] = 0x00000005
	cw.testInst(0)
	if cw.c.GR[1] != 0x1234567d {
		t.Errorf("AR register 1 was incorrect got: %08x wanted: %08x", cw.c.GR[1], 0x1234567d)
	}
	if cw.c.GR[2] != 0x00000005 {
		t.Errorf("AR register 2 was incorrect got: %08x wanted: %08x", cw.c.GR[2], 0x00000005)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("AR CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}

	cw.c.PSW.CC = 3
	// Test negative number
	cw.c.GR[1] = 0x81234567
	cw.c.GR[2] = 0x00000001
	cw.testInst(0)
	if cw.c.GR[1] != 0x81234568 {
		t.Errorf("AR register 1 was incorrect got: %08x wanted: %08x", cw.c.GR[1], 0x81234568)
	}
	if cw.c.GR[2] != 0x00000001 {
		t.Errorf("AR register 2 was incorrect got: %08x wanted: %08x", cw.c.GR[2], 0x00000001)
	}
	if cw.c.PSW.CC != 1 {
		t.Errorf("AR CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}

	cw.c.PSW.CC = 3
	// Test zero
	cw.c.GR[1] = 0x00000002
	cw.c.GR[2] = 0xfffffffe
	cw.testInst(0)
	if cw.c.GR[1] != 0x00000000 {
		t.Errorf("AR register 1 was incorrect got: %08x wanted: %08x", cw.c.GR[1], 0x00000000)
	}
	if cw.c.GR[2] != 0xfffffffe {
		t.Errorf("AR register 2 was incorrect got: %08x wanted: %08x", cw.c.GR[2], 0xfffffffe)
	}
	if cw.c.PSW.CC != 0 {
		t.Errorf("AR CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}

	cw.c.PSW.CC = 3
	// Test overflow
	cw.c.GR[1] = 0x7fffffff
	cw.c.GR[2] = 0x00000001
	cw.testInst(0)
	if cw.c.GR[1] != 0x80000000 {
		t.Errorf("AR register 1 was incorrect got: %08x wanted: %08x", cw.c.GR[1], 0x80000000)
	}
	if cw.c.GR[2] != 0x00000001 {
		t.Errorf("AR register 2 was incorrect got: %08x wanted: %08x", cw.c.GR[2], 0x00000001)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("AR CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x1A121A31) // AR 1,2 AR 3,1
	cw.c.GR[1] = 0x12345678
	cw.c.GR[2] = 0x00000001
	cw.c.GR[3] = 0x00000010
	cw.testInst(0)
	if cw.c.GR[1] != 0x12345679 {
		t.Errorf("AR 2 register 1 was incorrect got: %08x wanted: %08x", cw.c.GR[1], 0x12345679)
	}
	if cw.c.GR[2] != 0x00000001 {
		t.Errorf("AR 2 register 2 was incorrect got: %08x wanted: %08x", cw.c.GR[2], 0x00000001)
	}
	if cw.c.GR[3] != 0x12345689 {
		t.Errorf("AR 2 register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], 0x12345689)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("AR CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}
	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x1a120000) // AR 1,2
	cw.c.GR[1] = 0x7fffffff
	cw.c.GR[2] = 0x00000001
	cw.testInst(8)
	psw1 := cw.getMemory(0x28)
	psw2 := cw.getMemory(0x2c)
	if !cw.trap {
		t.Errorf("AR 3 did not trap")
	}
	if cw.c.GR[1] != 0x80000000 {
		t.Errorf("AR 3 register 1 was incorrect got: %08x wanted: %08x", cw.c.GR[1], 0x80000000)
	}
	if cw.c.GR[2] != 0x00000001 {
		t.Errorf("AR 3 register 2 was incorrect got: %08x wanted: %08x", cw.c.GR[2], 0x00000001)
	}
	if cw.c.PSW.CC != 0 {
		t.Errorf("AR 3 CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}
	if psw1 != 0x00000008 {
		t.Errorf("AR 3 psw1 was incorrect got: %08x wanted: %08x", psw1, 0x00000008)
	}
	if psw2 != 0x78000402 {
		t.Errorf("AR 3 psw2 was incorrect got: %08x wanted: %08x", psw2, 0x78000402)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x5a156200) // AR 1,200(5,6)
	cw.c.GR[1] = 0x12345678
	cw.c.GR[5] = 0x00000100
	cw.c.GR[6] = 0x00000200
	cw.setMemory(0x500, 0x34567890)
	cw.testInst(0)
	s := uint32(0x12345678) + uint32(0x34567890)
	if cw.c.GR[1] != s {
		t.Errorf("A register 1 was incorrect got: %08x wanted: %08x", cw.c.GR[1], s)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("A CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}

	// Test add with random values
	rnum := rand.New(rand.NewSource(42))

	for range testCycles {
		cw.c.PSW.CC = 3
		n1 := rnum.Int31()
		n2 := rnum.Int31()
		r := int64(n1) + int64(n2)
		ur := uint64(r)
		sum := uint32(ur & FDMASK)
		cw.c.GR[1] = uint32(n1)
		cw.setMemory(0x100, uint32(n2))
		cw.setMemory(0x400, 0x5a100100) // A 1,100(0,0)
		cw.testInst(0)

		switch x := r; {
		case x == 0: // Zero
			if cw.c.PSW.CC != 0 {
				t.Errorf("A rand not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
			}
		case x > 0: // Positive
			if (ur & HDMASK) != 0 {
				if cw.c.PSW.CC != 3 {
					t.Errorf("A rand not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
				}
				if cw.c.GR[1] != sum {
					t.Errorf("A rand over register 1 was incorrect got: %08x wanted: %08x", cw.c.GR[1], sum)
				}
				continue
			}
			if cw.c.PSW.CC != 2 {
				t.Errorf("A rand not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
			}
		default: // Negative
			if (ur & HDMASK) != HDMASK {
				if cw.c.PSW.CC != 3 {
					t.Errorf("A rand not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
				}
				if cw.c.GR[1] != sum {
					t.Errorf("A rand over register 1 was incorrect got: %08x wanted: %08x", cw.c.GR[1], sum)
				}
				continue
			}
			if cw.c.PSW.CC != 1 {
				t.Errorf("A rand not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
			}
		}
		if cw.c.GR[1] != sum {
			t.Errorf("A rand register 1 was incorrect got: %08x wanted: %08x", cw.c.GR[1], sum)
		}
	}
}

// Second test of Add Half.
func (cw *cornwellFixture) TestCycleAH1(t *testing.T) {
	cw.setup()
	cw.setMemory(0x400, 0x4a156200) // AH 1,200(5,6)
	cw.c.GR[1] = 0x12345678
	cw.c.GR[5] = 0x00000100
	cw.c.GR[6] = 0x00000202
	cw.setMemory(0x500, 0x34567890)
	cw.testInst(0)
	s := uint32(0x12345678) + uint32(0x7890)
	if cw.c.GR[1] != s {
		t.Errorf("AH register 1 was incorrect got: %08x wanted: %08x", cw.c.GR[1], s)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("AH CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}

	// Sign extend
	cw.setMemory(0x400, 0x4a156200) // AH 1,200(5,6)
	cw.c.GR[1] = 0x00000001
	cw.c.GR[5] = 0x00000100
	cw.c.GR[6] = 0x00000200
	cw.setMemory(0x500, 0xfffe1234)
	cw.testInst(0)
	if cw.c.GR[1] != 0xffffffff {
		t.Errorf("AH register 1 was incorrect got: %08x wanted: %08x", cw.c.GR[1], 0xffffffff)
	}
	if cw.c.PSW.CC != 1 {
		t.Errorf("AH CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}
}

// Test Add Logical.
func (cw *cornwellFixture) TestCycleAL(t *testing.T) {
	cw.setup()
	cw.setMemory(0x400, 0x1e120000) // ALR 1,2
	cw.c.GR[1] = 0x00000000
	cw.c.GR[2] = 0x00000000
	cw.testInst(0)

	if cw.c.GR[1] != 0x00000000 {
		t.Errorf("ALR register 1 was incorrect got: %08x wanted: %08x", cw.c.GR[1], 0x00000000)
	}
	if cw.c.PSW.CC != 0 {
		t.Errorf("ALR CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x1e120000) // ALR 1,2
	cw.c.GR[1] = 0xffff0000
	cw.c.GR[2] = 0x00000002
	cw.testInst(0)

	if cw.c.GR[1] != 0xffff0002 {
		t.Errorf("ALR register 1 was incorrect got: %08x wanted: %08x", cw.c.GR[1], 0xffff0002)
	}
	if cw.c.PSW.CC != 1 {
		t.Errorf("ALR CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x1e120000) // ALR 1,2
	cw.c.GR[1] = 0xfffffffe
	cw.c.GR[2] = 0x00000002
	cw.testInst(0)

	if cw.c.GR[1] != 0x00000000 {
		t.Errorf("ALR register 1 was incorrect got: %08x wanted: %08x", cw.c.GR[1], 0x00000000)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("ALR CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x1e120000) // ALR 1,2
	cw.c.GR[1] = 0xfffffffe
	cw.c.GR[2] = 0x00000003
	cw.testInst(0)

	if cw.c.GR[1] != 0x00000001 {
		t.Errorf("ALR register 1 was incorrect got: %08x wanted: %08x", cw.c.GR[1], 0x00000001)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("ALR CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	// Sign extend
	cw.setMemory(0x400, 0x5e156200) // AL 1,200(5,6)
	cw.c.GR[1] = 0x12345678
	cw.c.GR[5] = 0x00000100
	cw.c.GR[6] = 0x00000200
	cw.setMemory(0x500, 0xf0000000)
	cw.testInst(0)
	if cw.c.GR[1] != 0x02345678 {
		t.Errorf("ALR register 1 was incorrect got: %08x wanted: %08x", cw.c.GR[1], 0x02345678)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("ALR CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	// Test add logical with random values
	rnum := rand.New(rand.NewSource(125))

	for range testCycles {
		cw.c.PSW.CC = 3
		n1 := rnum.Int31()
		n2 := rnum.Int31()
		ur := (uint64(n1) & LMASKL) + (uint64(n2) & LMASKL)
		sum := uint32(ur & LMASKL)
		cw.c.GR[1] = uint32(n1)
		cw.setMemory(0x100, uint32(n2))
		cw.setMemory(0x400, 0x5e100100) // AL 1,100(0,0)
		cc := uint8(0)
		if (ur & 0x100000000) != 0 {
			cc = 2
			ur &= 0x0ffffffff
		}
		if ur != 0 {
			cc++
		}
		cw.testInst(0)

		if cw.c.PSW.CC != cc {
			t.Errorf("AL rand not correct got: %x wanted: %x", cw.c.PSW.CC, cc)
		}
		if cw.c.GR[1] != sum {
			t.Errorf("AL rand register 1 was incorrect got: %08x wanted: %08x", cw.c.GR[1], sum)
		}
	}
}

// Test subtract instruction.
func (cw *cornwellFixture) TestCycleS(t *testing.T) {
	cw.setup()
	cw.setMemory(0x400, 0x1b120000) // SR 1,2
	cw.c.GR[1] = 0x12345678
	cw.c.GR[2] = 0x00000001
	cw.testInst(0)
	if cw.c.GR[1] != 0x12345677 {
		t.Errorf("S register 1 was incorrect got: %08x wanted: %08x", cw.c.GR[1], 0x12345677)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("S CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x5b156200) // S 1,200(5,6)
	cw.setMemory(0x500, 0x12300000)
	cw.c.GR[1] = 0x12345678
	cw.c.GR[5] = 0x00000100
	cw.c.GR[6] = 0x00000200
	cw.testInst(0)

	if cw.c.GR[1] != 0x00045678 {
		t.Errorf("S register 1 was incorrect got: %08x wanted: %08x", cw.c.GR[1], 0x00045678)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("S CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x1b110000) // SR 1,1
	cw.c.GR[1] = 0x8fffffff
	cw.testInst(0)

	if cw.c.GR[1] != 0x00000000 {
		t.Errorf("S register 1 was incorrect got: %08x wanted: %08x", cw.c.GR[1], 0x00000000)
	}
	if cw.c.PSW.CC != 0 {
		t.Errorf("S CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x1b110000) // SR 1,1
	cw.c.GR[1] = 0xffffffff
	cw.testInst(0)

	if cw.c.GR[1] != 0x00000000 {
		t.Errorf("S register 1 was incorrect got: %08x wanted: %08x", cw.c.GR[1], 0x00000000)
	}
	if cw.c.PSW.CC != 0 {
		t.Errorf("S CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}

	cw.setMemory(0x400, 0x1b110000) // SR 1,1
	cw.c.GR[1] = 0x80000000
	cw.testInst(0)
	if cw.c.GR[1] != 0x00000000 {
		t.Errorf("S register 1 was incorrect got: %08x wanted: %08x", cw.c.GR[1], 0x00000000)
	}
	if cw.c.PSW.CC != 0 {
		t.Errorf("S CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}

	// Test multiply with random values
	rnum := rand.New(rand.NewSource(42))

	for range testCycles {
		cw.c.PSW.CC = 3
		n1 := rnum.Int31()
		n2 := rnum.Int31()
		r := n1 - n2
		ur := uint64(r)
		diff := uint32(n1) - uint32(n2)
		cw.c.GR[1] = uint32(n1)
		cw.setMemory(0x100, uint32(n2))
		cw.setMemory(0x400, 0x5b100100) // S 1,100(0,0)
		cw.testInst(0)

		switch x := r; {
		case x == 0: // Zero
			if cw.c.PSW.CC != 0 {
				t.Errorf("S rand not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
			}
		case x > 0: // Positive
			if (ur & HDMASK) != 0 {
				if cw.c.PSW.CC != 3 {
					t.Errorf("S rand not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
				}
				if cw.c.GR[1] != diff {
					t.Errorf("S rand over register 1 was incorrect got: %08x wanted: %08x", cw.c.GR[1], diff)
				}
				continue
			}
			if cw.c.PSW.CC != 2 {
				t.Errorf("S rand not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
			}
		default: // Negative
			if (ur & HDMASK) != HDMASK {
				if cw.c.PSW.CC != 3 {
					t.Errorf("S rand not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
				}
				if cw.c.GR[1] != diff {
					t.Errorf("S rand over register 1 was incorrect got: %08x wanted: %08x", cw.c.GR[1], diff)
				}
				continue
			}
			if cw.c.PSW.CC != 1 {
				t.Errorf("S rand not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
			}
		}
		if cw.c.GR[1] != diff {
			t.Errorf("S rand register 1 was incorrect got: %08x wanted: %08x", cw.c.GR[1], diff)
		}
	}
}

// Test AH instruction.
func (cw *cornwellFixture) TestCycleAH(t *testing.T) {
	cw.setup()
	// Test add half positive
	cw.setMemory(0x400, 0x4a300200) // AH 3,200(0,0)
	cw.setMemory(0x200, 0x1234eeee)
	cw.c.GR[3] = 0x12345678
	cw.testInst(0)

	v := cw.c.GR[3]
	r := uint32(0x12345678 + 0x1234)
	if v != r {
		t.Errorf("AH Register changed got: %08x wanted: %08x", v, r)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("AH CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}

	// Test add half sign extend
	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x4a300200) // AH 3,200(0,0)
	cw.setMemory(0x200, 0xfffe9999) // -2
	cw.c.GR[3] = 0x12345678
	cw.testInst(0)

	v = cw.c.GR[3]
	r = uint32(0x12345676)
	if v != r {
		t.Errorf("AH Register changed got: %08x wanted: %08x", v, r)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("AH CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}
}

// Test Subtract half.
func (cw *cornwellFixture) TestCycleSH(t *testing.T) {
	cw.setup()
	cw.setMemory(0x400, 0x4b156200) // SH 1,200(5,6)
	cw.setMemory(0x500, 0x1230ffff)
	cw.c.GR[1] = 0x12345678
	cw.c.GR[5] = 0x00000100
	cw.c.GR[6] = 0x00000200
	cw.testInst(0)
	s := uint32(0x12345678) - uint32(0x1230)
	if cw.c.GR[1] != s {
		t.Errorf("SH register 1 was incorrect got: %08x wanted: %08x", cw.c.GR[1], s)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("SH CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}
}

// Test Subtract logical.
func (cw *cornwellFixture) TestCycleSL(t *testing.T) {
	cw.setup()
	cw.setMemory(0x400, 0x1f120000) // SLR 1,2
	cw.c.GR[1] = 0x12345678
	cw.c.GR[2] = 0x12345678
	cw.testInst(0)
	if cw.c.GR[1] != 0x00000000 {
		t.Errorf("SL register 1 was incorrect got: %08x wanted: %08x", cw.c.GR[1], 0x00000000)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("SL CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x5f156200) // SL 1,200(5,6)
	cw.c.GR[1] = 0xffffffff
	cw.c.GR[5] = 0x00000100
	cw.c.GR[6] = 0x00000200
	cw.setMemory(0x500, 0x11111111)
	cw.testInst(0)
	if cw.c.GR[1] != 0xeeeeeeee {
		t.Errorf("SL register 1 was incorrect got: %08x wanted: %08x", cw.c.GR[1], 0xeeeeeeee)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("SL CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x5f156200) // SL 1,200(5,6)
	cw.c.GR[1] = 0x12345678
	cw.c.GR[5] = 0x00000100
	cw.c.GR[6] = 0x00000200
	cw.setMemory(0x500, 0x23456789)
	cw.testInst(0)
	if cw.c.GR[1] != 0xeeeeeeef {
		t.Errorf("SL register 1 was incorrect got: %08x wanted: %08x", cw.c.GR[1], 0xeeeeeeef)
	}
	if cw.c.PSW.CC != 1 {
		t.Errorf("SL CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}
	// // Test add logical with random values
	rnum := rand.New(rand.NewSource(44))

	for range testCycles {
		cw.c.PSW.CC = 3
		n1 := uint32(rnum.Int31())
		n2 := uint32(rnum.Int31())
		n3 := ^n2                          // Negate n2
		sum := uint64(n1) + uint64(n3) + 1 // Sum
		cw.c.GR[1] = n1
		cw.setMemory(0x100, n2)
		cw.setMemory(0x400, 0x5f100100) // SL 1,100(0,0)
		// Compute resulting cc flags
		cc := uint8(0)
		if (sum & 0x100000000) != 0 {
			cc = 2
			// r &= 0x0ffffffff
		}
		if sum != 0 {
			cc++
		}

		cw.testInst(0)

		if cw.c.PSW.CC != cc {
			t.Errorf("SL rand not correct got: %x wanted: %x", cw.c.PSW.CC, cc)
		}
		if cw.c.GR[1] != uint32(sum&LMASKL) {
			t.Errorf("SL rand register 1 was incorrect got: %08x wanted: %08x", cw.c.GR[1], sum)
		}
	}
}

func (cw *cornwellFixture) TestCycleC(t *testing.T) {
	cw.setup()
	cw.setMemory(0x400, 0x19120000) // CR 1,2
	cw.c.GR[1] = 0x12345678
	cw.c.GR[2] = 0x12345678
	cw.testInst(0)
	if cw.c.GR[1] != 0x12345678 {
		t.Errorf("CR register 1 was incorrect got: %08x wanted: %08x", cw.c.GR[1], 0x12345678)
	}
	if cw.c.PSW.CC != 0 {
		t.Errorf("CR CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x19120000) // CR 1,2
	cw.c.GR[1] = 0xfffffffe         // -2
	cw.c.GR[2] = 0xfffffffd         // -3
	cw.testInst(0)
	if cw.c.GR[1] != 0xfffffffe {
		t.Errorf("CR register 1 was incorrect got: %08x wanted: %08x", cw.c.GR[1], 0xfffffffe)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("CR CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x19120000) // CR 1,2
	cw.c.GR[1] = 2
	cw.c.GR[2] = 3
	cw.testInst(0)
	if cw.c.GR[1] != 2 {
		t.Errorf("CR register 1 was incorrect got: %08x wanted: %08x", cw.c.GR[1], 2)
	}
	if cw.c.PSW.CC != 1 {
		t.Errorf("CR CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}
	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x59156200) // C 1,200(5,6)
	cw.setMemory(0x500, 0x12345678)
	cw.c.GR[1] = 0xf0000000
	cw.c.GR[5] = 0x00000100
	cw.c.GR[6] = 0x00000200
	cw.testInst(0)

	if cw.c.GR[1] != 0xf0000000 {
		t.Errorf("C register 1 was incorrect got: %08x wanted: %08x", cw.c.GR[1], 0xf0000000)
	}
	if cw.c.PSW.CC != 1 {
		t.Errorf("C CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}
}

// Test CL instruction.
func (cw *cornwellFixture) TestCycleCL(t *testing.T) {
	cw.setup()
	// Test compare half equal
	cw.setMemory(0x400, 0x55123400) // CL 1,400(2,3)
	cw.setMemory(0x404, 0)
	cw.setMemory(0x900, 0x12345678)
	cw.c.GR[1] = 0x12345678
	cw.c.GR[2] = 0x200
	cw.c.GR[3] = 0x300
	cw.testInst(0)

	v := cw.c.GR[1]
	if v != 0x12345678 {
		t.Errorf("CL Register changed got: %08x wanted: %08x", v, 0x12345678)
	}
	if cw.c.PSW.CC != 0 {
		t.Errorf("CL CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}

	// Compare logical register
	cw.c.PSW.CC = 3
	cw.c.GR[1] = 0x12345678
	cw.c.GR[2] = 0x12345678
	cw.setMemory(0x400, 0x15120000) // CLR 1,2
	cw.testInst(0)
	if cw.c.PSW.CC != 0 {
		t.Errorf("CL CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}

	cw.c.PSW.CC = 3
	cw.c.GR[1] = 0x12345678
	cw.c.GR[2] = 0x12345679
	cw.setMemory(0x400, 0x15120000) // CLR 1,2
	cw.testInst(0)
	if cw.c.PSW.CC != 1 {
		t.Errorf("CL CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}

	cw.c.PSW.CC = 3
	cw.c.GR[1] = 0x12345679
	cw.c.GR[2] = 0x12345678
	cw.setMemory(0x400, 0x15120000) // CLR 1,2
	cw.testInst(0)
	if cw.c.PSW.CC != 2 {
		t.Errorf("CL CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}

	cw.c.PSW.CC = 3
	cw.c.GR[1] = 0x7fffffff
	cw.c.GR[2] = 0x8fffffff
	cw.setMemory(0x400, 0x15120000) // CLR 1,2
	cw.testInst(0)
	if cw.c.PSW.CC != 1 {
		t.Errorf("CL CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}

	// Compare logical
	cw.c.PSW.CC = 3
	cw.c.GR[1] = 0x12345678
	cw.c.GR[2] = 0x100
	cw.c.GR[3] = 0x100
	cw.setMemory(0x300, 0x12345678)
	cw.setMemory(0x400, 0x55123100) // CL 1,100(2,3)
	cw.setMemory(0x404, 0x00000000)
	cw.testInst(0)
	if cw.c.PSW.CC != 0 {
		t.Errorf("CL CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}
}

// Test CH instruction.
func (cw *cornwellFixture) TestCycleCH(t *testing.T) {
	cw.setup()
	// Test compare half equal
	cw.setMemory(0x400, 0x49300100) // CH 3,100(0,0)
	cw.setMemory(0x100, 0x5678abcd)
	cw.c.GR[3] = 0x00005678
	cw.testInst(0)

	v := cw.c.GR[3]
	if v != 0x00005678 {
		t.Errorf("CH Register changed got: %08x wanted: %08x", v, 0x00005678)
	}
	if cw.c.PSW.CC != 0 {
		t.Errorf("CH CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}

	// Test compare half with sign extension
	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x49300100) // CH 3,100(0,0)
	cw.setMemory(0x100, 0x9678abcd)
	cw.c.GR[3] = 0xffff9678
	cw.testInst(0)

	if cw.c.PSW.CC != 0 {
		t.Errorf("CH CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}

	// Compare half word high
	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x49300100) // CH 3,100(0,0)
	cw.setMemory(0x100, 0x1234abcd)
	cw.c.GR[3] = 0x00001235
	cw.testInst(0)

	if cw.c.PSW.CC != 2 {
		t.Errorf("CH CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}

	// Compare half word sign extended
	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x49300100) // CH 3,100(0,0)
	cw.setMemory(0x100, 0x8234abcd)
	cw.c.GR[3] = 0x00001235
	cw.testInst(0)

	if cw.c.PSW.CC != 2 {
		t.Errorf("CH CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}

	// Compare half word low
	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x49300100) // CH 3,100(0,0)
	cw.setMemory(0x100, 0x1234abcd)
	cw.c.GR[3] = 0x80001235
	cw.testInst(0)

	if cw.c.PSW.CC != 1 {
		t.Errorf("CH CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}

	// Compare half lower extended
	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x49300100) // CH 3,100(0,0)
	cw.setMemory(0x100, 0xfffd0000)
	cw.c.GR[3] = 0xfffffffc
	cw.testInst(0)

	if cw.c.PSW.CC != 1 {
		t.Errorf("CH CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}
}

// Test Multiply instruction.
func (cw *cornwellFixture) TestCycleM(t *testing.T) {
	cw.setup()
	cw.setMemory(0x400, 0x1c240000) // MR 2,4
	cw.c.GR[2] = 0
	cw.c.GR[3] = 28
	cw.c.GR[4] = 19
	cw.testInst(0)
	if cw.c.GR[2] != 0 {
		t.Errorf("MR register 2 was incorrect got: %08x wanted: %08x", cw.c.GR[2], 0)
	}
	if cw.c.GR[3] != (28 * 19) {
		t.Errorf("MR register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], 28*16)
	}

	if cw.c.PSW.CC != 3 {
		t.Errorf("MR CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x1c240000) // MR 2,4
	cw.c.GR[2] = 0
	cw.c.GR[3] = 0x12345678
	cw.c.GR[4] = 0x34567890
	cw.testInst(0)
	if cw.c.GR[2] != 0x3b8c7b8 {
		t.Errorf("MR register 2 was incorrect got: %08x wanted: %08x", cw.c.GR[2], 0x3b8c7b8)
	}
	if cw.c.GR[3] != 0x3248e380 {
		t.Errorf("MR register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], 0x3248e380)
	}

	if cw.c.PSW.CC != 3 {
		t.Errorf("MR CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x1c240000) // MR 2,4
	cw.c.GR[2] = 0
	cw.c.GR[3] = 0x7fffffff
	cw.c.GR[4] = 0x7fffffff
	cw.testInst(0)
	if cw.c.GR[2] != 0x3fffffff {
		t.Errorf("MR register 2 was incorrect got: %08x wanted: %08x", cw.c.GR[2], 0x3fffffff)
	}
	if cw.c.GR[3] != 0x00000001 {
		t.Errorf("MR register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], 0x00000001)
	}

	if cw.c.PSW.CC != 3 {
		t.Errorf("MR CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x1c240000) // MR 2,4
	cw.c.GR[2] = 0
	cw.c.GR[3] = 0xfffffffc // -4
	cw.c.GR[4] = 0xfffffffb // -5
	cw.testInst(0)
	if cw.c.GR[2] != 0 {
		t.Errorf("MR register 2 was incorrect got: %08x wanted: %08x", cw.c.GR[2], 0)
	}
	if cw.c.GR[3] != 20 {
		t.Errorf("MR register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], 20)
	}

	if cw.c.PSW.CC != 3 {
		t.Errorf("MR CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x1c240000) // MR 2,4
	cw.c.GR[2] = 0
	cw.c.GR[3] = 0xfffffffc // -4
	cw.c.GR[4] = 0x0000000a // 10
	cw.testInst(0)
	if cw.c.GR[2] != 0xffffffff {
		t.Errorf("MR register 2 was incorrect got: %08x wanted: %08x", cw.c.GR[2], 0xffffffff)
	}
	if cw.c.GR[3] != 0xffffffd8 {
		t.Errorf("MR register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], 0xffffffd8)
	}

	if cw.c.PSW.CC != 3 {
		t.Errorf("MR CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x5c256200) // M 1,200(5,6)
	cw.setMemory(0x500, 0x34567890)
	cw.c.GR[2] = 0
	cw.c.GR[3] = 0x12345678
	cw.c.GR[5] = 0x00000100
	cw.c.GR[6] = 0x00000200
	cw.testInst(0)
	if cw.c.GR[2] != 0x03b8c7b8 {
		t.Errorf("M register 2 was incorrect got: %08x wanted: %08x", cw.c.GR[2], 0x03b8c7b8)
	}
	if cw.c.GR[3] != 0x3248e380 {
		t.Errorf("M register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], 0x3248e380)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("M CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	// Test multiply with random values
	rnum := rand.New(rand.NewSource(1))
	for range testCycles {
		cw.c.PSW.CC = 3
		n1 := rnum.Int31()
		n2 := rnum.Int31() // Keep both operands on the reproducible local stream.
		r := int64(n1) * int64(n2)
		h := uint32((uint64(r) >> 32) & uint64(FMASK))
		l := uint32(uint64(r) & uint64(FMASK))
		cw.c.GR[2] = 0
		cw.c.GR[3] = uint32(n1)
		cw.c.GR[4] = uint32(n2)
		cw.setMemory(0x400, 0x1c240000) // MR 2,4
		cw.testInst(0)
		if cw.c.GR[2] != h {
			t.Errorf("MR rand register 2 was incorrect got: %08x wanted: %08x", cw.c.GR[2], h)
		}
		if cw.c.GR[3] != l {
			t.Errorf("MR rand register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], l)
		}
		if cw.c.PSW.CC != 3 {
			t.Errorf("MR rand not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
		}
	}
}

func (cw *cornwellFixture) TestCycleMH(t *testing.T) {
	cw.setup()
	cw.setMemory(0x400, 0x4c356202) // MH 3,202(5,6)
	cw.setMemory(0x500, 0x00000003)
	cw.c.GR[2] = 0
	cw.c.GR[3] = 4
	cw.c.GR[5] = 0x00000100
	cw.c.GR[6] = 0x00000200
	cw.testInst(0)
	if cw.c.GR[2] != 0 {
		t.Errorf("MHregister 2 was incorrect got: %08x wanted: %08x", cw.c.GR[2], 0)
	}
	if cw.c.GR[3] != 12 {
		t.Errorf("MH register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], 12)
	}

	if cw.c.PSW.CC != 3 {
		t.Errorf("MH CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x4c250200) // MH 2,200(5)
	cw.setMemory(0x500, 0xffd91111) // -39
	cw.c.GR[2] = 0x00000015         // 21
	cw.c.GR[3] = 0x00000005
	cw.c.GR[5] = 0x00000300
	cw.c.GR[6] = 0x00000200
	cw.testInst(0)
	if cw.c.GR[2] != 0xfffffccd {
		t.Errorf("MHregister 2 was incorrect got: %08x wanted: %08x", cw.c.GR[2], 0xfffffccd)
	}
	if cw.c.GR[3] != 0x00000005 {
		t.Errorf("MH register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], 0x00000005)
	}

	if cw.c.PSW.CC != 3 {
		t.Errorf("MH CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}
}

func (cw *cornwellFixture) TestCycleD(t *testing.T) {
	cw.setup()
	cw.setMemory(0x400, 0x1d240000) // DR 2,4
	cw.c.GR[2] = 0x1
	cw.c.GR[3] = 0x12345678
	cw.c.GR[4] = 0x00000234
	// divide R2/R3 by R4
	cw.testInst(0)
	if cw.c.GR[2] != (0x112345678 % 0x234) {
		t.Errorf("DR register 2 was incorrect got: %08x wanted: %08x", cw.c.GR[2], 0x112345678%0x234)
	}
	if cw.c.GR[3] != (0x112345678 / 0x234) {
		t.Errorf("DR register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], 0x112345678/0x234)
	}

	if cw.c.PSW.CC != 3 {
		t.Errorf("DR CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x1d240000) // DR 2,4
	cw.c.GR[2] = 0x1
	cw.c.GR[3] = 0x12345678
	cw.c.GR[4] = 0xfffffdcc
	// divide R2/R3 by R4
	cw.testInst(0)
	if cw.c.GR[2] != (0x112345678 % 0x234) {
		t.Errorf("DR register 2 was incorrect got: %08x wanted: %08x", cw.c.GR[2], 0x112345678%0x234)
	}
	if cw.c.GR[3] != (((0x112345678 / 0x234) ^ FMASK) + 1) {
		t.Errorf("DR register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], ((0x112345678/0x234)^FMASK)+1)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("DR CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	// Divide big value
	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x1d240000) // DR 2,4
	cw.c.GR[2] = 0x00112233
	cw.c.GR[3] = 0x44556677
	cw.c.GR[4] = 0x12345678 // 0x1122334455667788 / 0x12345678
	// divide R2/R3 by R4
	cw.testInst(0)
	if cw.c.GR[2] != (0x11b3d5f7) {
		t.Errorf("DR register 2 was incorrect got: %08x wanted: %08x", cw.c.GR[2], 0x11b3d5f7)
	}
	if cw.c.GR[3] != 0x00f0f0f0 {
		t.Errorf("DR register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], 0x00f0f0f0)
	}

	if cw.c.PSW.CC != 3 {
		t.Errorf("DR CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x5d256200) // D 2,200(5,6)
	cw.setMemory(0x404, 0x00000000)
	cw.setMemory(0x500, 0x73456789)
	cw.c.GR[2] = 0x12345678
	cw.c.GR[3] = 0x9abcdef0
	cw.c.GR[5] = 0x00000100
	cw.c.GR[6] = 0x00000200
	cw.testInst(0)
	if cw.c.GR[2] != 0x50c0186a {
		t.Errorf("D register 2 was incorrect got: %08x wanted: %08x", cw.c.GR[2], 0x50c0186a)
	}
	if cw.c.GR[3] != 0x286dead6 {
		t.Errorf("D register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], 0x286dead6)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("D CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	// Divide overflow
	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x5d256200) // D 2,200(5,6)
	cw.setMemory(0x404, 0x00000000)
	cw.setMemory(0x800, 0x00000000)
	cw.setMemory(0x500, 0x23456789)
	cw.c.GR[2] = 0x12345678
	cw.c.GR[3] = 0x9abcdef0
	cw.c.GR[5] = 0x00000100
	cw.c.GR[6] = 0x00000200

	cw.testInst(0x8)
	if cw.c.GR[2] != 0x12345678 {
		t.Errorf("D register 2 was incorrect got: %08x wanted: %08x", cw.c.GR[2], 0x12345678)
	}
	if cw.c.GR[3] != 0x9abcdef0 {
		t.Errorf("D register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], 0x9abcdef0)
	}
	if !cw.trap {
		t.Errorf("D over did not trap")
	}

	// Test divide with random values
	rnum := rand.New(rand.NewSource(124))
	for range testCycles {
		cw.c.PSW.CC = 3
		dividend := rnum.Int63() / 1000
		divisor := rnum.Int31()
		q := dividend / int64(divisor)
		r := dividend % int64(divisor)

		cw.c.GR[2] = uint32(dividend >> 32)
		cw.c.GR[3] = uint32(uint64(dividend) & LMASKL)
		cw.setMemory(0x100, uint32(divisor))
		cw.setMemory(0x400, 0x5d200100) // D 2,100(0,0)
		cw.setMemory(0x404, 0x00000000)
		cw.setMemory(0x800, 0x00000000)
		cw.testInst(0)

		if divisor < 0 {
			r = -r
		}

		// Check if we should overflow.
		if (q & 0x7fffffff) != q {
			if !cw.trap {
				t.Errorf("D rand over did not trap")
			}
		} else {
			if cw.trap {
				t.Errorf("D rand no over trap")
			}
			if cw.c.GR[2] != uint32(r) {
				t.Logf("D %016x / %08x = %08x (%08x) %t", dividend, divisor, q, r, cw.trap)
				t.Errorf("D rand register 2 was incorrect got: %08x wanted: %08x", cw.c.GR[2], uint32(r))
			}
			if cw.c.GR[3] != uint32(q) {
				t.Errorf("D rand register 3 was incorrect got: %08x wanted: %08x", cw.c.GR[3], uint32(q))
			}
			if cw.c.PSW.CC != 3 {
				t.Errorf("D rand CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
			}
		}
	}
}

// Test Store Word.
func (cw *cornwellFixture) TestCycleST(t *testing.T) {
	cw.setup()
	cw.setMemory(0x400, 0x50123400) // ST 1,400(2,3)
	cw.setMemory(0x600, 0xffffffff)
	cw.c.GR[1] = 0x12345678
	cw.c.GR[2] = 0x100
	cw.c.GR[3] = 0x100
	// Store Half
	cw.testInst(0)

	v := cw.getMemory(0x600)
	if v != 0x12345678 {
		t.Errorf("ST Memory not correct got: %08x wanted: %08x", v, 0x12345678)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("ST CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	// Check store off align
	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x50123400) // ST 1,400(2,3)
	cw.setMemory(0x600, 0xffffffff)
	cw.setMemory(0x604, 0xffffffff)
	cw.c.GR[1] = 0x12345678
	cw.c.GR[2] = 0x101
	cw.c.GR[3] = 0x100
	// Store Half
	cw.testInst(0)

	v = cw.getMemory(0x600)
	if v != 0xff123456 {
		t.Errorf("ST Memory not correct got: %08x wanted: %08x", v, 0xff123456)
	}
	v = cw.getMemory(0x604)
	if v != 0x78ffffff {
		t.Errorf("ST Memory not correct got: %08x wanted: %08x", v, 0x78ffffff)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("ST CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x50123400) // ST 1,400(2,3)
	cw.setMemory(0x600, 0xffffffff)
	cw.setMemory(0x604, 0xffffffff)
	cw.c.GR[1] = 0x12345678
	cw.c.GR[2] = 0x102
	cw.c.GR[3] = 0x100
	// Store Half
	cw.testInst(0)

	v = cw.getMemory(0x600)
	if v != 0xffff1234 {
		t.Errorf("ST Memory not correct got: %08x wanted: %08x", v, 0xffff1234)
	}
	v = cw.getMemory(0x604)
	if v != 0x5678ffff {
		t.Errorf("ST Memory not correct got: %08x wanted: %08x", v, 0x5678ffff)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("ST CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x50123400) // ST 1,400(2,3)
	cw.setMemory(0x600, 0xffffffff)
	cw.setMemory(0x604, 0xffffffff)
	cw.c.GR[1] = 0x12345678
	cw.c.GR[2] = 0x103
	cw.c.GR[3] = 0x100
	// Store Half
	cw.testInst(0)

	v = cw.getMemory(0x600)
	if v != 0xffffff12 {
		t.Errorf("ST Memory not correct got: %08x wanted: %08x", v, 0xffffff12)
	}
	v = cw.getMemory(0x604)
	if v != 0x345678ff {
		t.Errorf("ST Memory not correct got: %08x wanted: %08x", v, 0x345678ff)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("ST CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}
}

// Test Store Half Word.
func (cw *cornwellFixture) TestCycleSTH(t *testing.T) {
	cw.setup()
	cw.setMemory(0x400, 0x40345ffe) // STH 2,ffe(4,5)
	cw.setMemory(0x1000, 0x12345678)
	cw.c.GR[3] = 0xaabbccdd
	cw.c.GR[4] = 1
	cw.c.GR[5] = 1
	// Store Half
	cw.testInst(0)

	v := cw.getMemory(0x1000)
	if v != 0xccdd5678 {
		t.Errorf("STH Memory not correct got: %08x wanted: %08x", v, 0xccdd5678)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("STH CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}
	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x40345ffe) // STH 2,ffe(4,5)
	cw.setMemory(0x1000, 0x12345678)
	cw.c.GR[3] = 0xaabbccdd
	cw.c.GR[4] = 1
	cw.c.GR[5] = 3
	// Store Half
	cw.testInst(0)

	v = cw.getMemory(0x1000)
	if v != 0x1234ccdd {
		t.Errorf("STH Memory not correct got: %08x wanted: %08x", v, 0x1234ccdd)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("STH CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}
	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x40345ffe) // STH 2,ffe(4,5)
	cw.setMemory(0x1000, 0x12345678)
	cw.c.GR[3] = 0xaabbccdd
	cw.c.GR[4] = 1
	cw.c.GR[5] = 2
	// Store Half
	cw.testInst(0)

	v = cw.getMemory(0x1000)
	if v != 0x12ccdd78 {
		t.Errorf("STH Memory not correct got: %08x wanted: %08x", v, 0x12ccdd78)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("STH CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}
	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x40345ffe) // STH 2,ffe(4,5)
	cw.setMemory(0x1000, 0x12345678)
	cw.setMemory(0x1004, 0x9abcdef0)
	cw.c.GR[3] = 0xaabbccdd
	cw.c.GR[4] = 1
	cw.c.GR[5] = 4
	// Store Half
	cw.testInst(0)

	v = cw.getMemory(0x1000)
	if v != 0x123456cc {
		t.Errorf("STH Memory not correct got: %08x wanted: %08x", v, 0x123456cc)
	}
	v = cw.getMemory(0x1004)
	if v != 0xddbcdef0 {
		t.Errorf("STH Memory not correct got: %08x wanted: %08x", v, 0xddbcdef0)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("STH CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}
}

// Test Load Half Word.
func (cw *cornwellFixture) TestCycleLH(t *testing.T) {
	cw.setup()
	cw.setMemory(0x400, 0x48345986) // LH 3,986(4,5)
	cw.setMemory(0x1b84, 0x87654321)
	cw.c.GR[3] = 0xffffffff
	cw.c.GR[4] = 0x1000
	cw.c.GR[5] = 0x200
	// Store Half
	cw.testInst(0)

	v := cw.c.GR[3]
	if v != 0x00004321 {
		t.Errorf("LH Memory not correct got: %08x wanted: %08x", v, 0x00004321)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("LH CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}
	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x48345984) // LH 3,984(4,5)
	cw.setMemory(0x1b84, 0x17654321)
	cw.c.GR[3] = 0xffffffff
	cw.c.GR[4] = 0x1000
	cw.c.GR[5] = 0x200
	// Store Half
	cw.testInst(0)

	v = cw.c.GR[3]
	if v != 0x00001765 {
		t.Errorf("LH Memory not correct got: %08x wanted: %08x", v, 0x00001765)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("LH CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}
	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x48345984) /// LH 3,984(4,5)
	cw.setMemory(0x1b84, 0x87654321)
	cw.c.GR[3] = 0xaabbccdd
	cw.c.GR[4] = 0x1000
	cw.c.GR[5] = 0x200
	// Store Half
	cw.testInst(0)

	v = cw.c.GR[3]
	if v != 0xffff8765 {
		t.Errorf("LH Memory not correct got: %08x wanted: %08x", v, 0xffff8765)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("LH CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}
	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x48345984) // LH 3,984(4,5)
	cw.setMemory(0x1b84, 0x87654321)
	cw.setMemory(0x1b88, 0xabcdef00)
	cw.c.GR[3] = 0xffffffff
	cw.c.GR[4] = 0x1000
	cw.c.GR[5] = 0x201
	// Store Half
	cw.testInst(0)

	v = cw.c.GR[3]
	if v != 0x00006543 {
		t.Errorf("LH Memory not correct got: %08x wanted: %08x", v, 0x00006543)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("LH CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}
	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x48345984) // LH 3,984(4,5)
	cw.setMemory(0x1b84, 0x87654321)
	cw.setMemory(0x1b88, 0xabcdef00)
	cw.c.GR[3] = 0xffffffff
	cw.c.GR[4] = 0x1000
	cw.c.GR[5] = 0x203
	// Store Half
	cw.testInst(0)

	v = cw.c.GR[3]
	if v != 0x000021ab {
		t.Errorf("LH Memory not correct got: %08x wanted: %08x", v, 0x000021ab)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("LH CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}
}

// Test LA.
func (cw *cornwellFixture) TestCycleLA(t *testing.T) {
	cw.setup()
	// From Princ Ops p147
	cw.setMemory(0x400, 0x41100800) // LA 1,800
	cw.c.GR[1] = 0xffffffff
	cw.testInst(0)
	v := cw.c.GR[1]
	if v != 2048 {
		t.Errorf("LA Register not correct got: %08x wanted: %08x", v, 2048)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("LA CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}
	// From Princ Ops p147
	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x4150500a) // LA 5, 10(5)
	cw.c.GR[5] = 0x00123456
	cw.testInst(0)

	v = cw.c.GR[5]
	if v != 0x00123460 {
		t.Errorf("LA Register not correct got: %08x wanted: %08x", v, 0x00123460)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("LA CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x4156500a) // LA 5, 10(6,5)
	cw.c.GR[5] = 0x00123456
	cw.c.GR[6] = 0x00000010
	cw.testInst(0)

	v = cw.c.GR[5]
	if v != 0x00123470 {
		t.Errorf("LA Register not correct got: %08x wanted: %08x", v, 0x00123470)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("LA CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x4155000a) // LA 5, 10(0,5)
	cw.c.GR[5] = 0x00123456
	cw.c.GR[6] = 0x00000010
	cw.testInst(0)

	v = cw.c.GR[5]
	if v != 0x00123460 {
		t.Errorf("LA Memory not correct got: %08x wanted: %08x", v, 0x00123460)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("LA CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}
}

// Test STC.
func (cw *cornwellFixture) TestCycleSTC(t *testing.T) {
	cw.setup()
	for i := range 4 { // Test all 4 offsets.
		cw.c.PSW.CC = 3
		cw.c.GR[5] = 0xffffff12
		cw.c.GR[1] = uint32(i)
		cw.setMemory(0x400, 0x42501100) // STC 5,100(0,1)
		cw.setMemory(0x100, 0xaabbccdd)
		cw.testInst(0)
		if cw.c.PSW.CC != 3 {
			t.Errorf("STC CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
		}
		v := cw.getMemory(0x100)
		shift := (3 - i) * 8
		desired := (uint32(0xaabbccdd) & ^(uint32(0xff) << shift)) | (uint32(0x12) << shift)

		if v != desired {
			t.Errorf("STC Memory not correct got: %08x wanted: %08x", v, desired)
		}
	}
}

// Test IC.
func (cw *cornwellFixture) TestCycleSIC(t *testing.T) {
	cw.setup()
	for i := range 4 { // Test all 4 offsets.
		cw.c.PSW.CC = 3
		cw.c.GR[5] = 0xaabbccdd
		cw.c.GR[1] = uint32(i)
		cw.setMemory(0x400, 0x43501100) // IC 5,100(0,1)
		cw.setMemory(0x100, 0x00112233)
		cw.testInst(0)
		if cw.c.PSW.CC != 3 {
			t.Errorf("IC CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
		}
		v := cw.getMemory(0x100)
		shift := (3 - i) * 8
		desired := (uint32(0x00112233) >> shift & 0xff) | 0x00112233

		if v != desired {
			t.Errorf("IC Memory not correct got: %08x wanted: %08x", v, desired)
		}
	}
}

// Test EX.
func (cw *cornwellFixture) TestCycleEX(t *testing.T) {
	cw.setup()
	cw.setMemory(0x100, 0x1a000000) // Target instruction AR 0,0
	cw.c.GR[1] = 0x00000045
	cw.c.GR[4] = 0x100
	cw.c.GR[5] = 0x200
	cw.setMemory(0x400, 0x44100100) // EX 1,100(0,0)
	cw.setMemory(0x404, 0x00000000) // Prevent fetch of next instruction
	cw.testInst(0)
	v := cw.c.GR[4]
	if v != 0x300 {
		t.Errorf("EX AR Register not correct got: %08x wanted: %08x", v, 0x300)
	}

	cw.setMemory(0x045, 0x1a000000) // Target instruction AR 0,0
	cw.setMemory(0x100, 0x44100000) // Target instruction EX 1,100(0,0)
	cw.c.GR[1] = 0x00000045
	cw.c.GR[4] = 0x100
	cw.c.GR[5] = 0x200
	cw.setMemory(0x400, 0x44100100) // EX 1,100(0,0)
	cw.setMemory(0x404, 0x00000000) // Prevent fetch of next instruction
	cw.testInst(0)

	if !cw.trap {
		t.Errorf("EX of EX did not trap")
	}
}

// Test BAL.
func (cw *cornwellFixture) TestCycleBAL(t *testing.T) {
	cw.setup()
	cw.c.GR[3] = 0x12000000
	cw.c.GR[4] = 0x00005600
	cw.setMemory(0x400, 0x45134078) // BAL 1,78(3,4)
	cw.c.ilc = 0
	cw.c.PSW.CC = 3
	cw.testInst(0xa)
	v := cw.c.GR[1]
	if v != 0xba000404 {
		t.Errorf("BAL Register 1 not correct got: %08x wanted: %08x", v, 0xba000404)
	}
	if cw.c.PSW.IA != 0x00005678 {
		t.Errorf("BAL PC not correct got: %08x wanted: %08x", cw.c.PSW.IA, 0x00005678)
	}
}

// Test BALR.
func (cw *cornwellFixture) TestCycleBALR(t *testing.T) {
	cw.setup()
	cw.c.GR[1] = 0
	cw.c.GR[2] = 0x12005678
	cw.setMemory(0x400, 0x05120000) // BALR 1,2
	cw.c.ilc = 0
	cw.c.PSW.CC = 3
	cw.testInst(0xa)
	v := cw.c.GR[1]
	if v != 0x7a000402 {
		t.Errorf("BAL Register 1 not correct got: %08x wanted: %08x", v, 0x7a000402)
	}
	if cw.c.PSW.IA != 0x00005678 {
		t.Errorf("BAL PC not correct got: %08x wanted: %08x", cw.c.PSW.IA, 0x00005678)
	}

	// Branch and link with no branch
	cw.setup()
	cw.c.GR[1] = 0
	cw.c.GR[2] = 0x12005678
	cw.setMemory(0x400, 0x05100000) // BALR 1,9
	cw.c.ilc = 0
	cw.c.PSW.CC = 3
	cw.testInst(0xa)
	v = cw.c.GR[1]
	if v != 0x7a000402 {
		t.Errorf("BAL Register 1 not correct got: %08x wanted: %08x", v, 0x7a000402)
	}
	if cw.c.PSW.IA != 0x402 {
		t.Errorf("BAL PC not correct got: %08x wanted: %08x", cw.c.PSW.IA, 0x402)
	}
}

// Test BCT.
func (cw *cornwellFixture) TestCycleBCT(t *testing.T) {
	cw.setup()
	cw.c.GR[1] = 3          // Count
	cw.c.GR[2] = 0x00005678 // branch destination
	cw.c.GR[3] = 0x00000010
	cw.setMemory(0x400, 0x46123100) // BCT 1,100(2,3)
	cw.c.PSW.CC = 3
	cw.testInst(0)
	v := cw.c.GR[1]
	if v != 2 {
		t.Errorf("BCT Register 1 not correct got: %08x wanted: %08x", v, 2)
	}
	if cw.c.PSW.IA != 0x00005788 {
		t.Errorf("BCT PC not correct got: %08x wanted: %08x", cw.c.PSW.IA, 0x00005788)
	}
	cw.c.GR[1] = 1          // Count
	cw.c.GR[2] = 0x00005678 // branch destination
	cw.c.GR[3] = 0x00000010
	cw.setMemory(0x400, 0x46123100) // BCT 1,100(2,3)
	cw.c.PSW.CC = 3
	cw.testInst(0)
	v = cw.c.GR[1]
	if v != 0 {
		t.Errorf("BCT Register 1 not correct got: %08x wanted: %08x", v, 0)
	}
	if cw.c.PSW.IA != 0x404 {
		t.Errorf("BCT PC not correct got: %08x wanted: %08x", cw.c.PSW.IA, 0x404)
	}
}

// Test BCTR.
func (cw *cornwellFixture) TestCycleBCTR(t *testing.T) {
	cw.setup()
	cw.c.GR[1] = 3          // Count
	cw.c.GR[2] = 0x00005678 // branch destination
	cw.c.GR[3] = 0x00000010
	cw.setMemory(0x400, 0x06120000) // BCTR 1,2
	cw.c.PSW.CC = 3
	cw.testInst(0)
	v := cw.c.GR[1]
	if v != 2 {
		t.Errorf("BCT Register 1 not correct got: %08x wanted: %08x", v, 2)
	}
	if cw.c.PSW.IA != 0x00005678 {
		t.Errorf("BCT PC not correct got: %08x wanted: %08x", cw.c.PSW.IA, 0x00005578)
	}

	cw.c.GR[1] = 0          // Count
	cw.c.GR[2] = 0x00005678 // branch destination
	cw.c.GR[3] = 0x00000010
	cw.setMemory(0x400, 0x06120000) // BCTR 1,2
	cw.c.PSW.CC = 3
	cw.testInst(0)
	v = cw.c.GR[1]
	if v != 0xffffffff {
		t.Errorf("BCT Register 1 not correct got: %08x wanted: %08x", v, 0xffffffff)
	}
	if cw.c.PSW.IA != 0x00005678 {
		t.Errorf("BCT PC not correct got: %08x wanted: %08x", cw.c.PSW.IA, 0x00005678)
	}

	cw.c.GR[1] = 1          // Count
	cw.c.GR[2] = 0x00005678 // branch destination
	cw.c.GR[3] = 0x00000010
	cw.setMemory(0x400, 0x06120000) // BCTR 1,2
	cw.c.PSW.CC = 3
	cw.testInst(0)
	v = cw.c.GR[1]
	if v != 0 {
		t.Errorf("BCT Register 1 not correct got: %08x wanted: %08x", v, 0)
	}
	if cw.c.PSW.IA != 0x402 {
		t.Errorf("BCT PC not correct got: %08x wanted: %08x", cw.c.PSW.IA, 0x402)
	}
}

// Test BC on all conditions with all values of CC.
func (cw *cornwellFixture) TestCycleBC(t *testing.T) {
	cw.setup()
	cw.setMemory(0x100, 0)
	for i := range 16 {
		for j := range 4 {
			op := uint32(0x47000100) | (uint32(i) << 20) // BC i,100
			cw.c.PSW.CC = uint8(j)
			cw.setMemory(0x400, op)
			cw.testInst(0)
			if ((i&8) != 0 && cw.c.PSW.CC == 0) ||
				((i&4) != 0 && cw.c.PSW.CC == 1) ||
				((i&2) != 0 && cw.c.PSW.CC == 2) ||
				((i&1) != 0 && cw.c.PSW.CC == 3) {
				// Taken
				if cw.c.PSW.IA != 0x100 {
					t.Errorf("BCT PC not correct got: %08x wanted: %08x", cw.c.PSW.IA, 0x100)
				}
			} else {
				if cw.c.PSW.IA != 0x404 {
					t.Errorf("BCT PC not correct got: %08x wanted: %08x", cw.c.PSW.IA, 0x404)
				}
			}
		}
	}
}

// Test BCR on all conditions with all values of CC.
func (cw *cornwellFixture) TestCycleBCR(t *testing.T) {
	cw.setup()
	cw.c.GR[1] = 0x12005678 // Branch destination
	for i := range 16 {
		for j := range 4 {
			op := uint32(0x07010000) | (uint32(i) << 20) // BCR i,1
			cw.c.PSW.CC = uint8(j)
			cw.setMemory(0x400, op)
			cw.testInst(0)
			if ((i&8) != 0 && cw.c.PSW.CC == 0) ||
				((i&4) != 0 && cw.c.PSW.CC == 1) ||
				((i&2) != 0 && cw.c.PSW.CC == 2) ||
				((i&1) != 0 && cw.c.PSW.CC == 3) {
				// Taken
				if cw.c.PSW.IA != 0x00005678 {
					t.Errorf("BCT PC not correct got: %08x wanted: %08x", cw.c.PSW.IA, 0x00005678)
				}
			} else {
				if cw.c.PSW.IA != 0x402 {
					t.Errorf("BCT PC not correct got: %08x wanted: %08x", cw.c.PSW.IA, 0x402)
				}
			}
		}
	}
}

// Test BXH.
func (cw *cornwellFixture) TestCycleBXH(t *testing.T) {
	cw.setup()

	// Add increment to first operand, compare with odd register after R3
	cw.setMemory(0x400, 0x86142200) // BXH 1, 4, 200(2)
	cw.setMemory(0x1200, 0)         // Clear target of branch
	cw.c.GR[1] = 0x12345678         // Value
	cw.c.GR[2] = 0x1000             // Branch target
	cw.c.GR[4] = 1                  // Increment
	cw.c.GR[5] = 0x12345678         // Compare value

	cw.testInst(0)
	v := cw.c.GR[1]
	if v != 0x12345679 {
		t.Errorf("BXH Register not correct got: %08x wanted: %08x", v, 0x12345679)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("BXH CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}
	if cw.c.PSW.IA != 0x1200 {
		t.Errorf("BXH PC not correct got: %08x wanted: %08x", cw.c.PSW.IA, 0x1200)
	}

	// Add increment to first operand, compare with odd register after R3
	cw.setMemory(0x400, 0x86142200) // BXH 1, 4, 200(2)
	cw.setMemory(0x1200, 0)         // Clear target of branch
	cw.c.GR[1] = 0x12345678         // Value
	cw.c.GR[2] = 0x1000             // Branch target
	cw.c.GR[4] = 0xffffffff         // Increment -1
	cw.c.GR[5] = 0x12345678         // Compare value

	cw.testInst(0)
	v = cw.c.GR[1]
	if v != 0x12345677 {
		t.Errorf("BXH Register not correct got: %08x wanted: %08x", v, 0x12345677)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("BXH CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}
	if cw.c.PSW.IA != 0x404 {
		t.Errorf("BXH PC not correct got: %08x wanted: %08x", cw.c.PSW.IA, 0x404)
	}

	// Add increment to first operand, compare with odd register after R3
	cw.setMemory(0x400, 0x86132200) // BXH 1, 3, 200(2)
	cw.setMemory(0x1200, 0)         // Clear target of branch
	cw.c.GR[1] = 1                  // Value
	cw.c.GR[2] = 0x1000             // Branch target
	cw.c.GR[3] = 0x12345678         // Incrment and Compare value
	cw.c.GR[4] = 0xffffffff         // Increment -1
	cw.c.GR[5] = 0x12345678         // Compare value

	cw.testInst(0)
	v = cw.c.GR[1]
	if v != 0x12345679 {
		t.Errorf("BXH Register not correct got: %08x wanted: %08x", v, 0x12345679)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("BXH CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}
	if cw.c.PSW.IA != 0x1200 {
		t.Errorf("BXH PC not correct got: %08x wanted: %08x", cw.c.PSW.IA, 0x1200)
	}

	// Add increment to first operand, compare with odd register after R3
	cw.setMemory(0x400, 0x86132200) // BXH 1, 3, 200(2)
	cw.setMemory(0x1200, 0)         // Clear target of branch
	cw.c.GR[1] = 0xffffffff         // Value
	cw.c.GR[2] = 0x1000             // Branch target
	cw.c.GR[3] = 0x12345678         // Incrment and Compare value
	cw.c.GR[4] = 0xffffffff         // Increment -1
	cw.c.GR[5] = 0x12345678         // Compare value

	cw.testInst(0)
	v = cw.c.GR[1]
	if v != 0x12345677 {
		t.Errorf("BXH Register not correct got: %08x wanted: %08x", v, 0x12345677)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("BXH CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}
	if cw.c.PSW.IA != 0x404 {
		t.Errorf("BXH PC not correct got: %08x wanted: %08x", cw.c.PSW.IA, 0x404)
	}
}

// Test BXLE.
func (cw *cornwellFixture) TestCycleBXLE(t *testing.T) {
	cw.setup()

	// Add increment to first operand, compare with odd register after R3
	cw.setMemory(0x400, 0x87142200) // BXLE 1, 4, 200(2)
	cw.setMemory(0x1200, 0)         // Clear target of branch
	cw.c.GR[1] = 0x12345678         // Value
	cw.c.GR[2] = 0x1000             // Branch target
	cw.c.GR[4] = 1                  // Increment
	cw.c.GR[5] = 0x12345678         // Compare value

	cw.testInst(0)
	v := cw.c.GR[1]
	if v != 0x12345679 {
		t.Errorf("BXLE Register not correct got: %08x wanted: %08x", v, 0x12345679)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("BXLE CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}
	if cw.c.PSW.IA != 0x404 {
		t.Errorf("BXLE PC not correct got: %08x wanted: %08x", cw.c.PSW.IA, 0x40)
	}

	// Add increment to first operand, compare with odd register after R3
	cw.setMemory(0x400, 0x87142200) // BXLE 1, 4, 200(2)
	cw.setMemory(0x1200, 0)         // Clear target of branch
	cw.c.GR[1] = 0x12345678         // Value
	cw.c.GR[2] = 0x1000             // Branch target
	cw.c.GR[4] = 0xffffffff         // Increment -1
	cw.c.GR[5] = 0x12345678         // Compare value

	cw.testInst(0)
	v = cw.c.GR[1]
	if v != 0x12345677 {
		t.Errorf("BXLE Register not correct got: %08x wanted: %08x", v, 0x12345677)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("BXLE CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}
	if cw.c.PSW.IA != 0x1200 {
		t.Errorf("BXLE PC not correct got: %08x wanted: %08x", cw.c.PSW.IA, 0x1200)
	}

	// Add increment to first operand, compare with odd register after R3
	cw.setMemory(0x400, 0x87132200) // BXLE 1, 3, 200(2)
	cw.setMemory(0x1200, 0)         // Clear target of branch
	cw.c.GR[1] = 1                  // Value
	cw.c.GR[2] = 0x1000             // Branch target
	cw.c.GR[3] = 0x12345678         // Incrment and Compare value
	cw.c.GR[4] = 0xffffffff         // Increment -1
	cw.c.GR[5] = 0x12345678         // Compare value

	cw.testInst(0)
	v = cw.c.GR[1]
	if v != 0x12345679 {
		t.Errorf("BXLE Register not correct got: %08x wanted: %08x", v, 0x12345679)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("BXLE CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}
	if cw.c.PSW.IA != 0x404 {
		t.Errorf("BXLE PC not correct got: %08x wanted: %08x", cw.c.PSW.IA, 0x404)
	}

	// Add increment to first operand, compare with odd register after R3
	cw.setMemory(0x400, 0x87132200) // BXLE 1, 3, 200(2)
	cw.setMemory(0x1200, 0)         // Clear target of branch
	cw.c.GR[1] = 0xffffffff         // Value
	cw.c.GR[2] = 0x1000             // Branch target
	cw.c.GR[3] = 0x12345678         // Incrment and Compare value
	cw.c.GR[4] = 0xffffffff         // Increment -1
	cw.c.GR[5] = 0x12345678         // Compare value

	cw.testInst(0)
	v = cw.c.GR[1]
	if v != 0x12345677 {
		t.Errorf("BXLE Register not correct got: %08x wanted: %08x", v, 0x12345677)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("BXLE CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}
	if cw.c.PSW.IA != 0x1200 {
		t.Errorf("BXLE PC not correct got: %08x wanted: %08x", cw.c.PSW.IA, 0x1200)
	}
}

// Test and instruction.
func (cw *cornwellFixture) TestCycleN(t *testing.T) {
	cw.setup()

	cw.setMemory(0x400, 0x54123454) // N 1,454(2,3)
	cw.setMemory(0x404, 0)
	cw.setMemory(0x954, 0x12345678)
	cw.c.GR[1] = 0x11223344
	cw.c.GR[2] = 0x200
	cw.c.GR[3] = 0x300
	cw.testInst(0)
	v := cw.c.GR[1]
	mv := uint32(0x11223344) & uint32(0x12345678)
	if v != mv {
		t.Errorf("N Register not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 1 {
		t.Errorf("N CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x54123454) // N 1,454(2,3)
	cw.setMemory(0x404, 0)
	cw.setMemory(0x954, 0x00000000)
	cw.c.GR[1] = 0xffffffff
	cw.c.GR[2] = 0x200
	cw.c.GR[3] = 0x300
	cw.testInst(0)
	v = cw.c.GR[1]
	mv = uint32(0xffffffff) & uint32(0x00000000)
	if v != mv {
		t.Errorf("N Register not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 0 {
		t.Errorf("N CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}
	// And register
	cw.c.PSW.CC = 3
	cw.c.GR[1] = 0xff00ff00
	cw.c.GR[2] = 0x12345678
	cw.setMemory(0x400, 0x14120000) // NR 1,2
	cw.testInst(0)
	v = cw.c.GR[1]
	mv = uint32(0x12005600)
	if v != mv {
		t.Errorf("N Register not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 1 {
		t.Errorf("N CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}
	// And register zero result
	cw.c.PSW.CC = 3
	cw.c.GR[1] = 0x12345678
	cw.c.GR[2] = 0xedcba987
	cw.setMemory(0x400, 0x14120000) // NR 1,2
	cw.testInst(0)
	v = cw.c.GR[1]
	mv = uint32(0x0)
	if v != mv {
		t.Errorf("N Register not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 0 {
		t.Errorf("N CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}
}

// Test or instruction.
func (cw *cornwellFixture) TestCycleO(t *testing.T) {
	cw.setup()

	cw.setMemory(0x400, 0x56123454) // O 1,454(2,3)
	cw.setMemory(0x404, 0)
	cw.setMemory(0x954, 0x12345678)
	cw.c.GR[1] = 0x11223344
	cw.c.GR[2] = 0x200
	cw.c.GR[3] = 0x300

	cw.testInst(0)
	v := cw.c.GR[1]
	mv := uint32(0x11223344) | uint32(0x12345678)
	if v != mv {
		t.Errorf("O Register not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 1 {
		t.Errorf("O CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x56123454) // O 1,454(2,3)
	cw.setMemory(0x404, 0)
	cw.setMemory(0x954, 0x00000000)
	cw.c.GR[1] = 0x00000000
	cw.c.GR[2] = 0x200
	cw.c.GR[3] = 0x300

	cw.testInst(0)
	v = cw.c.GR[1]
	mv = uint32(0x00000000)
	if v != mv {
		t.Errorf("O Register not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 0 {
		t.Errorf("O CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}

	// Or register
	cw.c.PSW.CC = 3
	cw.c.GR[1] = 0xff00ff00
	cw.c.GR[2] = 0x12345678
	cw.setMemory(0x400, 0x16120000) // OR 1,2
	cw.testInst(0)
	v = cw.c.GR[1]
	mv = uint32(0xff34ff78)
	if v != mv {
		t.Errorf("O Register not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 1 {
		t.Errorf("O CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}
}

// Test or instruction.
func (cw *cornwellFixture) TestCycleX(t *testing.T) {
	cw.setup()

	cw.setMemory(0x400, 0x57123454) // X 1,454(2,3)
	cw.setMemory(0x404, 0)
	cw.setMemory(0x954, 0x12345678)
	cw.c.GR[1] = 0x11223344
	cw.c.GR[2] = 0x200
	cw.c.GR[3] = 0x300

	cw.testInst(0)
	v := cw.c.GR[1]
	mv := uint32(0x11223344) ^ uint32(0x12345678)
	if v != mv {
		t.Errorf("X Register not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 1 {
		t.Errorf("X CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0x57123454) // X 1,454(2,3)
	cw.setMemory(0x404, 0)
	cw.setMemory(0x954, 0x11223344)
	cw.c.GR[1] = 0x11223344
	cw.c.GR[2] = 0x200
	cw.c.GR[3] = 0x300

	cw.testInst(0)
	v = cw.c.GR[1]
	mv = 0x00000000
	if v != mv {
		t.Errorf("X Register not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 0 {
		t.Errorf("X CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}

	// Exclusive or register
	cw.c.PSW.CC = 3
	cw.c.GR[1] = 0xff00ff00
	cw.c.GR[2] = 0x12345678
	cw.setMemory(0x400, 0x17120000) // XR 1,2
	cw.testInst(0)
	v = cw.c.GR[1]
	mv = 0xed34a978
	if v != mv {
		t.Errorf("X Register not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 1 {
		t.Errorf("X CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}
}

// Shift left arithmetic single register.
func (cw *cornwellFixture) TestCycleSLA(t *testing.T) {
	cw.setup()

	cw.c.GR[1] = 0x12345678
	cw.c.GR[2] = 0x00000001
	cw.setMemory(0x400, 0x8b1f2001) // SLA 1,1(2)
	cw.testInst(0)
	v := cw.c.GR[1]
	mv := uint32(0x12345678) << 2
	if v != mv {
		t.Errorf("SLA Register not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("SLA C not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}

	// Shift left single zero
	cw.c.PSW.CC = 3
	cw.c.GR[1] = 0x12345678
	cw.setMemory(0x400, 0x8b100000) // SLA 1,0(0)
	cw.testInst(0)
	v = cw.c.GR[1]
	mv = uint32(0x12345678)
	if v != mv {
		t.Errorf("SLA Register not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("SLA CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}

	// // Shift left single zero negative
	cw.c.PSW.CC = 3
	cw.c.GR[1] = 0x92345678
	cw.setMemory(0x400, 0x8b100000) // SLA 1,0(0)
	cw.testInst(0)
	v = cw.c.GR[1]
	mv = uint32(0x92345678)
	if v != mv {
		t.Errorf("SLA Register not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 1 {
		t.Errorf("SLA CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}

	// Shift left single  zero, zero value
	cw.c.PSW.CC = 3
	cw.c.GR[1] = 0
	cw.setMemory(0x400, 0x8b100000) // SLA 1,0(0)
	cw.testInst(0)
	v = cw.c.GR[1]
	mv = uint32(0)
	if v != mv {
		t.Errorf("SLA Register not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 0 {
		t.Errorf("SLA CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}

	// Shift left single positive overflow
	cw.c.PSW.CC = 3
	cw.c.GR[1] = 0x10000000
	cw.c.GR[2] = 2
	cw.setMemory(0x400, 0x8b1f2000) // SLA 1,0(2)
	cw.testInst(0)
	v = cw.c.GR[1]
	mv = uint32(0x40000000)
	if v != mv {
		t.Errorf("SLA Register not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("SLA CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}

	cw.c.PSW.CC = 3
	cw.c.GR[1] = 0x10000000
	cw.c.GR[2] = 3
	cw.setMemory(0x400, 0x8b1f2000) // SLA 1,0(2)
	cw.testInst(0)
	v = cw.c.GR[1]
	mv = uint32(0x00000000)
	if v != mv {
		t.Errorf("SLA Register not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("SLA CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	// Shift left single
	cw.c.PSW.CC = 3
	cw.c.GR[1] = 0x7fffffff
	cw.c.GR[2] = 0x0000001f         // Shift by 31 shifts out entire number
	cw.setMemory(0x400, 0x8b1f2000) // SLA 1,0(2)
	cw.testInst(0)
	v = cw.c.GR[1]
	mv = uint32(0x00000000)
	if v != mv {
		t.Errorf("SLA Register not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("SLA CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	// Shift left single
	cw.c.PSW.CC = 3
	cw.c.GR[1] = 0x7fffffff
	cw.c.GR[2] = 0x00000020         // Shift by 32 shifts out entire number
	cw.setMemory(0x400, 0x8b1f2000) // SLA 1,0(2)
	cw.testInst(0)
	v = cw.c.GR[1]
	mv = uint32(0x00000000)
	if v != mv {
		t.Errorf("SLA Register not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("SLA CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	cw.c.PSW.CC = 3
	cw.c.GR[1] = 0x80000000
	cw.c.GR[2] = 0x0000001f         // Shift by 31 shifts out entire number
	cw.setMemory(0x400, 0x8b1f2000) // SLA 1,0(2)
	cw.testInst(0)
	v = cw.c.GR[1]
	mv = uint32(0x80000000)
	if v != mv {
		t.Errorf("SLA Register not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("SLA CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	cw.c.PSW.CC = 3
	cw.c.GR[1] = 0x80000000
	cw.c.GR[2] = 2                  // Shift by 2 should overflow
	cw.setMemory(0x400, 0x8b1f2000) // SLA 1,0(2)
	cw.testInst(0)
	v = cw.c.GR[1]
	mv = uint32(0x80000000)
	if v != mv {
		t.Errorf("SLA Register not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("SLA CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	cw.c.PSW.CC = 3
	cw.c.GR[1] = 0x80000001
	cw.c.GR[2] = 2                  // Shift by 2 should overflow
	cw.setMemory(0x400, 0x8b1f2000) // SLA 1,0(2)
	cw.testInst(0)
	v = cw.c.GR[1]
	mv = uint32(0x80000004)
	if v != mv {
		t.Errorf("SLA Register not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("SLA CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	cw.c.PSW.CC = 3
	cw.c.GR[1] = 0xf0000001
	cw.c.GR[2] = 0x00000001
	cw.setMemory(0x400, 0x8b1f2001) // SLA 1,1(2)
	cw.testInst(0)
	v = cw.c.GR[1]
	mv = uint32(0xc0000004)
	if v != mv {
		t.Errorf("SLA Register not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 1 {
		t.Errorf("SLA CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}

	// From Princ Ops p143
	cw.c.PSW.CC = 3
	cw.c.GR[2] = 0x007f0a72
	cw.setMemory(0x400, 0x8b2f0008) // SLA 2,8(0) // Shift left 8
	cw.testInst(0)
	v = cw.c.GR[2]
	mv = uint32(0x7f0a7200)
	if v != mv {
		t.Errorf("SLA Register not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("SLA CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}
}

// Shift left logical instruction.
func (cw *cornwellFixture) TestCycleSLL(t *testing.T) {
	cw.setup()

	cw.c.GR[1] = 0x82345678
	cw.c.GR[2] = 0x12340003         // Shift 3 bits
	cw.setMemory(0x400, 0x891f2100) // SLL 1,100(2)
	cw.testInst(0)
	v := cw.c.GR[1]
	mv := uint32(0x11a2b3c0)
	if v != mv {
		t.Errorf("SLL Register not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("SLL CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	for i := range uint32(31) {
		cw.c.GR[1] = 1
		cw.c.GR[2] = 0x12340000 + i     // Shift i bits
		cw.setMemory(0x400, 0x891f2100) // SLL 1,100(2)
		cw.testInst(0)
		v := cw.c.GR[1]
		mv := uint32(1 << i)
		if v != mv {
			t.Errorf("SLL Register not correct got: %08x wanted: %08x", v, mv)
		}
	}
}

// Shift right logical instruction.
func (cw *cornwellFixture) TestCycleSRL(t *testing.T) {
	cw.setup()

	cw.c.GR[1] = 0x82345678
	cw.c.GR[2] = 0x12340003         // Shift 3 bits
	cw.setMemory(0x400, 0x881f2100) // SRL 1,100(2)
	cw.testInst(0)
	v := cw.c.GR[1]
	mv := uint32(0x82345678 >> 3)
	if v != mv {
		t.Errorf("SRL Register not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("SRL CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}
}

// Shift right arithmatic instruction.
func (cw *cornwellFixture) TestCycleSRA(t *testing.T) {
	cw.setup()

	cw.c.GR[2] = 0x11223344
	cw.setMemory(0x400, 0x8a2f0105) // SRA 2,105(0) // Shift right 5
	cw.testInst(0)
	v := cw.c.GR[2]
	mv := uint32(0x0089119a)
	if v != mv {
		t.Errorf("SRA Register not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("SRA CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}
}

// Shift right double logical.
func (cw *cornwellFixture) TestCycleSRDL(t *testing.T) {
	cw.setup()

	cw.c.GR[4] = 0x12345678
	cw.c.GR[5] = 0xaabbccdd
	cw.setMemory(0x400, 0x8c4f0118) // SRDL 4,118(0) // Shift right 24 (x18)
	cw.testInst(0)
	v := cw.c.GR[4]
	mv := uint32(0x00000012)
	if v != mv {
		t.Errorf("SRDL Register 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.c.GR[5]
	mv = uint32(0x345678aa)
	if v != mv {
		t.Errorf("SRDL Register 2 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("SRDL CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}
}

// Shift left double logical.
func (cw *cornwellFixture) TestCycleSLDL(t *testing.T) {
	cw.setup()

	cw.c.GR[4] = 0x12345678
	cw.c.GR[5] = 0xaabbccdd
	cw.c.GR[6] = 8
	cw.setMemory(0x400, 0x8d4f6100) // SLDL 4,100(6)  // Shift left 8
	cw.testInst(0)
	v := cw.c.GR[4]
	mv := uint32(0x345678aa)
	if v != mv {
		t.Errorf("SLDL Register 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.c.GR[5]
	mv = uint32(0xbbccdd00)
	if v != mv {
		t.Errorf("SLDL Register 2 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("SLDL CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	cw.c.PSW.CC = 3
	cw.c.GR[4] = 0x12345678
	cw.c.GR[5] = 0x00010001
	cw.setMemory(0x400, 0x8d4f051b) // SLDL 4,51b(0) // Shift left 27
	cw.testInst(0)
	v = cw.c.GR[4]
	mv = uint32(0xc0000800)
	if v != mv {
		t.Errorf("SLDL Register 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.c.GR[5]
	mv = uint32(0x08000000)
	if v != mv {
		t.Errorf("SLDL Register 2 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("SLDL CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	cw.c.PSW.CC = 3
	cw.c.GR[4] = 0x12345678
	cw.c.GR[5] = 0x00010001
	cw.setMemory(0x400, 0x8d1f2100) // SLDL 1,100(2)
	cw.testInst(0)
	if !cw.trap {
		t.Error("SLDL did not trap")
	}
	v = cw.c.GR[4]
	mv = uint32(0x12345678)
	if v != mv {
		t.Errorf("SLDL Register 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.c.GR[5]
	mv = uint32(0x00010001)
	if v != mv {
		t.Errorf("SLDL Register 2 not correct got: %08x wanted: %08x", v, mv)
	}
}

// Shift double right arithmatic.
func (cw *cornwellFixture) TestCycleSRDA(t *testing.T) {
	cw.setup()

	cw.c.GR[4] = 0x12345678
	cw.c.GR[5] = 0xaabbccdd
	cw.c.GR[6] = 8
	cw.setMemory(0x400, 0x8e4f0118) // SRDA 4,118(0) // Shift right 24 (x18)
	cw.testInst(0)
	v := cw.c.GR[4]
	mv := uint32(0x00000012)
	if v != mv {
		t.Errorf("SRDA Register 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.c.GR[5]
	mv = uint32(0x345678aa)
	if v != mv {
		t.Errorf("SRDA Register 2 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("SRDA CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}

	cw.c.PSW.CC = 3
	cw.c.GR[4] = 0x02345678
	cw.c.GR[5] = 0xaabbccdd
	cw.setMemory(0x400, 0x8e4f013c) // SRDA 4,13c(0) //  Shift right 60 (x3c)
	cw.testInst(0)
	v = cw.c.GR[4]
	mv = uint32(0x00000000)
	if v != mv {
		t.Errorf("SRDA Register 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.c.GR[5]
	mv = uint32(0x00000000)
	if v != mv {
		t.Errorf("SRDA Register 2 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 0 {
		t.Errorf("SRDA CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}

	cw.c.PSW.CC = 3
	cw.c.GR[4] = 0x92345678
	cw.c.GR[5] = 0xaabbccdd
	cw.setMemory(0x400, 0x8e4f0118) // SRDA 4,118(0) // Shift right 24 (x18)
	cw.testInst(0)
	v = cw.c.GR[4]
	mv = uint32(0xffffff92)
	if v != mv {
		t.Errorf("SRDA Register 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.c.GR[5]
	mv = uint32(0x345678aa)
	if v != mv {
		t.Errorf("SRDA Register 2 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 1 {
		t.Errorf("SRDA CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}
}

// Shift double left arithmatic.
func (cw *cornwellFixture) TestCycleSLDA(t *testing.T) {
	cw.setup()

	cw.c.GR[2] = 0x007f0a72
	cw.c.GR[3] = 0xfedcba98
	cw.setMemory(0x400, 0x8f2f001f) // SLDA 2,1f(0)
	cw.testInst(0)
	v := cw.c.GR[2]
	mv := uint32(0x7f6e5d4c)
	if v != mv {
		t.Errorf("SLDA Register 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.c.GR[3]
	mv = uint32(0x00000000)
	if v != mv {
		t.Errorf("SLDA Register 2 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("SLDA CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	cw.c.PSW.CC = 3
	cw.c.GR[2] = 0xffffffff
	cw.c.GR[3] = 0xffffe070
	cw.setMemory(0x400, 0x8f2f0030) // SLDA 2,30(0)
	cw.testInst(0)
	v = cw.c.GR[2]
	mv = uint32(0xe0700000)
	if v != mv {
		t.Errorf("SLDA Register 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.c.GR[3]
	mv = uint32(0x00000000)
	if v != mv {
		t.Errorf("SLDA Register 2 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 1 {
		t.Errorf("SLDA CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}

	cw.c.PSW.CC = 3
	cw.c.GR[2] = 0x92345678
	cw.c.GR[3] = 0xc0506070
	cw.setMemory(0x400, 0x8f2f0020) // SLDA 2,20(0)
	cw.testInst(0)
	v = cw.c.GR[2]
	mv = uint32(0xc0506070)
	if v != mv {
		t.Errorf("SLDA Register 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.c.GR[3]
	mv = uint32(0x00000000)
	if v != mv {
		t.Errorf("SLDA Register 2 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("SLDA CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	cw.c.PSW.CC = 3
	cw.c.GR[2] = 0xff902030
	cw.c.GR[3] = 0x40506070
	cw.setMemory(0x400, 0x8f2f0008) // SLDA 2,8(0)
	cw.testInst(0)
	v = cw.c.GR[2]
	mv = uint32(0x90203040)
	if v != mv {
		t.Errorf("SLDA Register 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.c.GR[3]
	mv = uint32(0x50607000)
	if v != mv {
		t.Errorf("SLDA Register 2 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 1 {
		t.Errorf("SLDA CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}

	cw.c.PSW.CC = 3
	cw.c.GR[2] = 0x00000000
	cw.c.GR[3] = 0x000076f7
	cw.setMemory(0x400, 0x8f2f0030) // SLDA 2,30(0)
	cw.testInst(0)
	v = cw.c.GR[2]
	mv = uint32(0x76f70000)
	if v != mv {
		t.Errorf("SLDA Register 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.c.GR[3]
	mv = uint32(0x00000000)
	if v != mv {
		t.Errorf("SLDA Register 2 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("SLDA CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}
}

// Load multiple registers.
func (cw *cornwellFixture) TestCycleLM(t *testing.T) {
	cw.setup()

	cw.c.GR[2] = 0xffffffff
	cw.c.GR[3] = 0x00000010
	cw.c.GR[4] = 0xffffffff
	cw.c.GR[5] = 0x00000000
	cw.setMemory(0x110, 0x12345678)
	cw.setMemory(0x114, 0x11223344)
	cw.setMemory(0x118, 0x55667788)
	cw.setMemory(0x11c, 0x99aabbcc)
	cw.setMemory(0x400, 0x98253100) // LM 2,5,100(3)
	cw.testInst(0)
	v := cw.c.GR[2]
	mv := uint32(0x12345678)
	if v != mv {
		t.Errorf("LM Register 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.c.GR[3]
	mv = uint32(0x11223344)
	if v != mv {
		t.Errorf("LM Register 2 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.c.GR[4]
	mv = uint32(0x55667788)
	if v != mv {
		t.Errorf("LM Register 3 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.c.GR[5]
	mv = uint32(0x99aabbcc)
	if v != mv {
		t.Errorf("LM Register 3 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("LM CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}
}

// Store multiple registers.
func (cw *cornwellFixture) TestCycleSTM(t *testing.T) {
	cw.setup()

	// From Princ Ops p143
	cw.c.GR[14] = 0x00002563
	cw.c.GR[15] = 0x00012736
	cw.c.GR[0] = 0x12430062
	cw.c.GR[1] = 0x73261257
	cw.c.GR[6] = 0x00004000
	cw.setMemory(0x400, 0x90e16050) // STM 14,1,50(6)
	cw.testInst(0)
	v := cw.getMemory(0x4050)
	mv := uint32(0x00002563)
	if v != mv {
		t.Errorf("STM Memory 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getMemory(0x4054)
	mv = uint32(0x00012736)
	if v != mv {
		t.Errorf("STM Memory 2 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getMemory(0x4058)
	mv = uint32(0x12430062)
	if v != mv {
		t.Errorf("STM Memory 3 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getMemory(0x405c)
	mv = uint32(0x73261257)
	if v != mv {
		t.Errorf("STM Memory 3 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("STM CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}
}

// Test under mask.
func (cw *cornwellFixture) TestCycleTM(t *testing.T) {
	cw.setup()

	// From Princ Ops p147
	cw.setMemory(0x9998, 0xaafbaaaa)
	cw.c.GR[9] = 0x00009990
	cw.setMemory(0x400, 0x91c39009) // TM 9(9),c3
	cw.testInst(0)
	if cw.c.PSW.CC != 3 {
		t.Errorf("TM CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x9998, 0xaa3caaaa)
	cw.c.GR[9] = 0x00009990
	cw.setMemory(0x400, 0x91c39009) // TM 9(9),c3
	cw.testInst(0)
	if cw.c.PSW.CC != 0 {
		t.Errorf("TM CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x9998, 0xaa3caaaa)
	cw.c.GR[9] = 0x00009990
	cw.setMemory(0x400, 0x91c39009) // TM 9(9),c3
	cw.testInst(0)
	if cw.c.PSW.CC != 0 {
		t.Errorf("TM CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x9998, 0xaa3caaaa)
	cw.c.GR[9] = 0x00009990
	cw.setMemory(0x400, 0x91009008) // TM 9(9),c3
	cw.testInst(0)
	if cw.c.PSW.CC != 0 {
		t.Errorf("TM CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x9998, 0xf03caaaa)
	cw.c.GR[9] = 0x00009990
	cw.setMemory(0x400, 0x91f09008) // TM 9(9),c3
	cw.testInst(0)
	if cw.c.PSW.CC != 3 {
		t.Errorf("TM CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x9998, 0xa0f8aaaa)
	cw.c.GR[9] = 0x00009990
	cw.setMemory(0x400, 0x910c9009) // TM 9(9),c3
	cw.testInst(0)
	if cw.c.PSW.CC != 1 {
		t.Errorf("TM CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}
}

// Test to convert to binary.
func (cw *cornwellFixture) TestCycleCVB(t *testing.T) {
	cw.setup()

	// Example from Principles of Operation p122
	cw.c.GR[5] = 50 // Example seems to have addresses in decimal?
	cw.c.GR[6] = 900
	cw.setMemory(1000, 0x00000000)
	cw.setMemory(1004, 0x0025594f)
	cw.setMemory(0x400, 0x4f756032) //  CVB 7,32(5,6)
	cw.testInst(0)
	v := cw.c.GR[7]
	mv := uint32(25594)
	if v != mv {
		t.Errorf("CVB 1 Register 7 not correct got: %08x wanted: %08x", v, mv)
	}

	// Test convert to binary with bad sign
	cw.c.PSW.CC = 3
	cw.c.GR[5] = 50 // Example seems to have addresses in decimal?
	cw.c.GR[6] = 900
	cw.setMemory(1000, 0x00000000)
	cw.setMemory(1004, 0x00255941)  // 1 is not a valid sign
	cw.setMemory(0x400, 0x4f756032) // CVB 7,32(5,6)
	cw.testInst(0)
	if !cw.trap {
		t.Error(("CVB 2 Should have trapped"))
	}

	// Test convert to binary with bad digit.
	cw.c.PSW.CC = 3
	cw.c.GR[5] = 50 // Example seems to have addresses in decimal?
	cw.c.GR[6] = 900
	cw.setMemory(1000, 0x00000000)
	cw.setMemory(1004, 0x002a594f)
	cw.setMemory(0x400, 0x4f756032) // CVB 7,32(5,6)
	cw.testInst(0)
	if !cw.trap {
		t.Error(("CVB 3 Should have trapped"))
	}

	cw.c.PSW.CC = 3
	cw.c.GR[5] = 50 // Example seems to have addresses in decimal?
	cw.c.GR[6] = 900
	cw.setMemory(1000, 0x00000214)
	cw.setMemory(1004, 0x8000000f)
	cw.setMemory(0x400, 0x4f756032) // CVB 7,32(5,6)
	cw.testInst(0)
	if !cw.trap {
		t.Error(("CVB 4 Should have trapped"))
	}
	v = cw.c.GR[7]
	mv = uint32(2148000000)
	if v != mv {
		t.Errorf("CVB 4 Register 7 not correct got: %08x wanted: %08x", v, mv)
	}

	// Test for overflow
	cw.c.PSW.CC = 3
	cw.c.GR[5] = 50 // Example seems to have addresses in decimal?
	cw.c.GR[6] = 900
	cw.setMemory(1000, 0x00000284)
	cw.setMemory(1004, 0x4242842c)
	cw.setMemory(0x400, 0x4f756032) // CVB 7,32(5,6)
	cw.testInst(0)
	if !cw.trap {
		t.Error(("CVB 5 Should have trapped"))
	}
	v = cw.c.GR[7]
	mv = uint32(0xa987b39a)
	if v != mv {
		t.Errorf("CVB 5 Register 7 not correct got: %08x wanted: %08x", v, mv)
	}

	// Test for larger overflow
	cw.c.PSW.CC = 3
	cw.c.GR[5] = 50 // Example seems to have addresses in decimal?
	cw.c.GR[6] = 900
	cw.setMemory(1000, 0x12345678)
	cw.setMemory(1004, 0x4800000f)
	cw.setMemory(0x400, 0x4f756032) // CVB 7,32(5,6)
	cw.testInst(0)
	if !cw.trap {
		t.Error(("CVB 6 Should have trapped"))
	}

	// Test big overflow
	cw.c.PSW.CC = 3
	cw.c.GR[5] = 50 // Example seems to have addresses in decimal?
	cw.c.GR[6] = 900
	cw.setMemory(1000, 0x12345678)
	cw.setMemory(1004, 0x4800000f)
	cw.setMemory(0x400, 0x4f756032) // CVB 7,32(5,6)
	cw.testInst(0)
	if !cw.trap {
		t.Error(("CVB 7 Should have trapped"))
	}

	// Test with large number
	cw.c.PSW.CC = 3
	cw.c.GR[5] = 50 // Example seems to have addresses in decimal?
	cw.c.GR[6] = 900
	cw.setMemory(1000, 0x00000021)
	cw.setMemory(1004, 0x2345678f)
	cw.setMemory(0x400, 0x4f756032) // CVB 7,32(5,6)
	cw.testInst(0)
	v = cw.c.GR[7]
	mv = uint32(212345678)
	if v != mv {
		t.Errorf("CVB 8 Register 7 not correct got: %08x wanted: %08x", v, mv)
	}

	//  Test negative
	cw.c.PSW.CC = 3
	cw.c.GR[5] = 50 // Example seems to have addresses in decimal?
	cw.c.GR[6] = 900
	cw.setMemory(1000, 0x00000000)
	cw.setMemory(1004, 0x0025594d)  // d is negative
	cw.setMemory(0x400, 0x4f756032) // CVB 7,32(5,6)
	cw.testInst(0)
	v = cw.c.GR[7]
	mv = uint32(0xffff9c06)
	if v != mv {
		t.Errorf("CVB 9 Register 7 not correct got: %08x wanted: %08x", v, mv)
	}

	// test model 50 case QE900/073C, CLF 112
	cw.c.PSW.CC = 3
	cw.c.GR[5] = 0x100
	cw.c.GR[6] = 0x200
	cw.setMemory(0x500, 0)
	cw.setMemory(0x504, 0x1234567f) // Decimal 1234567+
	cw.setMemory(0x400, 0x4f156200) // CVB 1,200(5,6)
	cw.testInst(0)
	v = cw.c.GR[1]
	mv = uint32(1234567)
	if v != mv {
		t.Errorf("CVB 10 Register ` not correct got: %08x wanted: %08x", v, mv)
	}

	// Second test with negative
	cw.c.PSW.CC = 3
	cw.c.GR[5] = 0x100
	cw.c.GR[6] = 0x200
	cw.setMemory(0x500, 0)
	cw.setMemory(0x504, 0x1234567b) // Decimal 1234567-
	cw.setMemory(0x400, 0x4f156200) // CVB 1,200(5,6)
	cw.testInst(0)
	v = cw.c.GR[1]
	mv = uint32(0xffed2979)
	if v != mv {
		t.Errorf("CVB 11 Register 1 not correct got: %08x wanted: %08x", v, mv)
	}

	cw.c.PSW.CC = 3
	cw.c.GR[5] = 50 // Example seems to have addresses in decimal?
	cw.c.GR[6] = 900
	cw.setMemory(1000, 0x00000214)
	cw.setMemory(1004, 0x8000000f)
	cw.setMemory(0x400, 0x4f756032) // CVB 7,32(5,6)
	cw.testInst(0)
	v = cw.c.GR[7]
	mv = uint32(2148000000)
	if v != mv {
		t.Errorf("CVB 12 Register 7 not correct got: %08x wanted: %08x", v, mv)
	}
}

// Test convert to decimal.
func (cw *cornwellFixture) TestCycleCVD(t *testing.T) {
	cw.setup()

	// Example from Principles of Operation p122
	cw.c.GR[1] = 0x00000f0f // 3855 dec
	cw.c.GR[13] = 0x00007600
	cw.setMemory(0x400, 0x4e10d008) // CVD 1,8(0,13)
	cw.testInst(0)
	v := cw.getMemory(0x7608)
	mv := uint32(0x00000000)
	if v != mv {
		t.Errorf("CVD Memory 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getMemory(0x760C)
	mv = uint32(0x0003855c)
	if v != mv {
		t.Errorf("CVD Memory 2 not correct got: %08x wanted: %08x", v, mv)
	}

	cw.c.GR[1] = 0xfffff0f1 // -3855 dec
	cw.c.GR[13] = 0x00007600
	cw.setMemory(0x400, 0x4e10d008) // CVD 1,8(0,13)
	cw.testInst(0)
	v = cw.getMemory(0x7608)
	mv = uint32(0x00000000)
	if v != mv {
		t.Errorf("CVD Memory 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getMemory(0x760C)
	mv = uint32(0x0003855d)
	if v != mv {
		t.Errorf("CVD Memory 2 not correct got: %08x wanted: %08x", v, mv)
	}
}

// Move immeditate.
func (cw *cornwellFixture) TestCycleMVI(t *testing.T) {
	cw.setup()

	cw.c.GR[1] = 0x3456
	cw.setMemory(0x3464, 0x12345678)
	cw.setMemory(0x400, 0x92421010) // MVI 10(1),42
	cw.testInst(0)
	v := cw.getMemory(0x3464)
	mv := uint32(0x12344278)
	if v != mv {
		t.Errorf("MVI Memory not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("MVI CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x100, 0x11223344)
	cw.c.GR[1] = 1
	cw.setMemory(0x400, 0x92551100) // MVI 100(1),55 // Move byte 55 to location 101
	cw.testInst(0)
	v = cw.getMemory(0x100)
	mv = uint32(0x11553344)
	if v != mv {
		t.Errorf("MVI Memory not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("MVI CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}
}

// And immediate.
func (cw *cornwellFixture) TestCycleNI(t *testing.T) {
	cw.setup()

	cw.c.GR[1] = 0x3456
	cw.setMemory(0x3464, 0x12345678)
	cw.setMemory(0x400, 0x94f01010) // NI 10(1),f0
	cw.testInst(0)
	v := cw.getMemory(0x3464)
	mv := uint32(0x12345078)
	if v != mv {
		t.Errorf("NI Memory not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 1 {
		t.Errorf("NI CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}

	cw.c.PSW.CC = 3
	cw.c.GR[1] = 0x3456
	cw.setMemory(0x3464, 0x12345678)
	cw.setMemory(0x400, 0x940f1010) // NI 10(1),f0
	cw.testInst(0)
	v = cw.getMemory(0x3464)
	mv = uint32(0x12340678)
	if v != mv {
		t.Errorf("NI Memory not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 1 {
		t.Errorf("NI CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}

	cw.c.PSW.CC = 3
	cw.c.GR[1] = 0x3456
	cw.setMemory(0x3464, 0x12345678)
	cw.setMemory(0x400, 0x94001010) // NI 10(1),0
	cw.testInst(0)
	v = cw.getMemory(0x3464)
	mv = uint32(0x12340078)
	if v != mv {
		t.Errorf("NII Memory not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 0 {
		t.Errorf("NI CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}
}

// Compare logical immediate.
func (cw *cornwellFixture) TestCycleCLI(t *testing.T) {
	cw.setup()

	cw.c.GR[1] = 0x3456
	cw.setMemory(0x3464, 0x12345678)
	cw.setMemory(0x400, 0x95561010) // CLI 10(1),56
	cw.testInst(0)
	if cw.c.PSW.CC != 0 {
		t.Errorf("CLI CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}

	cw.c.PSW.CC = 3
	cw.c.GR[1] = 0x3456
	cw.setMemory(0x3464, 0x12345678)
	cw.setMemory(0x400, 0x95ff1010) // CLI 10(1),ff
	cw.testInst(0)
	if cw.c.PSW.CC != 1 {
		t.Errorf("CLI CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}

	for i := range uint32(255) {
		cw.c.GR[1] = 0x3442
		cw.setMemory(0x3450, 0x12345678)
		cw.setMemory(0x400, 0x95001010|(i<<16)) // CLI 10(1),i
		cw.testInst(0)
		var cc uint8
		switch x := i; {
		case x == 0x56: // Equal
			cc = 0
		case x < 0x56: // Greater
			cc = 2
		default: // Less
			cc = 1
		}
		if cw.c.PSW.CC != cc {
			t.Errorf("CLI CC not correct got: %x wanted: %x", cw.c.PSW.CC, cc)
		}
	}
}

// Or immediate.
func (cw *cornwellFixture) TestCycleOI(t *testing.T) {
	cw.setup()

	cw.c.GR[1] = 2
	cw.setMemory(0x1000, 0x12345678)
	cw.setMemory(0x400, 0x96421fff) // OI fff(1),42
	cw.testInst(0)
	v := cw.getMemory(0x1000)
	mv := uint32(0x12765678)
	if v != mv {
		t.Errorf("OI Memory not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 1 {
		t.Errorf("OI CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}
}

// Xor immediate.
func (cw *cornwellFixture) TestCycleXI(t *testing.T) {
	cw.setup()

	cw.c.GR[0] = 0x100
	cw.setMemory(0x120, 0x12345678)
	cw.setMemory(0x400, 0x970f0123) // XI 123(0),f
	cw.testInst(0)
	v := cw.getMemory(0x120)
	mv := uint32(0x12345677)
	if v != mv {
		t.Errorf("XI Memory not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 1 {
		t.Errorf("XI CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}
}

// Move numeric.
func (cw *cornwellFixture) TestCycleMVN(t *testing.T) {
	cw.setup()

	// From Princ Ops p144
	cw.setMemory(0x7090, 0xc1c2c3c4)
	cw.setMemory(0x7094, 0xc5c6c7c8)
	cw.setMemory(0x7040, 0xaaf0f1f2)
	cw.setMemory(0x7044, 0xf3f4f5f6)
	cw.setMemory(0x7048, 0xf7f8aaaa)
	cw.c.GR[14] = 0x00007090
	cw.c.GR[15] = 0x00007040
	cw.setMemory(0x400, 0xd103f001)
	cw.setMemory(0x404, 0xe0000000) // MVN 1(4,15),0(14)
	cw.testInst(0)
	v := cw.getMemory(0x7090)
	mv := uint32(0xc1c2c3c4)
	if v != mv {
		t.Errorf("MVN Memory 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getMemory(0x7040)
	mv = uint32(0xaaf1f2f3)
	if v != mv {
		t.Errorf("MVN Memory 2 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getMemory(0x7044)
	mv = uint32(0xf4f4f5f6)
	if v != mv {
		t.Errorf("MVN Memory 3 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getMemory(0x7048)
	mv = uint32(0xf7f8aaaa)
	if v != mv {
		t.Errorf("MVN Memory 4 not correct got: %08x wanted: %08x", v, mv)
	}
}

// Move character.
func (cw *cornwellFixture) TestCycleMVC(t *testing.T) {
	cw.setup()

	cw.setMemory(0x100, 0x12345678)
	cw.setMemory(0x200, 0x11223344)
	cw.setMemory(0x400, 0xd2030100)
	cw.setMemory(0x404, 0x02000000) // MVC 100(4,0),200(0) // Move 4 bytes from 200 to 100
	cw.testInst(0)
	v := cw.getMemory(0x100)
	mv := uint32(0x11223344)
	if v != mv {
		t.Errorf("MVC Memory 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getMemory(0x200)
	mv = uint32(0x11223344)
	if v != mv {
		t.Errorf("MVC Memory 2 not correct got: %08x wanted: %08x", v, mv)
	}

	cw.setMemory(0x100, 0x12345678)
	cw.setMemory(0x104, 0xabcdef01)
	cw.c.GR[1] = 2
	cw.c.GR[2] = 0
	cw.setMemory(0x400, 0xd2011100)
	cw.setMemory(0x404, 0x01050000) // MVC 100(2,1),105(0) // Move 2 bytes from 105 to 102
	cw.testInst(0)
	v = cw.getMemory(0x100)
	mv = uint32(0x1234cdef)
	if v != mv {
		t.Errorf("MVC Memory 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getMemory(0x104)
	mv = uint32(0xabcdef01)
	if v != mv {
		t.Errorf("MVC Memory 2 not correct got: %08x wanted: %08x", v, mv)
	}
}

// Move zones.
func (cw *cornwellFixture) TestCycleMVZ(t *testing.T) {
	cw.setup()

	// From Princ Ops page 144
	cw.setMemory(0x800, 0xf1c2f3c4)
	cw.setMemory(0x804, 0xf5c6aabb)
	cw.c.GR[15] = 0x00000800
	cw.setMemory(0x400, 0xd304f001)
	cw.setMemory(0x404, 0xf0000000) // MVZ 1(5,15),0(15)
	cw.testInst(0)
	v := cw.getMemory(0x800)
	mv := uint32(0xf1f2f3f4)
	if v != mv {
		t.Errorf("MVZ Memory 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getMemory(0x804)
	mv = uint32(0xf5f6aabb)
	if v != mv {
		t.Errorf("MVZ Memory 2 not correct got: %08x wanted: %08x", v, mv)
	}
}

// Move offset.
func (cw *cornwellFixture) TestCycleMVO(t *testing.T) {
	cw.setup()

	// Princ Ops 152
	cw.c.GR[12] = 0x00005600
	cw.c.GR[15] = 0x00004500
	cw.setMemory(0x5600, 0x7788990c)
	cw.setMemory(0x4500, 0x123456ff)
	cw.setMemory(0x400, 0xf132c000)
	cw.setMemory(0x404, 0xf0000000) // MVO 0(4, 12), 0(3, 15)
	cw.testInst(0)
	v := cw.getMemory(0x5600)
	mv := uint32(0x0123456c)
	if v != mv {
		t.Errorf("MVO Memory 1 not correct got: %08x wanted: %08x", v, mv)
	}
}

// Move inverse.
func (cw *cornwellFixture) TestCycleMVIN(t *testing.T) {
	cw.setup()

	cw.setMemory(0x200, 0xC1C2C3C4)
	cw.setMemory(0x204, 0xC5C6C7C8)
	cw.setMemory(0x208, 0xC9CACB00)
	cw.setMemory(0x300, 0xF1F2F3F4)
	cw.setMemory(0x304, 0xF5F6F7F8)
	cw.setMemory(0x308, 0xF9000000)
	cw.setMemory(0x400, 0xe8070200) // MVINV 200(7),300
	cw.setMemory(0x404, 0x03070000)
	cw.testInst(0)
	v := cw.getMemory(0x200)
	mv := uint32(0xF8F7F6F5)
	if v != mv {
		t.Errorf("MVIN Memory 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getMemory(0x204)
	mv = uint32(0xF4F3F2F1)
	if v != mv {
		t.Errorf("MVIN Memory 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getMemory(0x208)
	mv = uint32(0xC9CACB00)
	if v != mv {
		t.Errorf("MVIN Memory 1 not correct got: %08x wanted: %08x", v, mv)
	}
}

// Pack instruction.
func (cw *cornwellFixture) TestCyclePACK(t *testing.T) {
	cw.setup()

	// Princ Ops p151
	cw.c.GR[12] = 0x00001000
	cw.setMemory(0x1000, 0xf1f2f3f4)
	cw.setMemory(0x1004, 0xc5000000)
	cw.setMemory(0x400, 0xf244c000)
	cw.setMemory(0x404, 0xc0000000) // PACK 0(5, 12), 0(5, 12)
	cw.testInst(0)
	v := cw.getMemory(0x1000)
	mv := uint32(0x00001234)
	if v != mv {
		t.Errorf("PACK Memory 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getMemory(0x1004)
	mv = uint32(0x5c000000)
	if v != mv {
		t.Errorf("PACK Memory 2 not correct got: %08x wanted: %08x", v, mv)
	}
}

// Unpack.
func (cw *cornwellFixture) TestCycleUNPK(t *testing.T) {
	cw.setup()

	// Princ Ops p151
	cw.c.GR[12] = 0x00001000
	cw.c.GR[13] = 0x00002500
	cw.setMemory(0x2500, 0xaa12345d)
	cw.setMemory(0x1000, 0xffffffff)
	cw.setMemory(0x1004, 0xffffffff)
	cw.setMemory(0x400, 0xf342c000)
	cw.setMemory(0x404, 0xd0010000) // UNPK 0(5, 12), 1(3, 13)
	cw.testInst(0)
	v := cw.getMemory(0x1000)
	mv := uint32(0xf1f2f3f4)
	if v != mv {
		t.Errorf("UNPK Memory 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getMemory(0x1004)
	mv = uint32(0xd5ffffff)
	if v != mv {
		t.Errorf("UNPK Memory 2 not correct got: %08x wanted: %08x", v, mv)
	}
}

// And characters.
func (cw *cornwellFixture) TestCycleNC(t *testing.T) {
	cw.setup()

	cw.setMemory(0x358, 0x00001790)
	cw.setMemory(0x360, 0x00001401)
	cw.c.GR[7] = 0x00000358
	cw.setMemory(0x400, 0xd4037000)
	cw.setMemory(0x404, 0x70080000) // NC 0(4,7),8(7)
	cw.testInst(0)
	v := cw.getMemory(0x358)
	mv := uint32(0x00001400)
	if v != mv {
		t.Errorf("NC Memory 1 not correct got: %08x wanted: %08x", v, mv)
	}
}

// Compare logical character.
func (cw *cornwellFixture) TestCycleCLC(t *testing.T) {
	cw.setup()

	cw.c.GR[1] = 0x100
	cw.c.GR[2] = 0x100
	cw.setMemory(0x200, 0x12345633)
	cw.setMemory(0x300, 0x12345644)
	cw.setMemory(0x400, 0xd5021100)
	cw.setMemory(0x404, 0x22000000) // CLC 100(3,1),200(2)
	cw.testInst(0)
	if cw.c.PSW.CC != 0 {
		t.Errorf("CLI CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}

	cw.c.GR[1] = 0x100
	cw.c.GR[2] = 0x100
	cw.setMemory(0x200, 0x12345678)
	cw.setMemory(0x300, 0x12345678)
	// 123456 vs 345678 because of offset
	cw.setMemory(0x400, 0xd5021100)
	cw.setMemory(0x404, 0x22010000) // CLC 100(3,1),201(2)
	cw.testInst(0)
	if cw.c.PSW.CC != 1 {
		t.Errorf("CLI CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}
}

// Or character.
func (cw *cornwellFixture) TestCycleOC(t *testing.T) {
	cw.setup()

	cw.setMemory(0x358, 0x00001790)
	cw.setMemory(0x360, 0x00001401)
	cw.c.GR[7] = 0x00000358
	cw.setMemory(0x400, 0xd6037000)
	cw.setMemory(0x404, 0x7008aaaa) // OC 0(4,7),8(7)
	cw.testInst(0)
	v := cw.getMemory(0x358)
	mv := uint32(0x00001791)
	if v != mv {
		t.Errorf("OC Memory 1 not correct got: %08x wanted: %08x", v, mv)
	}
}

// exclusive or character.
func (cw *cornwellFixture) TestCycleXC(t *testing.T) {
	cw.setup()

	cw.setMemory(0x358, 0x00001790)
	cw.setMemory(0x360, 0x00001401)
	cw.c.GR[7] = 0x00000358
	cw.setMemory(0x400, 0xd7037000)
	cw.setMemory(0x404, 0x70080000) // XC 0(4,7),8(7)
	cw.testInst(0)
	v := cw.getMemory(0x358)
	mv := uint32(0x00000391)
	if v != mv {
		t.Errorf("XC Memory 1 not correct got: %08x wanted: %08x", v, mv)
	}

	cw.setMemory(0x400, 0xd7037008)
	cw.setMemory(0x404, 0x70000000) // XC 8(4,7),0(7)
	cw.testInst(0)
	v = cw.getMemory(0x360)
	mv = uint32(0x00001790)
	if v != mv {
		t.Errorf("XC Memory 2 not correct got: %08x wanted: %08x", v, mv)
	}

	cw.setMemory(0x400, 0xd7037000)
	cw.setMemory(0x404, 0x70080000) // XC 0(4,7),8(7)
	cw.testInst(0)
	v = cw.getMemory(0x358)
	mv = uint32(0x00001401)
	if v != mv {
		t.Errorf("XC Memory 3 not correct got: %08x wanted: %08x", v, mv)
	}
}

// translate.
func (cw *cornwellFixture) TestCycleTR(t *testing.T) {
	cw.setup()

	// Based on Princ Ops p147
	for i := uint32(0); i < 256; i += 4 {
		// Table increments each char by 3. Don't worry about wrapping.
		cw.setMemory(0x1000+i, (((i + 3) << 24) |
			((i + 4) << 16) |
			((i + 5) << 8) |
			(i + 6)))
	}
	cw.setMemory(0x2100, 0x12345678)
	cw.setMemory(0x2104, 0xabcdef01)
	cw.setMemory(0x2108, 0x11223344)
	cw.setMemory(0x210c, 0x55667788)
	cw.setMemory(0x2110, 0x99aabbcc)
	cw.c.GR[12] = 0x00002100
	cw.c.GR[15] = 0x00001000
	cw.setMemory(0x400, 0xdc13c000)
	cw.setMemory(0x404, 0xf0000000) // TR 0(20,12),0(15)
	cw.testInst(0)
	v := cw.getMemory(0x2100)
	mv := uint32(0x1537597b)
	if v != mv {
		t.Errorf("TR Memory 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getMemory(0x2104)
	mv = uint32(0xaed0f204)
	if v != mv {
		t.Errorf("TR Memory 2 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getMemory(0x2108)
	mv = uint32(0x14253647)
	if v != mv {
		t.Errorf("TR Memory 2 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getMemory(0x210c)
	mv = uint32(0x58697a8b)
	if v != mv {
		t.Errorf("TR Memory 3 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getMemory(0x2110)
	mv = uint32(0x9cadbecf)
	if v != mv {
		t.Errorf("TR Memory 4 not correct got: %08x wanted: %08x", v, mv)
	}
}

// Translate and test.
func (cw *cornwellFixture) TestCycleTRT(t *testing.T) {
	cw.setup()

	// Based on Princ Ops p147
	for i := uint32(0); i < 256; i += 4 {
		cw.setMemory(0x2000+i, 0)
	}
	cw.setMemory(0x204c, 0x10202500)
	cw.setMemory(0x2050, 0x90000000)
	cw.setMemory(0x2058, 0x00000030)
	cw.setMemory(0x205c, 0x35404500)
	cw.setMemory(0x2060, 0x80850000)
	cw.setMemory(0x2068, 0x00000050)
	cw.setMemory(0x206c, 0x55000000)
	cw.setMemory(0x2078, 0x00000060)
	cw.setMemory(0x207c, 0x65707500)

	cw.setMemory(0x3000, 0x40404040)
	cw.setMemory(0x3004, 0x40e4d5d7) //  UNP
	cw.setMemory(0x3008, 0xd2404040) // K
	cw.setMemory(0x300c, 0x4040d7d9) //   PR
	cw.setMemory(0x3010, 0xd6e4e34d) // OUT(
	cw.setMemory(0x3014, 0xf95d6be6) // 9),W
	cw.setMemory(0x3018, 0xd6d9c44d) // ORD(
	cw.setMemory(0x301C, 0xf55d0000) // 5)

	cw.c.GR[1] = 0x3000
	cw.c.GR[2] = 0
	cw.c.GR[15] = 0x2000

	cw.setMemory(0x400, 0xdd1d1000) // TRT 0(30,1),0(15)
	cw.setMemory(0x404, 0xf0000000)
	cw.testInst(0)
	v := cw.c.GR[1] // Match at 3013
	mv := uint32(0x00003013)
	if v != mv {
		t.Errorf("TRT Register 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.c.GR[2] // Function value from table
	mv = uint32(0x00000020)
	if v != mv {
		t.Errorf("TRT Register 2 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 1 { // not complete
		t.Errorf("TRT CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}

	// Based on Princ Ops p147
	for i := uint32(0); i < 256; i += 4 {
		cw.setMemory(0x1000+i, 0)
	}
	cw.setMemory(0x2020, 0x10203040)
	cw.setMemory(0x3000, 0x12345621) // 21 will match table entry 20
	cw.setMemory(0x3004, 0x11223344)
	cw.setMemory(0x3008, 0x55667788)
	cw.setMemory(0x300c, 0x99aabbcc)
	cw.setMemory(0x400, 0xdd0f1000)
	cw.setMemory(0x404, 0xf0000000) // TRT 0(16,1),0(15)
	cw.c.GR[1] = 0x3000
	cw.c.GR[2] = 0
	cw.c.GR[15] = 0x2000
	cw.testInst(0)
	v = cw.c.GR[1] // Match at 3013
	mv = uint32(0x00003003)
	if v != mv {
		t.Errorf("TRT Register 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.c.GR[2] // Function value from table
	mv = uint32(0x00000020)
	if v != mv {
		t.Errorf("TRT Register 2 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 1 { // not complete
		t.Errorf("TRT CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}
}

// Test SPM instruction.
func (cw *cornwellFixture) TestCycleSPM(t *testing.T) {
	cw.setup()

	cw.c.GR[1] = 0x12345678         // Mask 2
	cw.setMemory(0x400, 0x041f0000) // SPM 1
	cw.testInst(0)
	v := cw.c.PSW.ProgMask
	mv := uint8(0x2)
	if v != mv {
		t.Errorf("SPM Mask not correct got: %02x wanted: %02x", v, mv)
	}
	if cw.c.PSW.CC != 1 { // not complete
		t.Errorf("SPM CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}
}

// Test SSM instruction.
func (cw *cornwellFixture) TestCycleSSM(t *testing.T) {
	cw.setup()

	cw.c.setSystemMask(0xff00>>8&0xfe | b2(cw.c.PSW.Ext))
	cw.c.PSW.Key = 0x30 >> 4
	cw.c.PSW.Problem = false // privileged
	cw.c.PSW.CC = 1
	cw.c.GR[3] = 0x11
	cw.setMemory(0x110, 0xaabbccdd) // Access byte 1
	cw.setMemory(0x400, 0x80ee3100) // "SSM 100(3)
	cw.setMemory(0x404, 0x00000000)
	cw.testInst(0)
	v := cw.channelMask()
	mv := uint16(0xBBFF)
	if v != mv {
		t.Errorf("SSM Mask not correct got: %04x wanted: %04x", v, mv)
	}
	v1 := (cw.c.PSW.Key << 4)
	mv1 := uint8(0x30)
	if v1 != mv1 {
		t.Errorf("SSM Key not correct got: %02x wanted: %02x", v1, mv1)
	}
	v1 = cw.c.PSW.ProgMask
	mv1 = uint8(0x0)
	if v1 != mv1 {
		t.Errorf("SSM Prog Mask not correct got: %02x wanted: %02x", v1, mv1)
	}
	if cw.c.PSW.CC != 1 {
		t.Errorf("SPM CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}
	v2 := cw.c.PSW.IA
	mv2 := uint32(0x404)
	if v2 != mv2 {
		t.Errorf("SSM PC not correct got: %04x wanted: %04x", v2, mv2)
	}
	if !cw.c.PSW.Ext {
		t.Error("SSM External mask not set")
	}
	cw.c.PSW.Key = 0x00 >> 4

	cw.c.setSystemMask(0xff00>>8&0xfe | b2(cw.c.PSW.Ext))
	cw.c.PSW.Problem = true // problem state
	cw.c.PSW.CC = 1
	cw.c.GR[3] = 0x11
	cw.setMemory(0x110, 0xaabbccdd) // Access byte 1
	cw.setMemory(0x400, 0x80ee3100) // "SSM 100(3)
	cw.setMemory(0x404, 0x00000000)
	cw.testInst(0)
	if !cw.trap {
		t.Error("SSM in problem state did not trap")
	}
	cw.c.PSW.Problem = false
}

// Test lpsw instruction.
func (cw *cornwellFixture) TestCycleLPSW(t *testing.T) {
	cw.setup()

	cw.c.PSW.Key = 0 >> 4
	cw.c.PSW.Problem = false // privileged
	cw.c.GR[3] = 0x10
	cw.setMemory(0x110, 0xE1345678)
	cw.setMemory(0x114, 0x9a003450)  // Branch to 123450
	cw.setMemory(0x400, 0x82003100)  // LPSW 100(3)
	cw.setMemory(0x3450, 0x00000000) // Nop in case things are executed
	cw.testInst(0)
	v := cw.channelMask()
	mv := uint16(0xe000)
	if v != mv {
		t.Errorf("LPSW Mask not correct got: %04x wanted: %04x", v, mv)
	}
	v1 := (cw.c.PSW.Key << 4)
	mv1 := uint8(0x30)
	if v1 != mv1 {
		t.Errorf("LPSW Key not correct got: %02x wanted: %02x", v1, mv1)
	}
	v1 = cw.c.PSW.ProgMask
	mv1 = uint8(0xa)
	if v1 != mv1 {
		t.Errorf("LPSW Prog Mask not correct got: %02x wanted: %02x", v1, mv1)
	}
	if cw.c.PSW.CC != 1 {
		t.Errorf("LPSW CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}
	v2 := cw.c.PSW.IA
	mv2 := uint32(0x003450)
	if v2 != mv2 {
		t.Errorf("LPSW PC not correct got: %04x wanted: %04x", v2, mv2)
	}
	if !cw.c.PSW.Ext {
		t.Error("LPSW External mask not set")
	}
	cw.c.PSW.Key = 0x00 >> 4
}

// Supervisory call.
func (cw *cornwellFixture) TestCycleSVC(t *testing.T) {
	cw.setup()

	cw.c.PSW.Key = 0 >> 4
	cw.c.PSW.Problem = true // privileged
	cw.c.setSystemMask(0xe000>>8&0xfe | b2(cw.c.PSW.Ext))
	cw.c.PSW.Ext = true
	cw.c.PSW.CC = 1
	cw.c.GR[3] = 0x10
	cw.setMemory(0x60, 0xE1345678)
	cw.setMemory(0x64, 0x9a003450)   // Branch to 3450
	cw.setMemory(0x400, 0x0a120000)  // SVC 12
	cw.setMemory(0x3450, 0x00000000) // Nop in case things are executed
	cw.testInst(0x4)
	v := cw.channelMask()
	mv := uint16(0xe000)
	if v != mv {
		t.Errorf("SVC Mask not correct got: %04x wanted: %04x", v, mv)
	}
	v1 := (cw.c.PSW.Key << 4)
	mv1 := uint8(0x30)
	if v1 != mv1 {
		t.Errorf("SVC Key not correct got: %02x wanted: %02x", v1, mv1)
	}
	v1 = cw.c.PSW.ProgMask
	mv1 = uint8(0xa)
	if v1 != mv1 {
		t.Errorf("SVC Prog Mask not correct got: %02x wanted: %02x", v1, mv1)
	}
	if cw.c.PSW.CC != 1 {
		t.Errorf("SVC CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}
	v2 := cw.c.PSW.IA
	mv2 := uint32(0x003450)
	if v2 != mv2 {
		t.Errorf("SVC PC not correct got: %04x wanted: %04x", v2, mv2)
	}
	if !cw.c.PSW.Ext {
		t.Error("SVC External mask not set")
	}
	v2 = cw.getMemory(0x20)
	mv2 = uint32(0xE1010012)
	if v2 != mv2 {
		t.Errorf("TR Memory 1 not correct got: %08x wanted: %08x", v2, mv2)
	}
	v2 = cw.getMemory(0x24)
	mv2 = uint32(0x54000402)
	if v2 != mv2 {
		t.Errorf("SVC Memory 2 not correct got: %08x wanted: %08x", v2, mv2)
	}
	cw.c.PSW.Key = 0x00 >> 4
}

// Set storage key.
func (cw *cornwellFixture) TestCycleSSK(t *testing.T) {
	cw.setup()

	cw.c.PSW.Problem = true // unprivileged
	cw.c.GR[1] = 0x11223344 // Key
	cw.c.GR[2] = 0x00005600 // Address: last 4 bits must be 0
	cw.putKey(0x5600, 0x40)
	cw.setMemory(0x400, 0x08120000) // SSK 1,2
	cw.testInst(0)
	if !cw.trap {
		t.Error("SSK should have trapped")
	}
	if cw.getKey(0x5600) != 0x40 {
		t.Errorf("SSK unprivileged changed key got: %02x expected: %02x", cw.getKey(0x5600), 0x40)
	}

	cw.c.PSW.Problem = false // privileged
	cw.c.GR[1] = 0x11223344  // Key
	cw.c.GR[2] = 0x00005600  // Address: last 4 bits must be 0
	cw.putKey(0x5600, 0)
	cw.setMemory(0x400, 0x08120000) // SSK 1,2
	cw.testInst(0)
	// Upstream expects 0x40 (five-bit key). S/370 with DAT retains R/C
	// bits in both BC and EC modes: GR1 ends in 0x44. See README.md.
	if cw.getKey(0x5600) != 0x44 {
		t.Errorf("SSK privileged key got: %02x expected: %02x", cw.getKey(0x5600), 0x44)
	}

	cw.c.PSW.Problem = false // privileged
	cw.c.GR[1] = 0x11223344  // Key
	cw.c.GR[2] = 0x12345674  // Address: last 4 bits must be 0
	cw.putKey(0x5600, 0x70)
	cw.setMemory(0x400, 0x08120000) // SSK 1,2
	cw.testInst(0)
	if !cw.trap {
		t.Error("SSK should have trapped")
	}
	if cw.getKey(0x5600) != 0x70 {
		t.Errorf("SSK unaligned changed key got: %02x expected: %02x", cw.getKey(0x5600), 0x70)
	}
}

// ISK reads the storage key.
func (cw *cornwellFixture) TestCycleISK(t *testing.T) {
	cw.setup()

	cw.c.PSW.Problem = true // unprivileged
	cw.c.GR[1] = 0x11223344 // Key
	cw.c.GR[2] = 0x00005600 // Address: last 4 bits must be 0
	cw.putKey(0x5600, 0x40)
	cw.setMemory(0x400, 0x09120000) // ISK 1,2
	cw.testInst(0)
	if !cw.trap {
		t.Error("ISK should have trapped")
	}

	cw.c.PSW.Problem = false // privileged
	cw.c.GR[1] = 0x89abcdef  // Key
	cw.c.GR[2] = 0x00005600  // Address: last 4 bits must be 0
	cw.putKey(0x5600, 0x20)
	cw.setMemory(0x400, 0x09120000) // ISK 1,2
	cw.testInst(0)
	v := cw.c.GR[1]
	mv := uint32(0x89abcd20)
	if v != mv {
		t.Errorf("ISK Register 1 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.getKey(0x5600) != 0x20 {
		t.Errorf("ISK privileged changed key got: %02x expected: %02x", cw.getKey(0x5600), 0x20)
	}

	cw.c.PSW.Problem = false // privileged
	cw.c.GR[1] = 0x11223344  // Key
	cw.c.GR[2] = 0x12345674  // Address: last 4 bits must be 0
	cw.putKey(0x5600, 0x70)
	cw.setMemory(0x400, 0x09120000) // ISK 1,2
	cw.testInst(0)
	if !cw.trap {
		t.Error("ISK should have trapped")
	}
	if cw.getKey(0x5600) != 0x70 {
		t.Errorf("ISK unaligned changed key got: %02x expected: %02x", cw.getKey(0x5600), 0x70)
	}
}

// Protection check. unmatched key.
func (cw *cornwellFixture) TestCycleProt(t *testing.T) {
	cw.setup()

	cw.c.PSW.Problem = true // unprivileged
	cw.c.PSW.Key = 0x20 >> 4
	cw.c.GR[1] = 0x11223344
	cw.c.GR[2] = 0x00005670
	cw.setMemory(0x5678, 0xff)
	cw.putKey(0x5600, 0x40)
	cw.setMemory(0x400, 0x50102008) // st 1,0(2)
	cw.testInst(0)
	if !cw.trap {
		t.Error("Store to wrong key did not trap")
	}
	v := cw.getMemory(0x5678)
	mv := uint32(0xff)
	if v != mv {
		t.Errorf("Store to wrong key changed memory correct got: %08x wanted: %08x", v, mv)
	}

	cw.c.PSW.Problem = true // unprivileged
	cw.c.PSW.Key = 0x40 >> 4
	cw.c.GR[1] = 0x11223344
	cw.c.GR[2] = 0x00005670
	cw.setMemory(0x5678, 0xff)
	cw.putKey(0x5600, 0x40)
	cw.setMemory(0x400, 0x50102008) // st 1,0(2)
	cw.testInst(0)
	if cw.trap {
		t.Error("Store to correct key traped")
	}
	v = cw.getMemory(0x5678)
	mv = uint32(0x11223344)
	if v != mv {
		t.Errorf("Store to wrong key changed memory correct got: %08x wanted: %08x", v, mv)
	}

	cw.c.PSW.Problem = true // unprivileged
	cw.c.PSW.Key = 0x20 >> 4
	cw.c.GR[1] = 0x11223344
	cw.c.GR[2] = 0x00005670
	cw.setMemory(0x5678, 0xff)
	cw.putKey(0x5600, 0x40)
	cw.setMemory(0x400, 0x58102008) // l 1,0(2)
	cw.setMemory(0x5678, 0x12345678)
	cw.testInst(0)
	if cw.trap {
		t.Error("Load to wrong key traped")
	}
	v = cw.getMemory(0x5678)
	mv = uint32(0x12345678)
	if v != mv {
		t.Errorf("Load to wrong key did not load register correct got: %08x wanted: %08x", v, mv)
	}

	cw.c.PSW.Problem = true // unprivileged
	cw.c.PSW.Key = 0x40 >> 4
	cw.c.GR[1] = 0x11223344
	cw.c.GR[2] = 0x00005670
	cw.setMemory(0x5678, 0xff)
	cw.putKey(0x5600, 0x40)
	cw.setMemory(0x400, 0x58102008) // l 1,0(2)
	cw.setMemory(0x5678, 0x12345678)
	cw.testInst(0)
	if cw.trap {
		t.Error("Load to correct key traped")
	}
	v = cw.getMemory(0x5678)
	mv = uint32(0x12345678)
	if v != mv {
		t.Errorf("Load to correct key did not change register correct got: %08x wanted: %08x", v, mv)
	}

	cw.c.PSW.Problem = true // unprivileged
	cw.c.PSW.Key = 0x00 >> 4
	cw.c.GR[1] = 0x11223344
	cw.c.GR[2] = 0x00005670
	cw.setMemory(0x5678, 0xff)
	cw.putKey(0x5600, 0x40)
	cw.setMemory(0x400, 0x50102008) // st 1,0(2)
	cw.testInst(0)
	if cw.trap {
		t.Error("Store zero key did trap")
	}
	v = cw.getMemory(0x5678)
	mv = uint32(0x11223344)
	if v != mv {
		t.Errorf("Store to zero did not update memory correct got: %08x wanted: %08x", v, mv)
	}

	// Test fetch protection
	cw.c.PSW.Problem = true // unprivileged
	cw.c.PSW.Key = 0x20 >> 4
	cw.c.GR[1] = 0x11223344
	cw.c.GR[2] = 0x00005670
	cw.setMemory(0x5678, 0xff)
	cw.putKey(0x5600, 0x41)
	cw.setMemory(0x400, 0x58102008) // l 1,0(2)
	cw.setMemory(0x5678, 0x12345678)
	cw.testInst(0)
	if cw.trap {
		t.Error("Load to fetch protected key traped")
	}
	v = cw.getMemory(0x5678)
	mv = uint32(0x12345678)
	if v != mv {
		t.Errorf("Load to fetch protected key did load register correct got: %08x wanted: %08x", v, mv)
	}

	cw.c.PSW.Problem = true // unprivileged
	cw.c.PSW.Key = 0x40 >> 4
	cw.c.GR[1] = 0x11223344
	cw.c.GR[2] = 0x00005670
	cw.setMemory(0x5678, 0xff)
	cw.putKey(0x5600, 0x41)
	cw.setMemory(0x400, 0x58102008) // l 1,0(2)
	cw.setMemory(0x5678, 0x12345678)
	cw.testInst(0)
	if cw.trap {
		t.Error("Load to  fetch correct key traped")
	}
	v = cw.getMemory(0x5678)
	mv = uint32(0x12345678)
	if v != mv {
		t.Errorf("Load to correct key did change register correct got: %08x wanted: %08x", v, mv)
	}
	cw.c.PSW.Problem = false
	cw.c.PSW.Key = 0x00 >> 4
	cw.putKey(0x5600, 0)
}

// Test and set.
func (cw *cornwellFixture) TestCycleTS(t *testing.T) {
	cw.setup()

	cw.c.GR[2] = 2                  // Index
	cw.setMemory(0x100, 0x83857789) // 102 top bit not set
	cw.setMemory(0x400, 0x93002100) // TS 100(2)
	cw.testInst(0)
	v := cw.getMemory(0x100)
	mv := uint32(0x8385ff89)
	if v != mv {
		t.Errorf("TS Memory 1 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 0 { // not complete
		t.Errorf("TS CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}

	cw.c.PSW.CC = 3
	cw.c.GR[2] = 2                  // Index
	cw.setMemory(0x100, 0x8385c789) // 102 top bit not set
	cw.setMemory(0x400, 0x93002100) // TS 100(2)
	cw.testInst(0)
	v = cw.getMemory(0x100)
	mv = uint32(0x8385ff89)
	if v != mv {
		t.Errorf("TS Memory 1 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 1 { // not complete
		t.Errorf("TS CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}
}

// Edit test.
func (cw *cornwellFixture) TestCycleED(t *testing.T) {
	cw.setup()

	cw.c.GR[12] = 0x1000
	cw.setMemory(0x1200, 0x0257426c)
	cw.setMemory(0x1000, 0x4020206b)
	cw.setMemory(0x1004, 0x2020214b)
	cw.setMemory(0x1008, 0x202040c3)
	cw.setMemory(0x100c, 0xd9ffffff)
	cw.setMemory(0x400, 0xde0cc000)
	cw.setMemory(0x404, 0xc2000000) // ED 0(13,12),200(12)
	cw.testInst(0)
	v := cw.getMemory(0x1000)
	mv := uint32(0x4040f26b)
	if v != mv {
		t.Errorf("ED Memory 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getMemory(0x1004)
	mv = uint32(0xf5f7f44b)
	if v != mv {
		t.Errorf("ED Memory 2 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getMemory(0x1008)
	mv = uint32(0xf2f64040)
	if v != mv {
		t.Errorf("ED Memory 3 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getMemory(0x100c)
	mv = uint32(0x40ffffff)
	if v != mv {
		t.Errorf("ED Memory 4 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 2 { // not complete
		t.Errorf("ED CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}

	cw.c.GR[12] = 0x1000
	cw.setMemory(0x1200, 0x0000026d)
	cw.setMemory(0x1000, 0x4020206b)
	cw.setMemory(0x1004, 0x2020214b)
	cw.setMemory(0x1008, 0x202040c3)
	cw.setMemory(0x100c, 0xd9ffffff)
	cw.setMemory(0x400, 0xde0cc000)
	cw.setMemory(0x404, 0xc2000000) // ED 0(13,12),200(12)
	cw.testInst(0)
	v = cw.getMemory(0x1000)
	mv = uint32(0x40404040)
	if v != mv {
		t.Errorf("ED Memory 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getMemory(0x1004)
	mv = uint32(0x4040404b)
	if v != mv {
		t.Errorf("ED Memory 2 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getMemory(0x1008)
	mv = uint32(0xf2f640c3)
	if v != mv {
		t.Errorf("ED Memory 3 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getMemory(0x100c)
	mv = uint32(0xd9ffffff)
	if v != mv {
		t.Errorf("ED Memory 4 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 1 { // not complete
		t.Errorf("ED CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}
}

// Edit and mark.
func (cw *cornwellFixture) TestCycleEDMK(t *testing.T) {
	cw.setup()

	cw.c.GR[1] = 0xaabbccdd
	cw.c.GR[12] = 0x1000
	cw.setMemory(0x1200, 0x0000026d)
	cw.setMemory(0x1000, 0x4020206b)
	cw.setMemory(0x1004, 0x2020214b)
	cw.setMemory(0x1008, 0x202040c3)
	cw.setMemory(0x100c, 0xd9ffffff)
	cw.setMemory(0x400, 0xdf0cc000)
	cw.setMemory(0x404, 0xc2000000) // EDMK 0(13,12),200(12)
	cw.testInst(0)
	v := cw.getMemory(0x1000)
	mv := uint32(0x40404040)
	if v != mv {
		t.Errorf("EDMK Memory 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getMemory(0x1004)
	mv = uint32(0x4040404b)
	if v != mv {
		t.Errorf("EDMK Memory 2 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getMemory(0x1008)
	mv = uint32(0xf2f640c3)
	if v != mv {
		t.Errorf("EDMK Memory 3 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getMemory(0x100c)
	mv = uint32(0xd9ffffff)
	if v != mv {
		t.Errorf("EDMK Memory 4 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.c.GR[1]
	mv = uint32(0xaabbccdd)
	if v != mv {
		t.Errorf("EDMK Register 1 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 1 { // not complete
		t.Errorf("EDMK CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}

	cw.c.GR[1] = 0xaabbccdd
	cw.c.GR[12] = 0x1000
	cw.setMemory(0x1200, 0x0000026d)
	cw.setMemory(0x1000, 0x4020206b)
	cw.setMemory(0x1004, 0x2020204b)
	cw.setMemory(0x1008, 0x202040c3)
	cw.setMemory(0x100c, 0xd9ffffff)
	cw.setMemory(0x400, 0xdf0cc000)
	cw.setMemory(0x404, 0xc2000000) // EDMK 0(13,12),200(12)
	cw.testInst(0)
	v = cw.getMemory(0x1000)
	mv = uint32(0x40404040)
	if v != mv {
		t.Errorf("EDMK Memory 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getMemory(0x1004)
	mv = uint32(0x40404040)
	if v != mv {
		t.Errorf("EDMK Memory 2 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getMemory(0x1008)
	mv = uint32(0xf2f640c3)
	if v != mv {
		t.Errorf("EDMK Memory 3 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getMemory(0x100c)
	mv = uint32(0xd9ffffff)
	if v != mv {
		t.Errorf("EDMK Memory 4 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.c.GR[1]
	mv = uint32(0xaa001008)
	if v != mv {
		t.Errorf("EDMK Register 1 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 1 { // not complete
		t.Errorf("EDMK CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}
}

func (cw *cornwellFixture) TestCycleCLM(t *testing.T) {
	cw.setup()
	cw.c.GR[1] = 0xFF00FF00
	cw.c.GR[2] = 0x00FFFF00
	cw.setMemory(0x500, 0xFFFFFFFF)
	cw.setMemory(0x400, 0xbd1a0500) // CLM 1,b'1010', 500
	cw.setMemory(0x404, 0x00000000)
	cw.testInst(0)
	if cw.c.PSW.CC != 0 {
		t.Errorf("CLM CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0xbd260500) // CLM 2,b'0110', 500
	cw.setMemory(0x404, 0x00000000)
	cw.testInst(0)
	if cw.c.PSW.CC != 0 {
		t.Errorf("CLM CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0xbd130500) // CLM 1,b'0011', 500
	cw.setMemory(0x404, 0x00000000)
	cw.testInst(0)
	if cw.c.PSW.CC != 1 {
		t.Errorf("CLM CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}

	cw.c.GR[1] = 0x01050102
	cw.c.GR[2] = 0x00010203
	cw.setMemory(0x500, 0x01020304)
	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0xbd190500) // CLM 1,b'1001', 500
	cw.setMemory(0x404, 0x00000000)
	cw.testInst(0)
	if cw.c.PSW.CC != 0 {
		t.Errorf("CLM CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0xbd260500) // CLM 2,b'0110', 500
	cw.setMemory(0x404, 0x00000000)
	cw.testInst(0)
	if cw.c.PSW.CC != 0 {
		t.Errorf("CLM CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0xbd150500) // CLM 1,b'0101', 500
	cw.setMemory(0x404, 0x00000000)
	cw.testInst(0)
	if cw.c.PSW.CC != 2 {
		t.Errorf("CLM CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0xbd230500) // CLM 2,b'0011', 500
	cw.setMemory(0x404, 0x00000000)
	cw.testInst(0)
	if cw.c.PSW.CC != 2 {
		t.Errorf("CLM CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}
}

func (cw *cornwellFixture) TestCycleICM(t *testing.T) {
	cw.setup()
	cw.c.GR[1] = 0x00000000
	cw.setMemory(0x500, 0x01020304)
	cw.setMemory(0x400, 0xbF130500) // ICM 1,b'0011', 500
	cw.setMemory(0x404, 0x00000000)
	cw.testInst(0)
	if cw.c.PSW.CC != 2 {
		t.Errorf("ICM CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}
	if cw.c.GR[1] != 0x00000102 {
		t.Errorf("ICM R1 not correct got: %x wanted: %x", cw.c.GR[1], 0x00000102)
	}

	cw.c.PSW.CC = 3
	cw.c.GR[1] = 0x00000000
	cw.setMemory(0x400, 0xbF190500) // ICM 1,b'1001', 500
	cw.setMemory(0x404, 0x00000000)
	cw.testInst(0)
	if cw.c.PSW.CC != 2 {
		t.Errorf("ICM CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}
	if cw.c.GR[1] != 0x01000002 {
		t.Errorf("ICM R1 not correct got: %x wanted: %x", cw.c.GR[1], 0x01000002)
	}

	cw.c.PSW.CC = 3
	cw.c.GR[1] = 0xd0d0d0d0
	cw.setMemory(0x400, 0xbF130500) // ICM 1,b'0011', 500
	cw.setMemory(0x404, 0x00000000)
	cw.testInst(0)
	if cw.c.PSW.CC != 2 {
		t.Errorf("ICM CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}
	if cw.c.GR[1] != 0xd0d00102 {
		t.Errorf("ICM R1 not correct got: %x wanted: %x", cw.c.GR[1], 0xd0d00102)
	}

	cw.c.PSW.CC = 3
	cw.c.GR[1] = 0xd0d0d0d0
	cw.setMemory(0x400, 0xbF190500) // ICM 1,b'1001', 500
	cw.setMemory(0x404, 0x00000000)
	cw.testInst(0)
	if cw.c.PSW.CC != 2 {
		t.Errorf("ICM CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}
	if cw.c.GR[1] != 0x01d0d002 {
		t.Errorf("ICM R1 not correct got: %x wanted: %x", cw.c.GR[1], 0x01d0d002)
	}

	cw.c.PSW.CC = 3
	cw.c.GR[1] = 0x00000000
	cw.setMemory(0x400, 0xbF170500) // ICM 1,b'0111', 500
	cw.setMemory(0x404, 0x00000000)
	cw.testInst(0)
	if cw.c.PSW.CC != 2 {
		t.Errorf("ICM CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}
	if cw.c.GR[1] != 0x00010203 {
		t.Errorf("ICM R1 not correct got: %x wanted: %x", cw.c.GR[1], 0x00010203)
	}

	cw.c.PSW.CC = 3
	cw.c.GR[1] = 0x00000000
	cw.setMemory(0x500, 0xf0f1f2f3)
	cw.setMemory(0x400, 0xbF130500) // ICM 1,b'0011', 500
	cw.setMemory(0x404, 0x00000000)
	cw.testInst(0)
	if cw.c.PSW.CC != 1 {
		t.Errorf("ICM CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}
	if cw.c.GR[1] != 0x0000F0F1 {
		t.Errorf("ICM R1 not correct got: %x wanted: %x", cw.c.GR[1], 0x0000F0F1)
	}

	cw.c.PSW.CC = 3
	cw.c.GR[1] = 0xd0d0d0d0
	cw.setMemory(0x500, 0xf0f1f2f3)
	cw.setMemory(0x400, 0xbF190500) // ICM 1,b'1001', 500
	cw.setMemory(0x404, 0x00000000)
	cw.testInst(0)
	if cw.c.PSW.CC != 1 {
		t.Errorf("ICM CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}
	if cw.c.GR[1] != 0xf0d0d0f1 {
		t.Errorf("ICM R1 not correct got: %x wanted: %x", cw.c.GR[1], 0xf0d0d0f1)
	}

	cw.c.PSW.CC = 3
	cw.c.GR[1] = 0xd0d0d0d0
	cw.setMemory(0x500, 0x00000000)
	cw.setMemory(0x400, 0xbF130500) // ICM 1,b'0011', 500
	cw.setMemory(0x404, 0x00000000)
	cw.testInst(0)
	if cw.c.PSW.CC != 0 {
		t.Errorf("ICM CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}
	if cw.c.GR[1] != 0xD0D00000 {
		t.Errorf("ICM R1 not correct got: %x wanted: %x", cw.c.GR[1], 0xD0D00000)
	}

	cw.c.GR[1] = 0x01050102
	cw.c.GR[2] = 0x00010203
	cw.setMemory(0x500, 0x01020304)
	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0xbd190500) // ICM 1,b'1001', 500
	cw.setMemory(0x404, 0x00000000)
	cw.testInst(0)
	if cw.c.PSW.CC != 0 {
		t.Errorf("ICM CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0xbd260500) // ICM 2,b'0110', 500
	cw.setMemory(0x404, 0x00000000)
	cw.testInst(0)
	if cw.c.PSW.CC != 0 {
		t.Errorf("ICM CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0xbd150500) // ICM 1,b'0101', 500
	cw.setMemory(0x404, 0x00000000)
	cw.testInst(0)
	if cw.c.PSW.CC != 2 {
		t.Errorf("ICM CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}

	cw.c.PSW.CC = 3
	cw.setMemory(0x400, 0xbd230500) // ICM 2,b'0011', 500
	cw.setMemory(0x404, 0x00000000)
	cw.testInst(0)
	if cw.c.PSW.CC != 2 {
		t.Errorf("ICM CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}
}

func (cw *cornwellFixture) TestCycleSTCM(t *testing.T) {
	cw.setup()
	cw.c.PSW.CC = 3
	cw.c.GR[3] = 0xf0f1f2f3
	cw.setMemory(0x500, 0xf0f1f2f3)
	cw.setMemory(0x400, 0xbe330500) // STCM 3,b'0011', 500
	cw.setMemory(0x404, 0x00000000)
	cw.testInst(0)
	if cw.c.PSW.CC != 3 {
		t.Errorf("STCM CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}
	v := cw.getMemory(0x500)
	if v != 0xf2f3f2f3 {
		t.Errorf("STCM memory not correct got: %x wanted: %x", v, 0xf2f3f2f3)
	}
	if cw.c.GR[3] != 0xf0f1f2f3 {
		t.Errorf("STCM R3 not correct got: %x wanted: %x", cw.c.GR[3], 0xf0f1f2f3)
	}

	cw.c.PSW.CC = 3
	cw.c.GR[3] = 0xf0f1f2f3
	cw.setMemory(0x500, 0xf0f1f2f3)
	cw.setMemory(0x400, 0xbe390500) // STCM 3,b'1001', 500
	cw.setMemory(0x404, 0x00000000)
	cw.testInst(0)
	if cw.c.PSW.CC != 3 {
		t.Errorf("STCM CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}
	v = cw.getMemory(0x500)
	if v != 0xf0f3f2f3 {
		t.Errorf("STCM memory not correct got: %x wanted: %x", v, 0xf0f3f2f3)
	}
	if cw.c.GR[3] != 0xf0f1f2f3 {
		t.Errorf("STCM R3 not correct got: %x wanted: %x", cw.c.GR[3], 0xf0f1f2f3)
	}

	cw.c.PSW.CC = 3
	cw.c.GR[1] = 0xf0f1f2f3
	cw.setMemory(0x500, 0x00000000)
	cw.setMemory(0x400, 0xbe3f0500) // STCM 3,b'1111', 500
	cw.setMemory(0x404, 0x00000000)
	cw.testInst(0)
	if cw.c.PSW.CC != 3 {
		t.Errorf("STCM CC not correct got: %x wanted: %x", cw.c.PSW.CC, 3)
	}
	v = cw.getMemory(0x500)
	if v != 0xf0f1f2f3 {
		t.Errorf("STCM memory not correct got: %x wanted: %x", v, 0xf0f1f2f3)
	}
	if cw.c.GR[1] != 0xf0f1f2f3 {
		t.Errorf("STCM R3 not correct got: %x wanted: %x", cw.c.GR[1], 0xf0f1f2f3)
	}
}

func (cw *cornwellFixture) TestCycleCLCL(t *testing.T) {
	cw.setup()

	cw.setMemory(0x500, 0xf0f1f2f3)
	cw.setMemory(0x504, 0xf4f5f6f7)
	cw.setMemory(0x508, 0xf8f9f0f0)
	cw.setMemory(0x50c, 0xf0f0f0f0)
	cw.setMemory(0x510, 0xf0f0f0f0)
	cw.setMemory(0x600, 0xf0f1f2f3)
	cw.setMemory(0x604, 0xf4f5f6f7)
	cw.setMemory(0x608, 0xf8f9f0f0)
	cw.setMemory(0x60c, 0xf0f0f0f0)
	cw.setMemory(0x610, 0xf0f0f0f0)
	cw.c.GR[2] = 0x500
	cw.c.GR[3] = 20
	cw.c.GR[4] = 0x600
	cw.c.GR[5] = 20
	cw.setMemory(0x400, 0x0f240000) // CLCL 2,4
	cw.testInst(0)
	if cw.c.PSW.CC != 0 {
		t.Errorf("CLCL CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}

	if cw.c.GR[2] != 0x500+20 {
		t.Errorf("CLCL R2 not correct got: %x wanted: %x", cw.c.GR[2], 0x500+20)
	}

	if cw.c.GR[3] != 0 {
		t.Errorf("CLCL R3 not correct got: %x wanted: %x", cw.c.GR[3], 0)
	}

	if cw.c.GR[4] != 0x600+20 {
		t.Errorf("CLCL R4 not correct got: %x wanted: %x", cw.c.GR[4], 0x600+20)
	}

	if cw.c.GR[5] != 0 {
		t.Errorf("CLCL R5 not correct got: %x wanted: %x", cw.c.GR[5], 0)
	}

	cw.c.GR[2] = 0x500
	cw.c.GR[3] = 20
	cw.c.GR[4] = 0x600
	cw.c.GR[5] = 0xf0000000 + 10
	cw.setMemory(0x400, 0x0f240000) // CLCL 2,4
	cw.testInst(0)
	if cw.c.PSW.CC != 0 {
		t.Errorf("CLCL CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}

	if cw.c.GR[2] != 0x500+20 {
		t.Errorf("CLCL R2 not correct got: %x wanted: %x", cw.c.GR[2], 0x500+20)
	}

	if cw.c.GR[3] != 0 {
		t.Errorf("CLCL R3 not correct got: %x wanted: %x", cw.c.GR[3], 0)
	}

	if cw.c.GR[4] != 0x600+10 {
		t.Errorf("CLCL R4 not correct got: %x wanted: %x", cw.c.GR[4], 0x600+10)
	}

	if cw.c.GR[5] != 0xf0000000 {
		t.Errorf("CLCL R5 not correct got: %x wanted: %x", cw.c.GR[5], 0xf0000000)
	}

	cw.c.GR[2] = 0x500
	cw.c.GR[3] = 10
	cw.c.GR[4] = 0x600
	cw.c.GR[5] = 0xf0000000 + 20
	cw.setMemory(0x400, 0x0f240000) // CLCL 2,4
	cw.testInst(0)
	if cw.c.PSW.CC != 0 {
		t.Errorf("CLCL CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}

	if cw.c.GR[2] != 0x500+10 {
		t.Errorf("CLCL R2 not correct got: %x wanted: %x", cw.c.GR[2], 0x500+10)
	}

	if cw.c.GR[3] != 0 {
		t.Errorf("CLCL R3 not correct got: %x wanted: %x", cw.c.GR[3], 0)
	}

	if cw.c.GR[4] != 0x600+20 {
		t.Errorf("CLCL R4 not correct got: %x wanted: %x", cw.c.GR[4], 0x600+20)
	}

	if cw.c.GR[5] != 0xf0000000 {
		t.Errorf("CLCL R5 not correct got: %x wanted: %x", cw.c.GR[5], 0xf0000000)
	}

	cw.setMemory(0x600, 0xf0f1f2f3)
	cw.setMemory(0x604, 0xf4f5f6f7)
	cw.setMemory(0x608, 0xf8f9f9f9)
	cw.setMemory(0x60c, 0xf9f9f9f9)
	cw.setMemory(0x610, 0xf9f9f9f9)
	cw.setMemory(0x400, 0x0f240000) // CLCL 2,4

	cw.c.GR[2] = 0x500
	cw.c.GR[3] = 20
	cw.c.GR[4] = 0x600
	cw.c.GR[5] = 20
	cw.testInst(0)
	if cw.c.PSW.CC != 1 {
		t.Errorf("CLCL CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}

	if cw.c.GR[2] != 0x500+10 {
		t.Errorf("CLCL R2 not correct got: %x wanted: %x", cw.c.GR[2], 0x500+10)
	}

	if cw.c.GR[3] != 10 {
		t.Errorf("CLCL R3 not correct got: %x wanted: %x", cw.c.GR[3], 10)
	}

	if cw.c.GR[4] != 0x600+10 {
		t.Errorf("CLCL R4 not correct got: %x wanted: %x", cw.c.GR[4], 0x600+10)
	}

	if cw.c.GR[5] != 10 {
		t.Errorf("CLCL R5 not correct got: %x wanted: %x", cw.c.GR[5], 10)
	}

	cw.setMemory(0x400, 0x0f420000) // CLCL 4,2

	cw.c.GR[2] = 0x500
	cw.c.GR[3] = 20
	cw.c.GR[4] = 0x600
	cw.c.GR[5] = 20
	cw.testInst(0)
	if cw.c.PSW.CC != 2 {
		t.Errorf("CLCL CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}

	if cw.c.GR[2] != 0x500+10 {
		t.Errorf("CLCL R2 not correct got: %x wanted: %x", cw.c.GR[2], 0x500+10)
	}

	if cw.c.GR[3] != 10 {
		t.Errorf("CLCL R3 not correct got: %x wanted: %x", cw.c.GR[3], 10)
	}

	if cw.c.GR[4] != 0x600+10 {
		t.Errorf("CLCL R4 not correct got: %x wanted: %x", cw.c.GR[4], 0x600+10)
	}

	if cw.c.GR[5] != 10 {
		t.Errorf("CLCL R5 not correct got: %x wanted: %x", cw.c.GR[5], 10)
	}

	cw.c.GR[2] = 0x500
	cw.c.GR[3] = 5
	cw.c.GR[4] = 0x600
	cw.c.GR[5] = 0xf5000000 + 20
	cw.setMemory(0x400, 0x0f240000) // CLCL 2,4
	cw.testInst(0)
	if cw.c.PSW.CC != 1 {
		t.Errorf("CLCL CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}

	if cw.c.GR[2] != 0x500+5 {
		t.Errorf("CLCL R2 not correct got: %x wanted: %x", cw.c.GR[2], 0x500+5)
	}

	if cw.c.GR[3] != 0 {
		t.Errorf("CLCL R3 not correct got: %x wanted: %x", cw.c.GR[3], 0)
	}

	if cw.c.GR[4] != 0x600+6 {
		t.Errorf("CLCL R4 not correct got: %x wanted: %x", cw.c.GR[4], 0x600+6)
	}

	if cw.c.GR[5] != 0xf500000e {
		t.Errorf("CLCL R5 not correct got: %x wanted: %x", cw.c.GR[5], 0xf500000e)
	}
}

// Basic Add Packed Decimal tests.
func (cw *cornwellFixture) TestCycleAP(t *testing.T) {
	cw.setup()

	// Short field
	cw.setMemory(0x100, 0x0000002c) // 2+
	cw.setMemory(0x200, 0x00003c00) // 3+
	cw.setMemory(0x400, 0xfa000103) // AP 103(1,0),202(1,0)
	cw.setMemory(0x404, 0x02020000)
	cw.testInst(0)
	v := cw.getMemory(0x100)
	mv := uint32(0x0000005c)
	if v != mv {
		t.Errorf("AP Memory 1 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("AP CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}

	// Add one
	cw.setMemory(0x100, 0x2888011c) // 2888011+
	cw.setMemory(0x200, 0x1112292c) // 1112292+
	cw.setMemory(0x400, 0xfa330100) // AP 100(4,0),200(4,0)
	cw.setMemory(0x404, 0x02000000)
	cw.testInst(0)
	v = cw.getMemory(0x100)
	mv = uint32(0x4000303c)
	if v != mv {
		t.Errorf("AP Memory 2 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("AP CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}

	// Add one
	cw.setMemory(0x100, 0x0000002c) // 2+
	cw.setMemory(0x200, 0x0000003c) // 3+
	cw.setMemory(0x400, 0xfa330100) // AP 100(4,0),200(4,0)
	cw.setMemory(0x404, 0x02000000)
	cw.testInst(0)
	v = cw.getMemory(0x100)
	mv = uint32(0x0000005c)
	if v != mv {
		t.Errorf("AP Memory 2 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("AP CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}

	// Add packed with offset
	cw.setMemory(0x100, 0x0043212c) // 2+
	cw.setMemory(0x200, 0x0023413c) // 3+
	cw.setMemory(0x400, 0xfa220101) // AP 101(3,0),201(3,0)
	cw.setMemory(0x404, 0x02010000)
	cw.testInst(0)
	v = cw.getMemory(0x100)
	mv = uint32(0x0066625c)
	if v != mv {
		t.Errorf("AP Memory 2 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("AP CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}

	// Add packed no offset
	cw.setMemory(0x100, 0x0043212c) // 2+
	cw.setMemory(0x200, 0x0023413c) // 3+
	cw.setMemory(0x400, 0xfa330100) // AP 100(4,0),200(4,0)
	cw.setMemory(0x404, 0x02000000)
	cw.testInst(0)
	v = cw.getMemory(0x100)
	mv = uint32(0x0066625c)
	if v != mv {
		t.Errorf("AP Memory 2 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("AP CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}

	// Add packed offset
	// Example from Princ Ops p136.2
	cw.c.GR[12] = 0x00002000
	cw.c.GR[13] = 0x000004fd
	cw.setMemory(0x2000, 0x38460d00) // 38460-
	cw.setMemory(0x500, 0x0112345c)  // 112345+
	cw.setMemory(0x400, 0xfa23c000)  // AP 0(3,12),3(4,13)
	cw.setMemory(0x404, 0xd0030000)
	cw.testInst(0)
	v = cw.getMemory(0x2000)
	mv = uint32(0x73885c00)
	if v != mv {
		t.Errorf("AP Memory 2 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("AP CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}

	// Add packed
	// Example from Princ Ops p136.2
	cw.c.GR[12] = 0x00002000
	cw.c.GR[13] = 0x000004fd
	cw.setMemory(0x2000, 0x0038460d)
	cw.setMemory(0x500, 0x0112345c)
	cw.setMemory(0x400, 0xfa33c000)
	cw.setMemory(0x404, 0xd0030000) // AP 0(4, 12), 3(4, 13)
	cw.testInst(0)
	v = cw.getMemory(0x2000)
	mv = uint32(0x0073885c)
	if v != mv {
		t.Errorf("AP Memory 2 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("AP CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}
}

// Basic Zero Add Packed Decimal tests.
func (cw *cornwellFixture) TestCycleZAP(t *testing.T) {
	cw.setup()

	cw.c.GR[9] = 0x00004000
	cw.setMemory(0x4000, 0x12345678)
	cw.setMemory(0x4004, 0x90aaaaaa)
	cw.setMemory(0x4500, 0x38460dff)
	cw.setMemory(0x400, 0xf8429000)
	cw.setMemory(0x404, 0x95000000) // ZAP 0(5, 9), 500(3, 9)
	cw.testInst(0)
	v := cw.getMemory(0x4000)
	mv := uint32(0x00003846)
	if v != mv {
		t.Errorf("ZAP Memory 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getMemory(0x4004)
	mv = uint32(0x0daaaaaa)
	if v != mv {
		t.Errorf("ZAP Memory 2 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 1 {
		t.Errorf("ZAP CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}

	// Zap short field
	cw.setMemory(0x100, 0x2a000000) // 2+
	cw.setMemory(0x200, 0x3a000000) // 3+
	cw.setMemory(0x400, 0xf8000100)
	cw.setMemory(0x404, 0x02000000) // ZAP 100(1, 0), 200(1, 0)
	cw.testInst(0)
	v = cw.getMemory(0x100)
	mv = uint32(0x3c000000)
	if v != mv {
		t.Errorf("ZAP Memory 2 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("ZAP CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}

	// Zap with offset
	cw.setMemory(0x100, 0x002a0000) // 2+
	cw.setMemory(0x200, 0x00003a00) // 3+
	cw.setMemory(0x400, 0xf8000101)
	cw.setMemory(0x404, 0x02020000) // ZAP 101(1, 0), 202(1, 0)
	cw.testInst(0)
	v = cw.getMemory(0x100)
	mv = uint32(0x003c0000)
	if v != mv {
		t.Errorf("ZAP Memory 2 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("ZAP CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}
}

// Compare packed.
func (cw *cornwellFixture) TestCycleCP(t *testing.T) {
	cw.setup()

	// Princ Op page 150
	cw.c.GR[12] = 0x00000600
	cw.c.GR[13] = 0x00000400
	cw.setMemory(0x700, 0x1725356d)
	cw.setMemory(0x500, 0x0672142d)
	cw.setMemory(0x400, 0xf933c100)
	cw.setMemory(0x404, 0xd1000000) // CP 100(4, 12), 100(4, 13)
	cw.testInst(0)
	if cw.c.PSW.CC != 1 {
		t.Errorf("CP CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}

	// Compare packed  equal
	cw.c.GR[12] = 0x00000600
	cw.c.GR[13] = 0x00000400
	cw.setMemory(0x700, 0x1725356d)
	cw.setMemory(0x500, 0x00172535)
	cw.setMemory(0x504, 0x6d000000)
	cw.setMemory(0x400, 0xf933c100)
	cw.setMemory(0x404, 0xd1010000) // CP 100(4, 12), 101(4, 13)
	cw.testInst(0)

	if cw.c.PSW.CC != 0 {
		t.Errorf("CP CC not correct got: %x wanted: %x", cw.c.PSW.CC, 0)
	}

	// Compare packed first higher
	cw.c.GR[12] = 0x00000600
	cw.c.GR[13] = 0x00000400
	cw.setMemory(0x700, 0x1725346d)
	cw.setMemory(0x500, 0x00172535)
	cw.setMemory(0x504, 0x6d000000)
	cw.setMemory(0x400, 0xf933c100)
	cw.setMemory(0x404, 0xd1010000) // CP 100(4, 12), 101(4, 13)
	cw.testInst(0)
	if cw.c.PSW.CC != 2 {
		t.Errorf("CP CC not correct got: %x wanted: %x", cw.c.PSW.CC, 2)
	}
}

// Subtract packed.
func (cw *cornwellFixture) TestCycleSP(t *testing.T) {
	cw.setup()

	cw.c.GR[12] = 0x00002000
	cw.c.GR[13] = 0x000004fc
	cw.setMemory(0x2000, 0x0038460c)
	cw.setMemory(0x500, 0x0112345c)
	cw.setMemory(0x400, 0xfb33c000)
	cw.setMemory(0x404, 0xd0040000) // SP 0(4, 12), 3(4, 13)
	cw.testInst(0)
	v := cw.getMemory(0x2000)
	mv := uint32(0x0073885d)
	if v != mv {
		t.Errorf("SP Memory 1 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 1 {
		t.Errorf("SP CC not correct got: %x wanted: %x", cw.c.PSW.CC, 1)
	}
}

// Multiply packed.
func (cw *cornwellFixture) TestCycleMP(t *testing.T) {
	cw.setup()

	cw.c.GR[4] = 0x00001200
	cw.c.GR[6] = 0x00000500
	cw.setMemory(0x1300, 0x00003846)
	cw.setMemory(0x1304, 0x0cffffff)
	cw.setMemory(0x500, 0x321dffff)
	cw.setMemory(0x400, 0xfc414100)
	cw.setMemory(0x404, 0x60000000) // MP 100(5, 4), 0(2, 6)
	cw.testInst(0)
	v := cw.getMemory(0x1300)
	mv := uint32(0x01234566)
	if v != mv {
		t.Errorf("MP Memory 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getMemory(0x1304)
	mv = uint32(0x0dffffff)
	if v != mv {
		t.Errorf("MP Memory 2 not correct got: %08x wanted: %08x", v, mv)
	}
}

// Divide packed.
func (cw *cornwellFixture) TestCycleDP(t *testing.T) {
	cw.setup()

	cw.c.GR[12] = 0x00002000
	cw.c.GR[13] = 0x00003000
	cw.setMemory(0x2000, 0x01234567)
	cw.setMemory(0x2004, 0x8cffffff)
	cw.setMemory(0x3000, 0x321dffff)
	cw.setMemory(0x400, 0xfd41c000)
	cw.setMemory(0x404, 0xd0000000) // DP 0(5, 12), 0(2, 13)
	cw.testInst(0)
	v := cw.getMemory(0x2000)
	mv := uint32(0x38460d01)
	if v != mv {
		t.Errorf("DP Memory 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getMemory(0x2004)
	mv = uint32(0x8cffffff)
	if v != mv {
		t.Errorf("DP Memory 2 not correct got: %08x wanted: %08x", v, mv)
	}
}

// Do a bunch of canned tests with Packed Decimal instructions.
var cornwellHexDigits = "0123456789abcdef"

type cornwellDecimalCase struct {
	op  uint8
	i1  string
	i2  string
	out string
	cc  uint8
	ex  uint8
}

var cornwellDecimalCases = []cornwellDecimalCase{
	{0xfa, "2c", "3c", "5c", 2, 0},
	{0xfb, "1c", "7c", "6d", 1, 0},
	{0xfa, "1c", "7c", "8c", 2, 0},
	{0xfb, "9c", "5c", "4c", 2, 0},
	{0xfa, "9c", "5c", "4c", 3, 10},
	{0xfb, "009c", "5d", "014c", 2, 0},
	{0xfb, "1d", "1d", "0c", 0, 0},
	{0xfa, "12345c", "54321c", "66666c", 2, 0},
	{0xfb, "12345c", "54321c", "41976d", 1, 0},
	{0xfb, "54321c", "12345c", "41976c", 2, 0},
	{0xfb, "54321c", "01234d", "55555c", 2, 0},
	{0xfb, "12345c", "54321d", "66666c", 2, 0},
	{0xfa, "12345d", "54321d", "66666d", 1, 0},
	{0xfa, "012c", "052c", "064c", 2, 0},
	{0xfa, "072c", "012c", "084c", 2, 0},
	{0xfa, "095c", "023c", "118c", 2, 0},
	{0xfb, "095c", "023d", "118c", 2, 0},
	{0xfb, "012c", "532c", "520d", 1, 0},
	{0xfa, "171c", "053c", "224c", 2, 0},
	{0xfb, "171d", "053c", "224d", 1, 0},
	{0xfa, "053d", "171d", "224d", 1, 0},
	{0xfa, "1c", "2c", "3c", 2, 0},
	{0xfa, "072c", "025d", "047c", 2, 0},
	{0xfa, "072d", "080c", "008c", 2, 0},
	{0xfb, "77532c", "12345c", "65187c", 2, 0},
	{0xfa, "9c", "018d", "9d", 1, 0},
	{0xfb, "6c", "014c", "8d", 1, 0},
	{0xfb, "8d", "019d", "1c", 3, 10},
	{0xfa, "7d", "016c", "9c", 2, 0},
	{0xfc, "0000125c", "752c", "0094000c", 2, 0},
	{0xfc, "012345", "654321", "012345", 0, 7},
	{0xfc, "5c", "5c", "5c", 0, 6},
	{0xfc, "005c", "5c", "025c", 0, 0},
	{0xfc, "005c", "005c", "025c", 0, 6},
	{0xfc, "005c", "012c", "005c", 0, 6},
	{0xfc, "006c", "013c", "006c", 0, 6},
	{0xfc, "00004c", "017c", "00068c", 0, 0},
	{0xfc, "005c", "215c", "005c", 0, 6},
	{0xfc, "00006c", "135c", "00810c", 0, 0},
	{0xfc, "00004c", "023c", "00092c", 0, 0},
	{0xfc, "007c", "9c", "063c", 0, 0},
	{0xfc, "009d", "8c", "072d", 0, 0},
	{0xfc, "018c", "2c", "036c", 0, 7},
	{0xfc, "008d", "3d", "024c", 0, 0},
	{0xfc, "001d", "0c", "000d", 0, 0},
	{0xfc, "000c", "052d", "000c", 0, 6},
	{0xfc, "00000014142c", "14142c", "00199996164c", 0, 0},
	{0xfc, "00000017320c", "17320c", "00299982400c", 0, 0},
	{0xfc, "0000000223607d", "0223607c", "0000000223607d", 0, 7},
	{0xfc, "002236067977499c", "3d", "006708203932497d", 0, 0},
	{0xfc, "001414213562373d", "2d", "002828427124746c", 0, 0},
	{0xfc, "022360679774997c", "3d", "022360679774997c", 0, 7},
	{0xfc, "014142135623730d", "2d", "014142135623730d", 0, 7},
	{0xfc, "002236067977499c", "029d", "002236067977499c", 0, 7},
	{0xfc, "001414213562373d", "021d", "001414213562373d", 0, 7},
	{0xfc, "000223606797749c", "029d", "000223606797749c", 0, 7},
	{0xfc, "000141421356237d", "021d", "000141421356237d", 0, 7},
	{0xfc, "022360697774997c", "9d", "022360697774997c", 0, 7},
	{0xfc, "074142315623730d", "8d", "074142315623730d", 0, 7},
	{0xfc, "000000000000005c", "0123456c", "000000000617280c", 0, 0},
	{0xfc, "000000000000005c", "1234567c", "000000006172835c", 0, 0},
	{0xfc, "000000000000003c", "012345678c", "000000037037034c", 0, 0},
	{0xfc, "000000000000015c", "0123456c", "000000001851840c", 0, 0},
	{0xfc, "000000000000025c", "1234567c", "000000030864175c", 0, 0},
	{0xfc, "000000000000093c", "012345678c", "000001148148054c", 0, 0},
	{0xfc, "000000001234567c", "1234567c", "001524155677489c", 0, 0},
	{0xfc, "000000001234567c", "012345678c", "000000001234567c", 0, 7},
	{0xfc, "000000001234567c", "123456789c", "000000001234567c", 0, 7},
	{0xfc, "0001234c", "025c", "0001234c", 0, 7},
	{0xfc, "0001243d", "017c", "0001243d", 0, 7},
	{0xfc, "0005432c", "071d", "0005432c", 0, 7},
	{0xfc, "0000123d", "176d", "0021648c", 0, 0},
	{0xfc, "0000512c", "01068c", "0000512c", 0, 7},
	{0xfc, "002c", "2c", "004c", 0, 0},
	{0xfc, "004c", "4c", "016c", 0, 0},
	{0xfc, "008c", "8c", "064c", 0, 0},
	{0xfc, "00016c", "016c", "00016c", 0, 7},
	{0xfc, "0000032c", "032c", "0001024c", 0, 0},
	{0xfc, "0000064c", "064c", "0004096c", 0, 0},
	{0xfc, "0000128c", "128c", "0016384c", 0, 0},
	{0xfc, "0000256c", "256c", "0065536c", 0, 0},
	{0xfc, "0000512c", "512c", "0262144c", 0, 0},
	{0xfc, "00000001024c", "01024c", "00001048576c", 0, 0},
	{0xfc, "00000002048c", "02048c", "00004194304c", 0, 0},
	{0xfc, "00000004096c", "04096c", "00016777216c", 0, 0},
	{0xfc, "00000008192c", "08192c", "00067108864c", 0, 0},
	{0xfc, "00000016384c", "16384c", "00268435456c", 0, 0},
	{0xfc, "00000032768c", "32768c", "01073741824c", 0, 0},
	{0xfc, "00000065536c", "65536c", "04294967296c", 0, 0},
	{0xfc, "000000000131072c", "0131072c", "000017179869184c", 0, 0},
	{0xfc, "000000000524288c", "0524288c", "000274877906944c", 0, 0},
	{0xfc, "000000002097152c", "0131072c", "000274877906944c", 0, 0},
	{0xfc, "000000002097152c", "65536c", "000137438953472c", 0, 0},
	{0xfc, "000000002097152c", "2097152c", "004398046511104c", 0, 0},
	{0xfc, "000002147483646c", "512c", "001099511626752c", 0, 0},
	{0xfc, "000002147483646c", "08192c", "000002147483646c", 0, 7},
	{0xfc, "000002147483646c", "16384c", "000002147483646c", 0, 7},
	{0xfc, "000002147483646c", "65536c", "000002147483646c", 0, 7},
	{0xfc, "004398046511104c", "8c", "035184372088832c", 0, 0},
	{0xfc, "004398046511104c", "064c", "004398046511104c", 0, 7},
	{0xfc, "000549755813888c", "08192c", "000549755813888c", 0, 7},
	{0xfc, "000549755813888c", "512c", "000549755813888c", 0, 7},
	{0xfc, "000549755813888c", "064c", "000549755813888c", 0, 7},
	{0xfc, "000549755813888c", "8c", "004398046511104c", 0, 0},
	{0xfc, "000068719476736c", "16384c", "000068719476736c", 0, 7},
	{0xfc, "000068719476736c", "04096c", "000068719476736c", 0, 7},
	{0xfc, "000068719476736c", "512c", "035184372088832c", 0, 0},
	{0xfc, "7c", "7d", "7c", 0, 6},
	{0xfc, "025c", "3d", "025c", 0, 7},
	{0xfc, "7d", "8d", "7d", 0, 6},
	{0xfd, "77325c", "025c", "77325c", 0, 11},
	{0xfd, "066c", "1c", "066c", 0, 11},
	{0xfd, "072c", "3d", "072c", 0, 11},
	{0xfd, "066d", "2c", "066d", 0, 11},
	{0xfd, "072c", "1c", "072c", 0, 11},
	{0xfd, "072c", "0c", "072c", 0, 11},
	{0xfd, "000077325c", "025c", "03093c000c", 0, 0},
	{0xfd, "0000066c", "2c", "00033c0c", 0, 0},
	{0xfd, "00066c", "2c", "033c0c", 0, 0},
	{0xfd, "00066c", "2c", "033c0c", 0, 0},
	{0xfd, "066c", "2c", "066c", 0, 11},
	{0xfd, "0123456c", "072c", "0123456c", 0, 11},
	{0xfd, "0123456c", "072c", "0123456c", 0, 11},
	{0xfd, "000123456c", "072c", "01714c048c", 0, 0},
	{0xfd, "000123456c", "072c", "01714c048c", 0, 0},
	{0xfd, "00000123456c", "072c", "0001714c048c", 0, 0},
	{0xfd, "00004398046511104c", "064c", "0068719476736c000c", 0, 0},
	{0xfd, "00004398046511104c", "064c", "0068719476736c000c", 0, 0},
	{0xfd, "004398046511104c", "064c", "68719476736c000c", 0, 0},
	{0xfd, "004398046511104c", "064c", "68719476736c000c", 0, 0},
	{0xfd, "00000043980465111c", "653c", "0000067351401c258c", 0, 0},
	{0xfd, "00000439804651110c", "653c", "0000673514013c621c", 0, 0},
	{0xfd, "00004398046511104c", "653c", "0006735140139c337c", 0, 0},
	{0xfd, "00004398046511104c", "653c", "0006735140139c337c", 0, 0},
	{0xfd, "004398046511104c", "653c", "06735140139c337c", 0, 0},
	{0xfd, "043980465111040c", "653c", "67351401395c105c", 0, 0},
	{0xfd, "439804651110400c", "653c", "439804651110400c", 0, 11},
	{0xfd, "0000435d", "7c", "00062d1d", 0, 0},
	{0xfd, "0000435c", "7d", "00062d1c", 0, 0},
	{0xfd, "0000435d", "7d", "00062c1d", 0, 0},
	{0xfd, "0000251d", "7d", "00035c6d", 0, 0},
	{0xfd, "0000252d", "7d", "00036c0d", 0, 0},
	{0xfd, "0000253d", "7d", "00036c1d", 0, 0},
	{0xfd, "00000d", "1c", "000d0d", 0, 0},
	{0xfd, "00001d", "1c", "001d0d", 0, 0},
	{0xfd, "00001c", "1c", "001c0c", 0, 0},
	{0xfd, "00000c", "1d", "000d0c", 0, 0},
	{0xfd, "00000c", "1c", "000c0c", 0, 0},
	{0xfd, "00000c", "0c", "00000c", 0, 11},
	{0xfd, "0000000000725c", "1234567c", "00000c0000725c", 0, 0},
	{0xfd, "0000000000725c", "012345678c", "000c000000725c", 0, 0},
	{0xfd, "1234567c", "1234567c", "1234567c", 0, 6},
	{0xfd, "012345678c", "1234567c", "012345678c", 0, 11},
	{0xfd, "000000008c", "1234567c", "0c0000008c", 0, 0},
	{0xfd, "000000008c", "0123456c", "0c0000008c", 0, 0},
	{0xfd, "000000008c", "12345c", "000c00008c", 0, 0},
	{0xfd, "0000000000000006543210987654321c", "123456789012345c", "000000000000053c000001170000036c", 0, 0},
	{0xfd, "0000000000006543210987654321000c", "123456789012345c", "000000000053000c001170000036000c", 0, 0},
	{0xfd, "0000000006543210987654321000111c", "123456789012345c", "000000053000009c058888934889006c", 0, 0},
	{0xfd, "0000006543210987654321000111222c", "123456789012345c", "000053000009477c000046530117657c", 0, 0},
	{0xfd, "0000043210987654321000111222333c", "123456789012345c", "000350009003150c010253617335583c", 0, 0},
	{0xfd, "0000543210987654321000111222333c", "123456789012345c", "004400009039600c013044117360333c", 0, 0},
	{0xfd, "0006543210987654321000111222333c", "123456789012345c", "053000009477000c046530117657333c", 0, 0},
	{0xfd, "0076543210987654321000111222333c", "123456789012345c", "620000014580003c066829754085298c", 0, 0},
	{0xfd, "0876543210987654321000111222333c", "123456789012345c", "0876543210987654321000111222333c", 0, 11},
	{0xfd, "6543210987654321000111222333444c", "123456789012345c", "6543210987654321000111222333444c", 0, 11},
	{0xfd, "0000000000000000000000000000000c", "123456789012345c", "000000000000000c000000000000000c", 0, 0},
	{0xfd, "0000000000000000000000000000000c", "01234567890123456c", "0000000000000000000000000000000c", 0, 6},
	{0xf1, "512c", "001068", "068c", 0, 0},
	{0xf1, "7788990c", "123456", "0123456c", 0, 0},
	{0xf1, "0001234c", "025c", "000025cc", 0, 0},
	{0xf1, "0001243d", "017c", "000017cd", 0, 0},
	{0xf1, "0005432c", "071d", "000071dc", 0, 0},
	{0xf1, "0000123d", "176d", "000176dd", 0, 0},
	{0xf1, "0000512c", "01068c", "001068cc", 0, 0},
	{0xf1, "002c", "2c", "02cc", 0, 0},
	{0xf1, "004c", "4c", "04cc", 0, 0},
	{0xf1, "008c", "8c", "08cc", 0, 0},
	{0xf1, "512c", "00068c", "68cc", 0, 0},
	{0xf8, "0001234c", "025c", "0000025c", 2, 0},
	{0xf8, "0001243d", "017c", "0000017c", 2, 0},
	{0xf8, "0005432c", "071d", "0000071d", 1, 0},
	{0xf8, "0000123d", "176d", "0000176d", 1, 0},
	{0xf8, "0000512c", "01068c", "0001068c", 2, 0},
	{0xf8, "002c", "2c", "002c", 2, 0},
	{0xf8, "004c", "4c", "004c", 2, 0},
	{0xf8, "008c", "8c", "008c", 2, 0},
	{0xf8, "512c", "01068c", "068c", 3, 10},
	{0xf8, "512c", "00068c", "068c", 2, 0},
	{0xf9, "0c", "000d", "0c", 0, 0},
	{0xf9, "1c", "5c", "1c", 1, 0},
	{0xf9, "9c", "9c", "9c", 0, 0},
	{0xf9, "9c", "9d", "9c", 2, 0},
	{0xf9, "017c", "4d", "017c", 2, 0},
	{0xf9, "1c", "034d", "1c", 2, 0},
	{0xf9, "027c", "000000235d", "027c", 2, 0},
	{0xf9, "5c", "000000235d", "5c", 2, 0},
	{0xf9, "12345c", "54321c", "12345c", 1, 0},
	{0xde, "20204021", "a0", "fa204021", 0, 7},
	{0xde, "ee2020202120", "00023c", "eeeeeeeef2f3", 2, 0},
	{0xde, "ee2020202120", "0c1c012c", "eeeef1eef1f2", 2, 0},
	{0xde, "ee2020202120", "0d1d012d", "eeeef1f0f1f2", 1, 0},
	{0xde, "ee202022202120", "0c1c012e", "eeeef1eeeef1f2", 2, 0},
	{0xde, "ee202020", "00b0", "eeeeee20", 0, 7},
	{0xde, "ee202020", "00c0", "eeeeee20", 0, 7},
	{0xde, "ee212020", "000f", "eeeef0f0", 0, 0},
	{0xde, "ee2020202020202020202020202020", "013b026c00129c789a", "eeeef1f3f0f2f6eeeef1f2f9f7f8f9", 2, 0},
	{0xde, "402020402120", "X1", "40f4f040f2f0", 1, 0},
	{0xfa, "3c", "5c", "8c", 2, 0},
}

// Run group of decimal test cornwellDecimalCases.
func (cw *cornwellFixture) TestCycleDecimalTest(t *testing.T) {
	cw.setup()

	for i, test := range cornwellDecimalCases {
		// Preserve the upstream rows; this expectation is specific to our
		// architecture. The reference and original result are in README.md.
		// The case still executes and asserts exact results.
		switch i {
		case 30: // MP: L1 == L2; specification precedes invalid decimal data.
			test.ex = pgmSpecification
		}
		var res [256]byte
		addr := uint32(0x1000)
		cw.c.GR[10] = addr
		arg, _ := hex.DecodeString(test.i1)
		for i, v := range arg {
			cw.setByte(addr+uint32(i), uint32(v))
		}
		l1 := len(arg)
		l2 := 0
		// Overlap data fields
		if test.i2[0] == 'X' {
			o := test.i2[1] - '0'
			cw.c.GR[12] = addr
			cw.c.GR[10] = addr + uint32(o)
		} else {
			addr2 := uint32(0x2000)
			cw.c.GR[12] = addr2
			arg, _ := hex.DecodeString(test.i2)
			for i, v := range arg {
				cw.setByte(addr2+uint32(i), uint32(v))
			}
			l2 = len(arg)
		}
		inst := (uint32(test.op) << 24) | 0xa000
		if test.op == 0xde {
			inst |= uint32(l1-1) << 16
		} else {
			inst |= uint32(l1-1) << 20
			inst |= uint32(l2-1) << 16
		}
		cw.setMemory(0x400, inst)
		cw.setMemory(0x404, 0xc0000000)
		cw.setMemory(0x800, 0)
		cw.setMemory(0x28, 0)
		cw.setMemory(0x2c, 0)
		cw.testInst(0x4)
		addr = 0x1000
		var data uint8
		// Convert result to hex string for compare.
		for j := range len(test.out) {
			if (j & 1) != 0 {
				addr++
				res[j] = cornwellHexDigits[data&0xf]
			} else {
				data = cw.getByte(addr)
				res[j] = cornwellHexDigits[(data>>4)&0xf]
			}
		}
		result := string(res[:len(test.out)])

		if test.ex != 0 {
			if !cw.trap {
				t.Errorf("Test %d did not trap", i)
			}
			v := cw.getMemory(0x28) & 0xffff
			if v != uint32(test.ex) {
				t.Errorf("Test %d did not trap correctly got: %04x expected: %04x", i, v, test.ex)
			}
		} else {
			if result != test.out {
				t.Errorf("Test %d did get correct result got: %s expected: %s", i, result, test.out)
			}
			if cw.c.PSW.CC != test.cc {
				t.Errorf("Test %d did not get correct CC got: %x expected: %x", i, cw.c.PSW.CC, test.cc)
			}
			if cw.trap {
				t.Errorf("Test %d traped", i)
			}
			v := cw.getMemory(0x28) & 0xffff
			if v != uint32(test.ex) {
				t.Errorf("Test %d did reported incorrect trap got: %04x expected: %04x", i, v, test.ex)
			}
		}
	}
}

// Test floating point store double.
func (cw *cornwellFixture) TestCycleSTD(t *testing.T) {
	cw.setup()

	cw.setFloatShort(0, 0x12345678)
	cw.setFloatShort(1, 0xaabbccdd)
	cw.c.GR[1] = 0x100
	cw.c.GR[2] = 0x300
	cw.setMemory(0x400, 0x60012100) // STD 0,100(1,2)
	cw.setMemory(0x404, 0x0)
	cw.testInst(0)
	v := cw.getMemory(0x500)
	mv := uint32(0x12345678)
	if v != mv {
		t.Errorf("STD Memory 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getMemory(0x504)
	mv = uint32(0xaabbccdd)
	if v != mv {
		t.Errorf("STD Memory 2 not correct got: %08x wanted: %08x", v, mv)
	}
}

// Test floating point load double.
func (cw *cornwellFixture) TestCycleLD(t *testing.T) {
	cw.setup()

	cw.setMemory(0x100, 0x12345678)
	cw.setMemory(0x104, 0xaabbccdd)
	cw.setMemory(0x400, 0x68000100) //  LD 0,100(0,0)
	cw.setMemory(0x404, 0x0)
	cw.setFloatShort(0, 0xffffffff)
	cw.setFloatShort(1, 0xffffffff)
	cw.testInst(0)
	v := cw.getFloatShort(0)
	mv := uint32(0x12345678)
	if v != mv {
		t.Errorf("LD Register 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getFloatShort(1)
	mv = uint32(0xaabbccdd)
	if v != mv {
		t.Errorf("LD Register 2 not correct got: %08x wanted: %08x", v, mv)
	}

	cw.setMemory(0x100, 0x44000000)
	cw.setMemory(0x104, 0xaabbccdd)
	cw.setMemory(0x400, 0x68000100) //  LD 0,100(0,0)
	cw.setFloatShort(0, 0xffffffff)
	cw.setFloatShort(1, 0xffffffff)
	cw.testInst(0)
	v = cw.getFloatShort(0)
	mv = uint32(0x44000000) // Stays unnormalized
	if v != mv {
		t.Errorf("LD Register 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getFloatShort(1)
	mv = uint32(0xaabbccdd)
	if v != mv {
		t.Errorf("LD Register 2 not correct got: %08x wanted: %08x", v, mv)
	}
}

// Load complement LCDR - LCDR 2,4.
func (cw *cornwellFixture) TestCycleLCDR(t *testing.T) {
	cw.setup()

	cw.setMemory(0x400, 0x23240000) // LCDR 2,4
	cw.setMemory(0x404, 0x0)

	// Test positive number
	cw.setFloatShort(4, 0x12345678)
	cw.setFloatShort(5, 0xaabbccdd)
	cw.testInst(0)
	v := cw.getFloatShort(2)
	mv := uint32(0x92345678)
	if v != mv {
		t.Errorf("LCDR Register 2 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getFloatShort(3)
	mv = uint32(0xaabbccdd)
	if v != mv {
		t.Errorf("LCDR Register 3 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 1 {
		t.Errorf("LCDR CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, 1)
	}

	// Test negative number
	cw.setFloatShort(4, 0x92345678)
	cw.setFloatShort(5, 0xaabbccdd)
	cw.testInst(0)
	v = cw.getFloatShort(2)
	mv = uint32(0x12345678)
	if v != mv {
		t.Errorf("LCDR Register 2 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getFloatShort(3)
	mv = uint32(0xaabbccdd)
	if v != mv {
		t.Errorf("LCDR Register 3 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("LCDR CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, 2)
	}

	// Test zero
	cw.setFloatShort(4, 0x00000000)
	cw.setFloatShort(5, 0x00000000)
	cw.testInst(0)
	v = cw.getFloatShort(2)
	mv = uint32(0x80000000)
	if v != mv {
		t.Errorf("LCDR Register 2 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getFloatShort(3)
	mv = uint32(0x00000000)
	if v != mv {
		t.Errorf("LCDR Register 3 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 0 {
		t.Errorf("LCDR CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, 0)
	}

	// Test overflow
	cw.setFloatShort(4, 0x80000000)
	cw.setFloatShort(5, 0x00000000)
	cw.testInst(0)
	v = cw.getFloatShort(2)
	mv = uint32(0x00000000)
	if v != mv {
		t.Errorf("LCDR Register 2 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getFloatShort(3)
	mv = uint32(0x00000000)
	if v != mv {
		t.Errorf("LCDR Register 3 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 0 {
		t.Errorf("LCDR CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, 0)
	}
}

// Load Positive LPDR - LPDR 3,4.
func (cw *cornwellFixture) TestCycleLPDR(t *testing.T) {
	cw.setup()

	cw.setMemory(0x400, 0x20240000) // LPDR 2,4
	cw.setMemory(0x404, 0x0)

	cw.setFloatShort(4, 0xffffffff)
	cw.setFloatShort(5, 0xffffffff)
	cw.testInst(0)
	v := cw.getFloatShort(2)
	mv := uint32(0x7fffffff)
	if v != mv {
		t.Errorf("LPDR Register 2 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getFloatShort(3)
	mv = uint32(0xffffffff)
	if v != mv {
		t.Errorf("LPDR Register 3 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("LPDR CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, 2)
	}

	// Test positive
	cw.setFloatShort(4, 0x12345678)
	cw.setFloatShort(5, 0x00000000)
	cw.testInst(0)
	v = cw.getFloatShort(2)
	mv = uint32(0x12345678)
	if v != mv {
		t.Errorf("LPDR Register 2 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getFloatShort(3)
	mv = uint32(0x00000000)
	if v != mv {
		t.Errorf("LPDR Register 3 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("LPDR CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, 2)
	}

	// Test zero
	cw.setFloatShort(4, 0x00000000)
	cw.setFloatShort(5, 0x00000000)
	cw.testInst(0)
	v = cw.getFloatShort(2)
	mv = uint32(0x00000000)
	if v != mv {
		t.Errorf("LPDR Register 2 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getFloatShort(3)
	mv = uint32(0x00000000)
	if v != mv {
		t.Errorf("LPDR Register 3 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 0 {
		t.Errorf("LPDR CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, 0)
	}

	// Test negative number
	cw.setFloatShort(4, 0x92345678)
	cw.setFloatShort(5, 0x00000000)
	cw.testInst(0)
	v = cw.getFloatShort(2)
	mv = uint32(0x12345678)
	if v != mv {
		t.Errorf("LPDR Register 2 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getFloatShort(3)
	mv = uint32(0x00000000)
	if v != mv {
		t.Errorf("LPDR Register 3 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("LPDR CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, 2)
	}

	// Test overflow
	cw.setFloatShort(4, 0x80000000)
	cw.setFloatShort(5, 0x00000000)
	cw.testInst(0)
	v = cw.getFloatShort(2)
	mv = uint32(0x00000000)
	if v != mv {
		t.Errorf("LPDR Register 2 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getFloatShort(3)
	mv = uint32(0x00000000)
	if v != mv {
		t.Errorf("LPDR Register 3 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 0 {
		t.Errorf("LPDR CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, 0)
	}
}

// Load negative LNDR - LNDR 3,4.
func (cw *cornwellFixture) TestCycleLNDR(t *testing.T) {
	cw.setup()

	cw.setMemory(0x400, 0x21240000) // LNDR 2,4
	cw.setMemory(0x404, 0x0)
	cw.setFloatShort(4, 0xffffffff)
	cw.setFloatShort(5, 0xffffffff)

	cw.testInst(0)
	v := cw.getFloatShort(2)
	mv := uint32(0xffffffff)
	if v != mv {
		t.Errorf("LNDR Register 2 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getFloatShort(3)
	mv = uint32(0xffffffff)
	if v != mv {
		t.Errorf("LNDR Register 3 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 1 {
		t.Errorf("LNDR CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, 1)
	}

	// Test positive
	cw.setFloatShort(4, 0x12345678)
	cw.setFloatShort(5, 0x00000000)
	cw.testInst(0)
	v = cw.getFloatShort(2)
	mv = uint32(0x92345678)
	if v != mv {
		t.Errorf("LNDR Register 2 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getFloatShort(3)
	mv = uint32(0x00000000)
	if v != mv {
		t.Errorf("LNDR Register 3 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 1 {
		t.Errorf("LNDR CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, 1)
	}

	// Test zero
	cw.setFloatShort(4, 0x00000000)
	cw.setFloatShort(5, 0x00000000)
	cw.testInst(0)
	v = cw.getFloatShort(2)
	mv = uint32(0x80000000)
	if v != mv {
		t.Errorf("LNDR Register 2 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getFloatShort(3)
	mv = uint32(0x00000000)
	if v != mv {
		t.Errorf("LNDR Register 3 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 0 {
		t.Errorf("LNDR CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, 0)
	}

	// Test negative number
	cw.setFloatShort(4, 0x92345678)
	cw.setFloatShort(5, 0x00000000)
	cw.testInst(0)
	v = cw.getFloatShort(2)
	mv = uint32(0x92345678)
	if v != mv {
		t.Errorf("LNDR Register 2 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getFloatShort(3)
	mv = uint32(0x00000000)
	if v != mv {
		t.Errorf("LNDR Register 3 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 1 {
		t.Errorf("LNDR CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, 1)
	}

	// Test overflow
	cw.setFloatShort(4, 0x80000000)
	cw.setFloatShort(5, 0x00000000)
	cw.testInst(0)
	v = cw.getFloatShort(2)
	mv = uint32(0x80000000)
	if v != mv {
		t.Errorf("LNDR Register 2 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getFloatShort(3)
	mv = uint32(0x00000000)
	if v != mv {
		t.Errorf("LNDR Register 3 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 0 {
		t.Errorf("LNDR CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, 0)
	}
}

// Test compare double.
func (cw *cornwellFixture) TestCycleCD(t *testing.T) {
	cw.setup()

	// Check results
	cw.setFloatShort(0, 0x43000000)
	cw.setFloatShort(1, 0x00000000)
	cw.setMemory(0x100, 0x32123456)
	cw.setMemory(0x104, 0x789ABCDE)
	cw.setMemory(0x400, 0x69000100) // CD 0,100(0,0)
	cw.setMemory(0x404, 0x00000000)
	cw.testInst(0)
	if cw.c.PSW.CC != 0 {
		t.Errorf("CD CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, 0)
	}

	cw.setFloatShort(0, 0x12345678)
	cw.setFloatShort(1, 0xaabbccdd)
	cw.setMemory(0x100, 0x44000000)
	cw.setMemory(0x104, 0xaabbccdd)
	cw.setMemory(0x400, 0x69000100) // CD 0,100(0,0)
	cw.setMemory(0x404, 0x00000000)
	cw.testInst(0)
	if cw.c.PSW.CC != 1 {
		t.Errorf("CD CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, 1)
	}

	cw.setFloatShort(0, 0x43082100)
	cw.setFloatShort(1, 0xaabbccdd)
	cw.setMemory(0x100, 0x43082100)
	cw.setMemory(0x104, 0xaabbccdd)
	cw.setMemory(0x400, 0x69000100) // CD 0,100(0,0)
	cw.setMemory(0x404, 0x00000000)
	cw.testInst(0)
	if cw.c.PSW.CC != 0 {
		t.Errorf("CD CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, 0)
	}
}

// Half instruct rand.
func (cw *cornwellFixture) TestCycleHD(t *testing.T) {
	cw.setup()
	rnum := rand.New(rand.NewSource(125))
	for range testCycles {
		f := rnum.NormFloat64()
		scale := rnum.Intn(100) - 50
		f = math.Ldexp(f, scale)
		err := cw.floatToFpreg(2, f)
		if !err {
			t.Errorf("HDR Unable to set register to %f", f)
		}
		mb := f / 2.0
		cw.setMemory(0x400, 0x24420000) // HDR 4,2
		cw.testInst(0)
		v := cw.cnvtLongFloat(4)
		ratio := math.Abs((v - mb) / mb)
		if ratio > 0.000001 {
			t.Errorf("HDR difference too large got: %f expected: %f", v, mb)
		}
	}
}

// Add double.
func (cw *cornwellFixture) TestCycleAD(t *testing.T) {
	cw.setup()

	cw.setFloatShort(6, 0x43082100)
	cw.setFloatShort(7, 0x00000000)
	cw.setMemory(0x2000, 0x41123456)
	cw.setMemory(0x2004, 0x00000000)
	cw.c.GR[13] = 0x00002000
	cw.setMemory(0x400, 0x6a60d000) // AD 6,0(0, 13)
	cw.setMemory(0x404, 0x00000000)
	cw.testInst(0)

	v := cw.getFloatShort(6)
	mv := uint32(0x42833345)
	if v != mv {
		t.Errorf("AD Register 6 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getFloatShort(7)
	mv = uint32(0x60000000)
	if v != mv {
		t.Errorf("AD Register 7 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("AD CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, 2)
	}

	rnum := rand.New(rand.NewSource(125))
	for range testCycles {
		f1 := rnum.NormFloat64()
		scale := rnum.Intn(100) - 50
		f1 = math.Ldexp(f1, scale)
		f2 := rnum.NormFloat64()
		scale = rnum.Intn(100) - 50
		f2 = math.Ldexp(f2, scale)
		err := cw.floatToFpreg(4, f1)
		if !err {
			t.Errorf("Unable to set register to %f", f1)
		}
		err = cw.floatToFpreg(2, f2)
		if !err {
			t.Errorf("Unable to set register to %f", f2)
		}
		mb := f1 + f2
		cw.setMemory(0x400, 0x2a420000) // ADR 4,2
		cw.testInst(0)
		v := cw.cnvtLongFloat(4)
		ratio := math.Abs((v - mb) / mb)
		if ratio > 0.000001 {
			t.Errorf("AD difference too large got: %f expected: %f", v, mb)
		}
		cc := uint8(0)
		if mb != 0.0 {
			if mb < 0.0 {
				cc = 1
			} else {
				cc = 2
			}
		}
		if cw.c.PSW.CC != cc {
			t.Errorf("AD CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, cc)
		}
	}
}

// Subtract double.
func (cw *cornwellFixture) TestCycleSD(t *testing.T) {
	cw.setup()

	cw.setFloatShort(6, 0x43082100)
	cw.setFloatShort(7, 0x00000000)
	cw.setMemory(0x2000, 0x41123456)
	cw.setMemory(0x2004, 0x00000000)
	cw.c.GR[13] = 0x00002000
	cw.setMemory(0x400, 0x6b60d000) // SD 6,0(0, 13)
	cw.setMemory(0x404, 0x00000000)
	cw.testInst(0)

	v := cw.getFloatShort(6)
	mv := uint32(0x4280ECBA)
	if v != mv {
		t.Errorf("SD Register 6 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getFloatShort(7)
	mv = uint32(0xA0000000)
	if v != mv {
		t.Errorf("SD Register 7 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("SD CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, 2)
	}

	rnum := rand.New(rand.NewSource(125))
	for range testCycles {
		f1 := rnum.NormFloat64()
		scale := rnum.Intn(100) - 50
		f1 = math.Ldexp(f1, scale)
		f2 := rnum.NormFloat64()
		scale = rnum.Intn(100) - 50
		f2 = math.Ldexp(f2, scale)
		err := cw.floatToFpreg(0, f1)
		if !err {
			continue
		}
		err = cw.floatToFpreg(2, f2)
		if !err {
			continue
		}
		mb := f1 - f2
		cw.setMemory(0x400, 0x2b020000) // SDR 0,2
		cw.testInst(0)
		v := cw.cnvtLongFloat(0)
		ratio := math.Abs((v - mb) / mb)
		if ratio > 0.000001 {
			t.Errorf("SD difference too large got: %f expected: %f", v, mb)
		}
		cc := uint8(0)
		if mb != 0.0 {
			if mb < 0.0 {
				cc = 1
			} else {
				cc = 2
			}
		}
		if cw.c.PSW.CC != cc {
			t.Errorf("SD CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, cc)
		}
	}
}

// Multiply double.
func (cw *cornwellFixture) TestCyclMD(t *testing.T) {
	cw.setup()

	cw.setFloatShort(6, 0x43082100)
	cw.setFloatShort(7, 0x00000000)
	cw.setMemory(0x2000, 0x41123456)
	cw.setMemory(0x2004, 0x00000000)
	cw.c.GR[13] = 0x00002000
	cw.setMemory(0x400, 0x6c60d000) // MD 6,0(0, 13)
	cw.testInst(0)

	v := cw.getFloatShort(6)
	mv := uint32(0x4293fb6f)
	if v != mv {
		t.Errorf("MD Register 6 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getFloatShort(7)
	mv = uint32(0x16000000)
	if v != mv {
		t.Errorf("MD Register 7 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("MD CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, 3)
	}

	rnum := rand.New(rand.NewSource(125))
	for range testCycles {
		f1 := rnum.NormFloat64()
		scale := rnum.Intn(100) - 50
		f1 = math.Ldexp(f1, scale)
		f2 := rnum.NormFloat64()
		scale = rnum.Intn(100) - 50
		f2 = math.Ldexp(f2, scale)
		if !cw.floatToFpreg(0, f1) {
			continue
		}
		if !cw.floatToFpreg(2, f2) {
			continue
		}
		mb := f1 * f2
		cw.setMemory(0x400, 0x2c020000) // MDR 0,2
		cw.testInst(0)
		if math.Abs(mb) < 5.4e-79 || math.Abs(mb) > 7.2e75 {
			if !cw.trap {
				t.Error("MD did not trap")
			}
		} else {
			if cw.trap {
				t.Error("MD should not have trapped")
			}
			v := cw.cnvtLongFloat(0)
			ratio := math.Abs((v - mb) / mb)
			if ratio > 0.000001 {
				t.Errorf("MD difference too large got: %f expected: %f", v, mb)
			}
		}
	}
}

// Divide double.
func (cw *cornwellFixture) TestCyclDD(t *testing.T) {
	cw.setup()

	cw.setFloatShort(6, 0x43082100)
	cw.setFloatShort(7, 0x00000000)
	cw.setMemory(0x2000, 0x41123456)
	cw.setMemory(0x2004, 0x00000000)
	cw.c.GR[13] = 0x00002000
	cw.setMemory(0x400, 0x6d60d000) // DD 6,0(0, 13)
	// 	cpuState.testInst(0,20)
	// 	ASSERT_EQUAL_X(0x42725012, get_fpreg_s(6))
	// 	ASSERT_EQUAL_X(0xf5527d99, get_fpreg_s(7))
	cw.testInst(0)

	v := cw.getFloatShort(6)
	mv := uint32(0x42725012)
	if v != mv {
		t.Errorf("DD Register 6 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getFloatShort(7)
	mv = uint32(0xf5527d99)
	if v != mv {
		t.Errorf("DD Register 7 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 3 {
		t.Errorf("DD CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, 3)
	}

	rnum := rand.New(rand.NewSource(125))
	for range testCycles {
		f1 := rnum.NormFloat64()
		scale := rnum.Intn(100) - 50
		f1 = math.Ldexp(f1, scale)
		f2 := rnum.NormFloat64()
		scale = rnum.Intn(100) - 50
		f2 = math.Ldexp(f2, scale)
		if !cw.floatToFpreg(0, f1) {
			continue
		}
		if !cw.floatToFpreg(2, f2) {
			continue
		}
		mb := f1 / f2
		cw.setMemory(0x400, 0x2d020000) // DDR 0,2
		cw.testInst(0)
		if math.Abs(mb) < 5.4e-79 || math.Abs(mb) > 7.2e75 {
			if !cw.trap {
				t.Error("DD did not trap")
			}
		} else {
			if cw.trap {
				t.Error("DD should not have trapped")
			}
			v := cw.cnvtLongFloat(0)
			ratio := math.Abs((v - mb) / mb)
			if ratio > 0.000001 {
				t.Errorf("DD difference too large got: %f expected: %f", v, mb)
			}
		}
	}
}

// Add double unnormalized.
func (cw *cornwellFixture) TestCycleAW(t *testing.T) {
	cw.setup()

	cw.setFloatShort(6, 0x43082100)
	cw.setFloatShort(7, 0x00000000)
	cw.setMemory(0x2000, 0x41123456)
	cw.setMemory(0x2004, 0x00000000)
	cw.c.GR[13] = 0x00002000
	cw.setMemory(0x400, 0x6e60d000) // AU 6,0(0, 13)
	cw.testInst(0)
	v := cw.getFloatShort(6)
	mv := uint32(0x43083334)
	if v != mv {
		t.Errorf("AW Register 6 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getFloatShort(7)
	mv = uint32(0x56000000)
	if v != mv {
		t.Errorf("AW Register 7 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("AW CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, 2)
	}
}

// Subtract double unnormalized.
func (cw *cornwellFixture) TestCycleSW(t *testing.T) {
	cw.setup()

	cw.setFloatShort(6, 0x43082100)
	cw.setFloatShort(7, 0x00000000)
	cw.setMemory(0x2000, 0x41123456)
	cw.setMemory(0x2004, 0x00000000)
	cw.c.GR[13] = 0x00002000
	cw.setMemory(0x400, 0x6f60d000) // SU 6,0(0, 13)
	cw.testInst(0)
	v := cw.getFloatShort(6)
	mv := uint32(0x43080ecb)
	if v != mv {
		t.Errorf("SW Register 6 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getFloatShort(7)
	mv = uint32(0xaa000000)
	if v != mv {
		t.Errorf("SW Register 7 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("SW CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, 2)
	}
}

// Store float point.
func (cw *cornwellFixture) TestCycleSTE(t *testing.T) {
	cw.setup()

	cw.setFloatShort(0, 0x12345678)
	cw.setFloatShort(1, 0xaabbccdd)
	cw.c.GR[1] = 0x100
	cw.c.GR[2] = 0x300
	cw.setMemory(0x404, 0x11223344)
	cw.setMemory(0x400, 0x70012100) // STE 0,100(1,2)
	cw.setMemory(0x500, 0xaabbccdd)
	cw.setMemory(0x505, 0x11223344)
	cw.testInst(0)
	v := cw.getMemory(0x500)
	mv := uint32(0x12345678)
	if v != mv {
		t.Errorf("STE Memory 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getMemory(0x504)
	mv = uint32(0x11223344)
	if v != mv {
		t.Errorf("STE Memory 2 not correct got: %08x wanted: %08x", v, mv)
	}
}

// Test floating point load short.
func (cw *cornwellFixture) TestCycleLE(t *testing.T) {
	cw.setup()

	cw.setFloatShort(0, 0x12345678)
	cw.setFloatShort(1, 0xaabbccdd)
	cw.c.GR[1] = 0x100
	cw.c.GR[2] = 0x300
	cw.setMemory(0x500, 0x11223344)
	cw.setMemory(0x505, 0x11223344)
	cw.setMemory(0x400, 0x78012100) // LE 0,100(1,2)
	cw.setMemory(0x404, 0x00000000)
	cw.testInst(0)
	v := cw.getFloatShort(0)
	mv := uint32(0x11223344)
	if v != mv {
		t.Errorf("LE Register 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getFloatShort(1)
	mv = uint32(0xaabbccdd)
	if v != mv {
		t.Errorf("LE Register 2 not correct got: %08x wanted: %08x", v, mv)
	}

	cw.setMemory(0x100, 0x44000000)
	cw.setMemory(0x104, 0xaabbccdd)
	cw.setMemory(0x400, 0x78000100) //  LE 0,100(0,0)
	cw.setMemory(0x404, 0x00000000)
	cw.setFloatShort(0, 0xffffffff)
	cw.setFloatShort(1, 0xffffffff)
	cw.testInst(0)
	v = cw.getFloatShort(0)
	mv = uint32(0x44000000) // Stays unnormalized
	if v != mv {
		t.Errorf("LE Register 1 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getFloatShort(1)
	mv = uint32(0xffffffff)
	if v != mv {
		t.Errorf("LE Register 2 not correct got: %08x wanted: %08x", v, mv)
	}
}

// Test compare short.
func (cw *cornwellFixture) TestCycleCE(t *testing.T) {
	cw.setup()

	// Check results
	cw.setFloatShort(0, 0x12345678)
	cw.setFloatShort(1, 0xaabbccdd)
	cw.c.GR[1] = 0x100
	cw.c.GR[2] = 0x300
	cw.setMemory(0x500, 0x11223344)
	cw.setMemory(0x400, 0x79012100) // CE 0,100(1,2)
	cw.setMemory(0x404, 0x00000000)
	cw.testInst(0)
	if cw.c.PSW.CC != 2 {
		t.Errorf("CE CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, 2)
	}

	cw.setFloatShort(0, 0x34100000)
	cw.setFloatShort(1, 0x00000000)
	cw.setMemory(0x100, 0x32123456)
	cw.setMemory(0x104, 0x789ABCDE)
	cw.setMemory(0x400, 0x79000100) // CE 0,100(0,0)
	cw.setMemory(0x404, 0x00000000)
	cw.testInst(0)
	if cw.c.PSW.CC != 2 {
		t.Errorf("CE CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, 2)
	}

	cw.setFloatShort(0, 0x12345678)
	cw.setFloatShort(1, 0xaabbccdd)
	cw.setMemory(0x100, 0x14100000)
	cw.setMemory(0x104, 0xaabbccdd)
	cw.setMemory(0x400, 0x79000100) // CE 0,100(0,0)
	cw.setMemory(0x404, 0x00000000)
	cw.testInst(0)
	if cw.c.PSW.CC != 1 {
		t.Errorf("CE CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, 1)
	}

	cw.setFloatShort(0, 0x43082100)
	cw.setFloatShort(1, 0xaabbccdd)
	cw.setMemory(0x100, 0x43082100)
	cw.setMemory(0x104, 0xaabbccdd)
	cw.setMemory(0x400, 0x79000100) // CE 0,100(0,0)
	cw.setMemory(0x404, 0x00000000)
	cw.testInst(0)
	if cw.c.PSW.CC != 0 {
		t.Errorf("CE CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, 0)
	}
}

// Half instruct rand.
func (cw *cornwellFixture) TestCycleHE(t *testing.T) {
	cw.setup()
	rnum := rand.New(rand.NewSource(125))
	for range testCycles {
		f := rnum.NormFloat64()
		scale := rnum.Intn(100) - 50
		f = math.Ldexp(f, scale)
		low := rnum.Uint32()
		if !cw.floatToFpreg(2, f) {
			continue
		}
		cw.setFloatShort(5, low) // Low half of destination FPR4.
		mb := f / 2.0
		cw.setMemory(0x400, 0x34420000) // HER 4,2
		cw.testInst(0)
		v := cw.cnvtShortFloat(4)
		ratio := math.Abs((v - mb) / mb)
		if ratio > 0.000001 {
			t.Errorf("HER difference too large got: %f expected: %f", v, mb)
		}
		if low != cw.getFloatShort(5) {
			t.Errorf("HER modified lower regiser got: %08x expected: %08x", cw.getFloatShort(5), low)
		}
	}
}

// Add short.
func (cw *cornwellFixture) TestCycleAE(t *testing.T) {
	cw.setup()

	cw.setFloatShort(0, 0x12345678)
	cw.setFloatShort(1, 0xaabbccdd)
	cw.c.GR[1] = 0x100
	cw.c.GR[2] = 0x300
	cw.setMemory(0x500, 0x11223344)
	cw.setMemory(0x400, 0x7a012100) // AE 0,100(1,2)
	cw.testInst(0)

	v := cw.getFloatShort(0)
	mv := uint32(0x123679ac)
	if v != mv {
		t.Fatalf("AE Register 0 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getFloatShort(1)
	mv = uint32(0xaabbccdd)
	if v != mv {
		t.Fatalf("AE Register 1 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 2 {
		t.Fatalf("AE CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, 2)
	}

	rnum := rand.New(rand.NewSource(125))
	executed := 0
	for range testCycles {
		f1 := rnum.NormFloat64()
		scale := rnum.Intn(100) - 50
		f1 = math.Ldexp(f1, scale)
		f2 := rnum.NormFloat64()
		scale = rnum.Intn(100) - 50
		f2 = math.Ldexp(f2, scale)
		low := rnum.Uint32()
		if !cw.floatToFpreg(4, f1) {
			continue
		}
		if !cw.floatToFpreg(2, f2) {
			continue
		}
		// Compare with the short operands actually supplied to the CPU.
		f1, f2 = cw.cnvtShortFloat(4), cw.cnvtShortFloat(2)
		executed++
		mb := f1 + f2
		cw.setFloatShort(5, low)
		cw.setFloatShort(3, ^low)
		cw.setMemory(0x400, 0x3a420000) // AER 4,2
		cw.testInst(0)
		v := cw.cnvtShortFloat(4)
		ratio := math.Abs((v - mb) / mb)
		if ratio > 0.000001 {
			t.Fatalf("AE difference too large got: %f expected: %f", v, mb)
		}
		cc := uint8(0)
		if mb != 0.0 {
			if mb < 0.0 {
				cc = 1
			} else {
				cc = 2
			}
		}
		if cw.c.PSW.CC != cc {
			t.Fatalf("AE CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, cc)
		}
		if low != cw.getFloatShort(5) {
			t.Fatalf("AE modified lower regiser got: %08x expected: %08x", cw.getFloatShort(5), low)
		}
	}
	if executed != testCycles {
		t.Fatalf("executed %d of %d random cases", executed, testCycles)
	}
}

// Subtract short.
func (cw *cornwellFixture) TestCycleSE(t *testing.T) {
	cw.setup()

	cw.setFloatShort(0, 0x12345678)
	cw.setFloatShort(1, 0xaabbccdd)
	cw.c.GR[1] = 0x100
	cw.c.GR[2] = 0x300
	cw.setMemory(0x500, 0x11223344)
	cw.setMemory(0x400, 0x7b012100) // SE 0,100(1,2)
	cw.testInst(0)
	v := cw.getFloatShort(0)
	mv := uint32(0x12323343)
	if v != mv {
		t.Fatalf("SE Register 0 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getFloatShort(1)
	mv = uint32(0xaabbccdd)
	if v != mv {
		t.Fatalf("SE Register 1 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 2 {
		t.Fatalf("SE CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, 2)
	}

	rnum := rand.New(rand.NewSource(125))
	executed := 0
	for range testCycles {
		f1 := rnum.NormFloat64()
		scale := rnum.Intn(100) - 50
		f1 = math.Ldexp(f1, scale)
		f2 := rnum.NormFloat64()
		scale = rnum.Intn(100) - 50
		f2 = math.Ldexp(f2, scale)
		low := rnum.Uint32()
		if !cw.floatToFpreg(0, f1) {
			continue
		}
		if !cw.floatToFpreg(2, f2) {
			continue
		}
		// Compare with the short operands actually supplied to the CPU.
		f1, f2 = cw.cnvtShortFloat(0), cw.cnvtShortFloat(2)
		executed++
		mb := f1 - f2
		cw.setFloatShort(1, low)
		cw.setFloatShort(3, ^low)
		cw.setMemory(0x400, 0x3b020000) // SER 0,2
		cw.testInst(0)
		v := cw.cnvtShortFloat(0)
		ratio := math.Abs((v - mb) / mb)
		if ratio > 0.000001 {
			t.Fatalf("SE difference too large got: %f expected: %f", v, mb)
		}
		cc := uint8(0)
		if mb != 0.0 {
			if mb < 0.0 {
				cc = 1
			} else {
				cc = 2
			}
		}
		if cw.c.PSW.CC != cc {
			t.Fatalf("SE CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, cc)
		}
		if low != cw.getFloatShort(1) {
			t.Fatalf("SE modified lower regiser got: %08x expected: %08x", cw.getFloatShort(1), low)
		}
	}
	if executed != testCycles {
		t.Fatalf("executed %d of %d random cases", executed, testCycles)
	}
}

// Multiply short.
func (cw *cornwellFixture) TestCyclME(t *testing.T) {
	cw.setup()

	cw.setFloatShort(0, 0x43082100)
	cw.setFloatShort(1, 0xaabbccdd)
	cw.setMemory(0x500, 0x41123456)
	cw.c.GR[1] = 0x100
	cw.c.GR[2] = 0x300
	cw.setMemory(0x400, 0x7c012100) // ME 0,100(1,2)
	cw.testInst(0)

	v := cw.getFloatLong(0)
	mv := uint64(0x4293fb6f16000000)
	if v != mv {
		t.Fatalf("ME Register 0 not correct got: %016x wanted: %016x", v, mv)
	}
	if cw.c.PSW.CC != 3 {
		t.Fatalf("ME CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, 3)
	}

	rnum := rand.New(rand.NewSource(125))
	executed := 0
	for range testCycles {
		f1 := rnum.NormFloat64()
		scale := rnum.Intn(100) - 50
		f1 = math.Ldexp(f1, scale)
		f2 := rnum.NormFloat64()
		scale = rnum.Intn(100) - 50
		f2 = math.Ldexp(f2, scale)
		low := rnum.Uint32()
		if !cw.floatToFpreg(0, f1) {
			continue
		}
		if !cw.floatToFpreg(2, f2) {
			continue
		}
		cw.setFloatShort(1, low)
		cw.setFloatShort(3, ^low)
		// Compare with the short operands actually supplied to the CPU.
		f1, f2 = cw.cnvtShortFloat(0), cw.cnvtShortFloat(2)
		executed++
		mb := f1 * f2
		cw.setMemory(0x400, 0x3c020000) // MER 0,2
		cw.testInst(0)
		if math.Abs(mb) < 5.4e-79 || math.Abs(mb) > 7.2e75 {
			if !cw.trap {
				t.Error("ME did not trap")
			}
		} else {
			if cw.trap {
				t.Error("ME should not have trapped")
			}
			v := cw.cnvtLongFloat(0)
			ratio := math.Abs((v - mb) / mb)
			if ratio > 0.000001 {
				t.Fatalf("ME difference too large got: %f expected: %f", v, mb)
			}
		}
	}
	if executed != testCycles {
		t.Fatalf("executed %d of %d random cases", executed, testCycles)
	}
}

// Divide short.
func (cw *cornwellFixture) TestCyclDE(t *testing.T) {
	cw.setup()

	cw.setFloatShort(0, 0x43082100)
	cw.setFloatShort(1, 0xaabbccdd)
	cw.setMemory(0x500, 0x41123456)
	cw.c.GR[1] = 0x100
	cw.c.GR[2] = 0x300
	cw.setMemory(0x400, 0x7d012100) // DE 0,100(1,2)
	// 	cpuState.testInst(0,20)
	// 	ASSERT_EQUAL_X(0x42725012, get_fpreg_s(0))
	cw.testInst(0)

	v := cw.getFloatShort(0)
	mv := uint32(0x42725012)
	if v != mv {
		t.Fatalf("DE Register 0 not correct got: %08x wanted: %08x", v, mv)
	}
	v = cw.getFloatShort(1)
	mv = uint32(0xaabbccdd)
	if v != mv {
		t.Fatalf("DE Register 1 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 3 {
		t.Fatalf("DE CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, 3)
	}

	rnum := rand.New(rand.NewSource(125))
	executed := 0
	for range testCycles {
		f1 := rnum.NormFloat64()
		scale := rnum.Intn(100) - 50
		f1 = math.Ldexp(f1, scale)
		f2 := rnum.NormFloat64()
		scale = rnum.Intn(100) - 50
		f2 = math.Ldexp(f2, scale)
		low := rnum.Uint32()
		if !cw.floatToFpreg(0, f1) {
			continue
		}
		if !cw.floatToFpreg(2, f2) {
			continue
		}
		// Compare with the short operands actually supplied to the CPU.
		f1, f2 = cw.cnvtShortFloat(0), cw.cnvtShortFloat(2)
		executed++
		mb := f1 / f2
		cw.setFloatShort(1, low)
		cw.setFloatShort(3, ^low)
		cw.setMemory(0x400, 0x3d020000) // DER 0,2
		cw.testInst(0)
		v := cw.cnvtShortFloat(0)
		ratio := math.Abs((v - mb) / mb)
		if ratio > 0.000001 {
			t.Fatalf("DE difference too large got: %f expected: %f", v, mb)
		}
		cc := uint8(3) // DER preserves CC, as does the fixed DE vector above.
		if cw.c.PSW.CC != cc {
			t.Fatalf("DE CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, cc)
		}
		if low != cw.getFloatShort(1) {
			t.Fatalf("DE modified lower regiser got: %08x expected: %08x", cw.getFloatShort(1), low)
		}
	}
	if executed != testCycles {
		t.Fatalf("executed %d of %d random cases", executed, testCycles)
	}
}

// Add short unnormalized.
func (cw *cornwellFixture) TestCycleAU(t *testing.T) {
	cw.setup()
	// Princ Ops 153

	cw.setFloatShort(6, 0x43082100)
	cw.setFloatShort(7, 0x00000000)
	cw.setMemory(0x2000, 0x41123456)
	cw.setMemory(0x2004, 0x00000000)
	cw.c.GR[13] = 0x00002000
	cw.setMemory(0x400, 0x7e60d000) // AU 6,0(0, 13)
	cw.testInst(0)
	v := cw.getFloatShort(6)
	mv := uint32(0x43083334)
	if v != mv {
		t.Errorf("AW Register 6 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("AW CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, 2)
	}
}

// Subtract short unnormalized.
func (cw *cornwellFixture) TestCycleSU(t *testing.T) {
	cw.setup()

	cw.setFloatShort(6, 0x43082100)
	cw.setFloatShort(7, 0x00000000)
	cw.setMemory(0x2000, 0x41123456)
	cw.setMemory(0x2004, 0x00000000)
	cw.c.GR[13] = 0x00002000
	cw.setMemory(0x400, 0x7f60d000) // SU 6,0(0, 13)
	cw.testInst(0)
	v := cw.getFloatShort(6)
	mv := uint32(0x43080ecb)
	if v != mv {
		t.Errorf("SE Register 6 not correct got: %08x wanted: %08x", v, mv)
	}
	if cw.c.PSW.CC != 2 {
		t.Errorf("SW CC not set correctly got: %d wanted: %d", cw.c.PSW.CC, 2)
	}
}
