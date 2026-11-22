package power

import "math"

// Round to an integral floating-point value independently of FPSCR.RN.
// Power ISA Book I 4.6.7.3 requires FR/FI=0 and preserves XX, even for an
// inexact result. Only a signaling NaN can raise a new exception here.
func (c *CPU) roundToIntegral(w uint32, round func(float64) float64) {
	t, b := (w>>21)&31, (w>>11)&31
	encoded := c.FPR[b]
	src := math.Float64frombits(encoded)
	c.FPSCR &^= fpsFR | fpsFI
	snan := math.IsNaN(src) && encoded&(1<<51) == 0
	if snan {
		c.fpException(fpsVXSNAN)
		if c.FPSCR&fpsVE != 0 {
			c.fpCheckEnabled(w, true)
			return
		}
	}
	var result uint64
	var class uint64
	if math.IsNaN(src) {
		result, class = encoded|1<<51, 0x11 // quiet NaN, retaining sign/payload
	} else {
		value := round(src)
		result = math.Float64bits(value)
		switch {
		case math.IsInf(value, 1):
			class = 5
		case math.IsInf(value, -1):
			class = 9
		case value == 0:
			class = 2
			if result>>63 != 0 {
				class = 0x12
			}
		case value < 0:
			class = 8
		default:
			class = 4
		}
	}
	c.FPR[t] = result
	c.FPSCR = c.FPSCR&^fpsFPRF | class<<12
	c.fpCheckEnabled(w, false)
}
