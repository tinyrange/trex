package amd64

import "testing"

func TestPrefetchIsNonFaultingHint(t *testing.T) {
	for _, code := range []string{"0f 18 00", "0f 18 08", "0f 18 10", "0f 18 18", "0f 0d 08"} {
		t.Run(code, func(t *testing.T) {
			c, m := codeMemory(t, code)
			c.registers[0] = 0x600deadbeef
			c.flags = flagCarry | flagZero | flagDirection
			before, flags, pc := c.registers, c.flags, c.rip
			if _, err := c.Step(m); err != nil {
				t.Fatal(err)
			}
			if c.registers != before || c.flags != flags || c.rip != pc+3 {
				t.Fatalf("prefetch changed architectural state: %#v", c)
			}
		})
	}
}
