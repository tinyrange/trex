package amd64

import (
	"github.com/tinyrange/trex/emulator/cpu"
	"testing"
)

func TestMOVAPD(t *testing.T) {
	for _, test := range []struct {
		code   string
		offset uint64
		fault  bool
	}{
		{"66 0f 28 c1", 0, false}, {"66 0f 28 00", 0, false}, {"66 0f 28 00", 1, true},
	} {
		c, m := codeMemory(t, test.code)
		var value [16]byte
		for i := range value {
			value[i] = byte(i * 17)
		}
		c.xmm[1] = value
		c.registers[0] = 0x600000000 + test.offset
		data := make([]byte, 32)
		copy(data, value[:])
		if err := m.Map(0x600000000, data, cpu.Read); err != nil {
			t.Fatal(err)
		}
		c.flags = flagCarry | flagOverflow
		_, err := c.Step(m)
		if test.fault {
			if err == nil {
				t.Fatal("accepted unaligned MOVAPD")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if c.xmm[0] != value || c.flags != flagCarry|flagOverflow {
			t.Fatal("MOVAPD corrupted bits/flags")
		}
	}
}
