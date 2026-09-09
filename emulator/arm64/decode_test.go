package arm64

import (
	"encoding/binary"
	"github.com/tinyrange/trex/emulator/cpu"
	"testing"
)

func TestDecodeCacheCodeChangesAndPermissions(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		m := memory(t)
		c := &CPU{DisableDecodeCache: disabled}
		var word [4]byte
		for _, instruction := range []struct {
			code uint32
			want uint64
		}{
			{0xd2800060, 3}, // MOV X0,#3
			{0x91001400, 8}, // ADD X0,X0,#5 at the same address
			{0xd2800120, 9}, // same class as the first, different operand
			{0xd2800060, 3}, // repeat after intervening code writes
		} {
			binary.LittleEndian.PutUint32(word[:], instruction.code)
			if err := m.WriteMemory(0x1000, word[:]); err != nil {
				t.Fatal(err)
			}
			c.SetPC(0x1000)
			if _, err := c.Step(m); err != nil {
				t.Fatal(err)
			}
			if c.x[0] != instruction.want {
				t.Fatalf("disabled=%v x0=%d want=%d", disabled, c.x[0], instruction.want)
			}
		}
		if _, err := m.Protect(0x1000, 4, cpu.Read|cpu.Write); err != nil {
			t.Fatal(err)
		}
		c.SetPC(0x1000)
		if _, err := c.Step(m); err == nil {
			t.Fatal("cached instruction bypassed execute permission")
		}
	}
}
