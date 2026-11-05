package amd64

import (
	"bytes"
	"testing"

	"github.com/tinyrange/trex/emulator/cpu"
)

func TestMOVNTPSStoreAndFence(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		source     int
	}{
		{"native-copy", "0f2b01 0faef8", 0},
		{"extended", "440f2b39 0faef8", 15},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, m := codeMemory(t, tc.code)
			const address = 0x200000010
			c.registers[1] = address
			if err := m.Map(address-16, bytes.Repeat([]byte{0x55}, 48), cpu.Read|cpu.Write); err != nil {
				t.Fatal(err)
			}
			c.xmm[tc.source] = [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
			c.flags = flagCarry | flagOverflow
			before := *c
			for range 2 {
				if _, err := c.Step(m); err != nil {
					t.Fatal(err)
				}
			}
			got := make([]byte, 48)
			if err := m.ReadMemory(address-16, got, cpu.Read); err != nil {
				t.Fatal(err)
			}
			want := bytes.Repeat([]byte{0x55}, 48)
			copy(want[16:32], before.xmm[tc.source][:])
			if !bytes.Equal(got, want) || c.xmm != before.xmm || c.registers != before.registers || c.flags != before.flags {
				t.Fatal("store/fence changed unexpected state")
			}
		})
	}
}

func TestMOVNTPSFaultPreservesState(t *testing.T) {
	for _, tc := range []struct {
		name        string
		offset      uint64
		permissions cpu.Access
	}{
		{"unaligned", 1, cpu.Read | cpu.Write},
		{"read-only", 0, cpu.Read},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, m := codeMemory(t, "0f2b01")
			address := uint64(0x200000000)
			c.registers[1] = address + tc.offset
			initial := bytes.Repeat([]byte{0x55}, 32)
			if err := m.Map(address, initial, tc.permissions); err != nil {
				t.Fatal(err)
			}
			c.xmm[0] = [16]byte{1, 2, 3, 4}
			before := *c
			if _, err := c.Step(m); err == nil {
				t.Fatal("invalid store succeeded")
			}
			got := make([]byte, 32)
			if err := m.ReadMemory(address, got, cpu.Read); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, initial) || c.PC() != before.PC() || c.xmm != before.xmm || c.flags != before.flags {
				t.Fatal("fault changed architectural state")
			}
		})
	}
}
