package amd64

import (
	"bytes"
	"encoding/binary"
	"github.com/tinyrange/trex/emulator/cpu"
	"testing"
)

func TestFXRSTORRoundTripAndFaults(t *testing.T) {
	for _, code := range []string{"0fae09", "480fae09", "410fae08"} {
		for _, mode := range []string{"restore", "alignment", "short", "write-only", "mxcsr", "control", "status", "tag", "opcode", "ip", "dp"} {
			c, m := codeMemory(t, code)
			address := uint64(0x200000)
			c.registers[1], c.registers[8] = address, address
			c.flags = 0xad7
			for i := range c.xmm {
				for j := range c.xmm[i] {
					c.xmm[i][j] = 0xa5
				}
			}
			state := bytes.Repeat([]byte{0xa5}, 512)
			clear(state[:32])
			binary.LittleEndian.PutUint16(state, 0x037f)
			binary.LittleEndian.PutUint32(state[24:28], 0x5f80)
			for i := 0; i < 16; i++ {
				for j := 0; j < 16; j++ {
					state[160+16*i+j] = byte(i*17 + j)
				}
			}
			access := cpu.Read
			switch mode {
			case "alignment":
				c.registers[1]++
				c.registers[8]++
			case "short":
				state = state[:415]
			case "write-only":
				access = cpu.Write
			case "mxcsr":
				binary.LittleEndian.PutUint32(state[24:28], 0x10000)
			case "control":
				state[0] = 0x7e
			case "status":
				state[2] = 1
			case "tag":
				state[4] = 1
			case "opcode":
				state[6] = 1
			case "ip":
				state[8] = 1
			case "dp":
				state[16] = 1
			}
			if err := m.Map(address, state, access); err != nil {
				t.Fatal(err)
			}
			before := *c
			_, err := c.Step(m)
			if mode != "restore" {
				if err == nil || *c != before {
					t.Fatalf("%s/%s: non-atomic fault: %v", code, mode, err)
				}
				continue
			}
			if err != nil {
				t.Fatalf("%s: %v", code, err)
			}
			if c.registers != before.registers || c.flags != before.flags || c.readMXCSR() != 0x5f80 {
				t.Fatal("incorrect restored state")
			}
			for i := range c.xmm {
				if !bytes.Equal(c.xmm[i][:], state[160+16*i:176+16*i]) {
					t.Fatalf("XMM%d not restored", i)
				}
			}
			// The source is read-only, and caller-owned/reserved bytes remain unchanged.
			got := make([]byte, len(state))
			if err := m.ReadMemory(address, got, cpu.Read); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, state) {
				t.Fatal("FXRSTOR modified its source")
			}
		}
	}
}
