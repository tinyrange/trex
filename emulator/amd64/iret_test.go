package amd64

import (
	"encoding/binary"
	"github.com/tinyrange/trex/emulator/cpu"
	"testing"
)

func TestIRETQUserContext(t *testing.T) {
	for _, mode := range []string{"return", "iopl3", "short", "write-only", "cs", "ss", "kernel", "null", "ip", "sp", "nt", "vm", "vif", "vip", "current-nt"} {
		c, m := codeMemory(t, "48cf")
		c.selectors[0], c.selectors[1] = 0x33, 0x2b
		c.flags = 0x202
		if mode == "iopl3" {
			c.flags |= 0x3000
		}
		frame := make([]byte, 40)
		put := func(o int, v uint64) { binary.LittleEndian.PutUint64(frame[o:], v) }
		put(0, 0x180002000)
		put(8, 0xaaaaaaaaaaaa0033)
		put(16, 0x251cd7)
		put(24, 0x7ffffeff0000)
		put(32, 0xbbbbbbbbbbbb002b)
		access := cpu.Read
		switch mode {
		case "short":
			frame = frame[:39]
		case "write-only":
			access = cpu.Write
		case "cs":
			put(8, 0x43)
		case "ss":
			put(32, 0x3b)
		case "kernel":
			c.selectors[0] = 0x10
			put(8, 0x10)
		case "null":
			c.selectors[0] = 3
			put(8, 3)
		case "ip":
			put(0, 1<<48)
		case "sp":
			put(24, 1<<47)
		case "nt":
			put(16, 1<<14)
		case "vm":
			put(16, 1<<17)
		case "vif":
			put(16, 1<<19)
		case "vip":
			put(16, 1<<20)
		case "current-nt":
			c.flags |= 1 << 14
		}
		c.registers[4] = 0x200000
		if err := m.Map(c.registers[4], frame, access); err != nil {
			t.Fatal(err)
		}
		before := *c
		_, err := c.Step(m)
		if mode != "return" && mode != "iopl3" {
			if err == nil || *c != before {
				t.Fatalf("%s: non-atomic invalid return: %v", mode, err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		want := before
		want.rip = 0x180002000
		want.registers[4] = 0x7ffffeff0000
		want.timestampCounter++
		want.flags = 0x250ed7 // input status/RF/AC/ID, old IF; input IOPL cannot elevate
		if mode == "iopl3" {
			want.flags = 0x253cd7
		} // IOPL retained, IF now cleared
		if *c != want {
			t.Fatalf("%s got flags=%x rsp=%x rip=%x, want flags=%x", mode, c.flags, c.registers[4], c.rip, want.flags)
		}
	}
}
