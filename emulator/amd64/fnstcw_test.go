package amd64

import (
	"bytes"
	"github.com/tinyrange/trex/emulator/cpu"
	"testing"
)

func TestFNSTCWContextAndFaultAtomicity(t *testing.T) {
	for _, mode := range []string{"write-only", "unaligned", "readonly", "short"} {
		c, m := codeMemory(t, "d9 b9 00 01 00 00") // fnstcw [rcx+100h], native RtlCaptureContext
		address := uint64(0x200000)
		if mode == "unaligned" {
			address++
		}
		c.registers[1] = address - 0x100
		c.flags = 0xad7
		size, access := 4, cpu.Write
		if mode == "readonly" {
			access = cpu.Read
		}
		if mode == "short" {
			size = 1
		}
		if err := m.Map(address, bytes.Repeat([]byte{0xa5}, size), access); err != nil {
			t.Fatal(err)
		}
		before := *c
		_, err := c.Step(m)
		fault := mode == "readonly" || mode == "short"
		if fault {
			if err == nil || *c != before {
				t.Fatalf("%s fault changed state: %v", mode, err)
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			expected := before
			expected.rip += 6
			expected.timestampCounter++
			if *c != expected {
				t.Fatal("FNSTCW modified registers")
			}
		}
		if _, err := m.Protect(address, size, cpu.Read|cpu.Write); err != nil {
			t.Fatal(err)
		}
		data := make([]byte, size)
		if err := m.ReadMemory(address, data, cpu.Read); err != nil {
			t.Fatal(err)
		}
		want := bytes.Repeat([]byte{0xa5}, size)
		if !fault {
			want[0], want[1] = 0x7f, 0x03
		}
		if !bytes.Equal(data, want) {
			t.Fatalf("%s changed guard or partial write: %x", mode, data)
		}
	}
}
