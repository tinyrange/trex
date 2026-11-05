package amd64

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/tinyrange/trex/emulator/cpu"
)

func TestFXSAVELongModeState(t *testing.T) {
	// Legacy, REX.W, REX.B (R8 destination), and RIP-relative operands.
	for _, code := range []string{"0fae01", "480fae01", "410fae00", "0fae05f9ff0f00"} {
		for _, control := range []uint64{0x1f80, 0, 0xffff} {
			c, m := codeMemory(t, code)
			address := uint64(0x200000)
			if code == "0fae05f9ff0f00" {
				address = c.rip + 0x100000
			}
			c.registers[1], c.registers[8] = address, address
			for i := range c.xmm {
				for j := range c.xmm[i] {
					c.xmm[i][j] = byte(i*17 + j)
				}
			}
			if err := c.setMXCSR(control); err != nil {
				t.Fatal(err)
			}
			c.flags = 0xad7
			before := *c
			// Guard the defined register area and the caller-owned tail;
			// deliberately deny reads to the instruction's destination.
			data := bytes.Repeat([]byte{0xa5}, 544)
			if err := m.Map(address-16, data, cpu.Write); err != nil {
				t.Fatal(err)
			}
			if _, err := c.Step(m); err != nil {
				t.Fatalf("%s: %v", code, err)
			}
			if c.registers != before.registers || c.xmm != before.xmm || c.flags != before.flags || c.readMXCSR() != control {
				t.Fatal("FXSAVE modified registers")
			}
			// Read the saved area after explicitly granting inspection access.
			if _, err := m.Protect(address-16, len(data), cpu.Read|cpu.Write); err != nil {
				t.Fatal(err)
			}
			if err := m.ReadMemory(address-16, data, cpu.Read); err != nil {
				t.Fatal(err)
			}
			state := data[16:432]
			if binary.LittleEndian.Uint16(state[:2]) != 0x037f || !bytes.Equal(state[2:24], make([]byte, 22)) || !bytes.Equal(state[32:160], make([]byte, 128)) {
				t.Fatalf("x87 reset environment %x", state[:32])
			}
			if binary.LittleEndian.Uint32(state[24:28]) != uint32(control) || binary.LittleEndian.Uint32(state[28:32]) != 0xffff {
				t.Fatalf("MXCSR environment %x", state[24:32])
			}
			for i := range before.xmm {
				if !bytes.Equal(state[160+16*i:176+16*i], before.xmm[i][:]) {
					t.Fatalf("XMM%d not saved", i)
				}
			}
			if !bytes.Equal(data[:16], bytes.Repeat([]byte{0xa5}, 16)) || !bytes.Equal(data[432:], bytes.Repeat([]byte{0xa5}, 112)) {
				t.Fatal("reserved/software tail or guard changed")
			}
		}
	}
}

func TestFXSAVEFaultsAndResetMXCSR(t *testing.T) {
	for _, mode := range []string{"alignment", "readonly", "unmapped-tail", "reset"} {
		c, m := codeMemory(t, "0fae01")
		address := uint64(0x200000)
		c.registers[1] = address
		c.flags = 0xad7
		size, access := 512, cpu.Read|cpu.Write
		if mode == "alignment" {
			c.registers[1]++
		}
		if mode == "readonly" {
			access = cpu.Read
		}
		if mode == "unmapped-tail" {
			size = 415
		}
		data := bytes.Repeat([]byte{0xa5}, size)
		if err := m.Map(address, data, access); err != nil {
			t.Fatal(err)
		}
		before := *c
		_, err := c.Step(m)
		if mode == "reset" {
			if err != nil {
				t.Fatal(err)
			}
			if err := m.ReadMemory(address, data, cpu.Read); err != nil {
				t.Fatal(err)
			}
			if binary.LittleEndian.Uint32(data[24:28]) != 0x1f80 {
				t.Fatal("incorrect reset MXCSR")
			}
		} else {
			if err == nil || c.PC() != before.PC() || c.flags != before.flags || c.xmm != before.xmm || c.registers != before.registers {
				t.Fatalf("fault changed architectural state: %v", err)
			}
			if err := m.ReadMemory(address, data, cpu.Read); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, bytes.Repeat([]byte{0xa5}, size)) {
				t.Fatal("fault partially wrote state")
			}
		}
	}
}
