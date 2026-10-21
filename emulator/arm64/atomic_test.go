package arm64

import (
	"encoding/binary"
	"testing"

	"github.com/tinyrange/trex/emulator/cpu"
)

func TestLSEAddAndSetSizesOrderingAndAliases(t *testing.T) {
	for _, operation := range []uint32{0, 3} {
		for sizeLog := uint32(0); sizeLog < 4; sizeLog++ {
			for order := uint32(0); order < 4; order++ {
				m := memory(t)
				c := &CPU{}
				c.x[1], c.x[2] = 0x2000, 3
				data := [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
				if err := m.WriteMemory(0x2000, data[:]); err != nil {
					t.Fatal(err)
				}
				code := uint32(0x38200000) | sizeLog<<30 | order<<22 | 2<<16 | operation<<12 | 1<<5
				step(t, c, m, code)
				if err := m.ReadMemory(0x2000, data[:], cpu.Read); err != nil {
					t.Fatal(err)
				}
				size := 1 << sizeLog
				wantOld := mask(uint32(size * 8))
				if c.x[0] != wantOld {
					t.Fatalf("op=%d size=%d ordering=%d old=%x", operation, size, order, c.x[0])
				}
				want := wantOld
				if operation == 0 {
					want = (want + 3) & wantOld
				}
				for j := 0; j < size; j++ {
					if data[j] != byte(want>>uint(8*j)) {
						t.Fatalf("atomic result %x", data)
					}
				}
				for j := size; j < 8; j++ {
					if data[j] != 255 {
						t.Fatal("atomic operation changed adjacent byte")
					}
				}
			}
		}
	}
	m := memory(t)
	c := &CPU{}
	c.sp = 0x2000
	c.x[3] = 0x80
	c.nzcv = 0xf0000000
	step(t, c, m, 0xf82333ff) // LDSET X3,XZR,[SP]
	var b [8]byte
	m.ReadMemory(0x2000, b[:], cpu.Read)
	if binary.LittleEndian.Uint64(b[:]) != 0x80 || c.sp != 0x2000 || c.nzcv != 0xf0000000 {
		t.Fatal("store alias/base/flags")
	}
	c.x[8] = 0x2000
	step(t, c, m, 0xb83f3108) // LDSET WZR,W8,[X8]: zero source, aliased address/destination
	if c.x[8] != 0x80 {
		t.Fatal("zero register source or address alias")
	}
}

func TestLSEFaultDoesNotCommitMemoryRegisterOrPC(t *testing.T) {
	for _, unaligned := range []bool{false, true} {
		m := memory(t)
		c := &CPU{}
		c.x[0], c.x[1], c.x[2] = 99, 0x2000, 1
		if unaligned {
			c.x[1]++
		} else if _, err := m.Protect(0x2000, 4096, cpu.Read); err != nil {
			t.Fatal(err)
		}
		var instruction [4]byte
		binary.LittleEndian.PutUint32(instruction[:], 0xf8220020)
		m.WriteMemory(0x1000, instruction[:])
		c.pc = 0x1000
		if _, err := c.Step(m); err == nil {
			t.Fatal("accepted invalid atomic access")
		}
		var b [8]byte
		m.ReadMemory(0x2000, b[:], cpu.Read)
		if c.pc != 0x1000 || c.x[0] != 99 || binary.LittleEndian.Uint64(b[:]) != 0 {
			t.Fatal("fault committed atomic effects")
		}
	}
}
