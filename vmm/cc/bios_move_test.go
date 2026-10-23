package cc

import (
	"bytes"
	"j5.nz/cc/hypervisor/x86state"
	"testing"
)

func TestBIOSExtendedMoveUsesBothDescriptorBaseHighBytes(t *testing.T) {
	p := &pc{ram: make([]byte, 32<<20)}
	src, dst := uint32(0x1000320), uint32(0x1800450)
	const count = 34
	descriptor := func(at int, base uint32) {
		p.ram[at], p.ram[at+1] = 0xff, 0xff
		p.ram[at+2] = byte(base)
		p.ram[at+3] = byte(base >> 8)
		p.ram[at+4] = byte(base >> 16)
		p.ram[at+5] = 0x93
		p.ram[at+7] = byte(base >> 24)
	}
	descriptor(0x7010, src)
	descriptor(0x7018, dst)
	for j := 0; j < count; j++ {
		p.ram[int(src)+j] = byte(j*7 + 1)
	}
	copy(p.ram[dst-1:dst+count+1], bytes.Repeat([]byte{0xa5}, count+2))
	if status := p.moveExtendedMemory(0x7000, count/2, x86state.SystemRegisters{}); status != 0 {
		t.Fatalf("status%x", status)
	}
	if !bytes.Equal(p.ram[src:src+count], p.ram[dst:dst+count]) || p.ram[dst-1] != 0xa5 || p.ram[dst+count] != 0xa5 {
		t.Fatal("truncated descriptor base, length, or buffer overrun")
	}
	descriptor(0x7010, uint32(len(p.ram)-2))
	before := append([]byte(nil), p.ram[dst:dst+count]...)
	if p.moveExtendedMemory(0x7000, count/2, x86state.SystemRegisters{}) == 0 || !bytes.Equal(before, p.ram[dst:dst+count]) {
		t.Fatal("invalid move partly wrote its destination")
	}
}
