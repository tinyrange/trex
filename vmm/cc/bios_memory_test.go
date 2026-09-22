package cc

import (
	"bytes"
	"encoding/binary"
	"testing"

	"j5.nz/cc/hypervisor/x86state"
)

func TestBIOSMemoryMap(t *testing.T) {
	p := &pc{ram: make([]byte, 128<<20)}
	s := x86state.SystemRegisters{Es: x86state.Segment{Base: 0x8000}}
	for _, size := range []uint64{20, 21, 24, 64} {
		token := uint64(0)
		for index, want := range [][3]uint64{{0, 0xa0000, 1}, {0xc0000, 0x40000, 2}, {0x100000, 127 << 20, 1}} {
			copy(p.ram[0x8100:], bytes.Repeat([]byte{0xcc}, 64))
			r := x86state.Registers{Rax: 0xe820, Rbx: token, Rcx: size, Rdx: 0x534d4150, Rdi: 0x100}
			if !p.extendedMemory(&r, s) {
				t.Fatalf("E820 size %d entry %d failed", size, index)
			}
			b := p.ram[0x8100:]
			got := [3]uint64{binary.LittleEndian.Uint64(b), binary.LittleEndian.Uint64(b[8:]), uint64(binary.LittleEndian.Uint32(b[16:]))}
			if got != want || r.Rax != 0x534d4150 || r.Rdi != 0x100 {
				t.Fatalf("E820 entry %d = %v, registers %+v", index, got, r)
			}
			returned := uint64(20)
			if size >= 24 {
				returned = 24
				if binary.LittleEndian.Uint32(b[20:]) != 1 {
					t.Fatal("range not marked enabled")
				}
			}
			if r.Rcx != returned || !bytes.Equal(b[returned:64], bytes.Repeat([]byte{0xcc}, int(64-returned))) {
				t.Fatal("incorrect returned size or buffer overrun")
			}
			if (r.Rbx == 0) != (index == 2) {
				t.Fatalf("bad continuation at entry %d: %d", index, r.Rbx)
			}
			token = r.Rbx
		}
	}
	for _, r := range []x86state.Registers{
		{Rax: 0xe820, Rcx: 19, Rdx: 0x534d4150},
		{Rax: 0xe820, Rcx: 24, Rdx: 0},
		{Rax: 0xe820, Rcx: 24, Rdx: 0x534d4150, Rbx: 3},
	} {
		before := append([]byte(nil), p.ram[0x8000:0x8040]...)
		if p.extendedMemory(&r, s) || !bytes.Equal(before, p.ram[0x8000:0x8040]) {
			t.Fatalf("accepted invalid call or modified its buffer: %+v", r)
		}
	}
	r := x86state.Registers{Rax: 0xe820, Rcx: 24, Rdx: 0x534d4150}
	s.Es.Base = uint64(len(p.ram) - 10)
	if p.extendedMemory(&r, s) {
		t.Fatal("accepted out-of-range descriptor buffer")
	}
}

func TestBIOSMemoryE801(t *testing.T) {
	p := &pc{ram: make([]byte, 128<<20)}
	r := x86state.Registers{Rax: 0xe801}
	if !p.extendedMemory(&r, x86state.SystemRegisters{}) || r.Rax != 15*1024 || r.Rcx != r.Rax || r.Rbx != 112*16 || r.Rdx != r.Rbx {
		t.Fatalf("E801 size registers: %+v", r)
	}
	r = x86state.Registers{Rax: 0x1234e801}
	if !p.extendedMemory(&r, x86state.SystemRegisters{}) || r.Rax != 0x12343c00 {
		t.Fatalf("E801 must use AX and preserve upper EAX: %+v", r)
	}
}
