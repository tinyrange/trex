package cc

import (
	"encoding/binary"
	"j5.nz/cc/hypervisor/x86state"
	"testing"
)

func TestBIOSKeyboardScansRingAndPolling(t *testing.T) {
	p := &pc{ram: make([]byte, 1<<20)}
	p.installKeyboardFirmware()
	// Shift+A, Ctrl+S, then an enhanced left arrow; release bytes must not
	// enqueue duplicate keys or leave modifiers latched.
	for _, scan := range []byte{0x2a, 0x1e, 0x9e, 0xaa, 0x1d, 0x1f, 0x9f, 0x9d, 0xe0, 0x4b, 0xe0, 0xcb} {
		p.biosKeyboardScan(scan)
	}
	if p.ram[0x417] != 0 {
		t.Fatalf("modifiers %#x", p.ram[0x417])
	}
	flags := uint16(0x241)
	r := x86state.Registers{Rax: 0xaabb1100}
	if p.keyboardBIOS(&r, &flags) || uint16(r.Rax) != 0x1e41 || r.Rax>>16 != 0xaabb || flags != 0x201 {
		t.Fatalf("peek %+v flags %#x", r, flags)
	}
	for _, want := range []uint16{0x1e41, 0x1f13, 0x4be0} {
		r.Rax = 0x1000
		if p.keyboardBIOS(&r, &flags) || uint16(r.Rax) != want {
			t.Fatalf("key %#x, want %#x", r.Rax, want)
		}
	}
	r.Rax = 0x1100
	p.keyboardBIOS(&r, &flags)
	if flags&0x40 == 0 {
		t.Fatal("empty peek did not set ZF")
	}
	r.Rax = 0
	if !p.keyboardBIOS(&r, &flags) {
		t.Fatal("empty read must wait")
	}
	// Wrap the ring and prove it never overwrites an unread key.
	for round := 0; round < 3; round++ {
		for i := 0; i < 15; i++ {
			if !p.biosKeyStore(uint16(i + 1)) {
				t.Fatal("early full ring")
			}
		}
		if p.biosKeyStore(99) {
			t.Fatal("overwrote full ring")
		}
		for i := 0; i < 15; i++ {
			r.Rax = 0
			p.keyboardBIOS(&r, &flags)
			if r.Rax != uint64(i+1) {
				t.Fatal("ring order")
			}
		}
	}
}
func TestBIOSKeyboardBlockingReadRestartsWithoutChangingCallerFrame(t *testing.T) {
	cpu := &clockBIOSCPU{r: x86state.Registers{Rip: 0x105b, Rsp: 0x8000, Rax: 0x1000, Rflags: 2}, s: x86state.SystemRegisters{Cs: x86state.Segment{Base: 0xf0000}}}
	p := &pc{cpu: cpu, ram: make([]byte, 1<<20)}
	p.installKeyboardFirmware()
	binary.LittleEndian.PutUint16(p.ram[0x8004:], 0x841)
	if err := p.bios(); err != nil {
		t.Fatal(err)
	}
	if cpu.r.Rip != 0x1059 || cpu.r.Rflags&0x200 == 0 || binary.LittleEndian.Uint16(p.ram[0x8004:]) != 0x841 {
		t.Fatal("wait damaged frame or blocked IRQs")
	}
	p.biosKeyboardScan(0x1e)
	cpu.r.Rip = 0x105b
	if err := p.bios(); err != nil {
		t.Fatal(err)
	}
	if cpu.r.Rax != 0x1e61 {
		t.Fatalf("read %#x", cpu.r.Rax)
	}
}
