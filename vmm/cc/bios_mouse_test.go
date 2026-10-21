package cc

import (
	"encoding/binary"
	"j5.nz/cc/hypervisor/x86state"
	"testing"
)

func TestBIOSMouseServicesValidateAndPreserveUnrelatedRegisterBits(t *testing.T) {
	p := &pc{ram: make([]byte, 1<<20), keyboard: newKeyboard(func(uint32, bool) error { return nil })}
	p.installMouseFirmware()
	r := x86state.Registers{Rax: 0xc200, Rbx: 0x100}
	if p.mouseBIOS(&r, x86state.SystemRegisters{}) != 5 || p.keyboard.mouseEnabled {
		t.Fatal("enabled without callback")
	}
	r.Rax = 0xc205
	r.Rbx = 0x400
	if p.mouseBIOS(&r, x86state.SystemRegisters{}) != 3 {
		t.Fatal("accepted unsupported packet size")
	}
	r.Rbx = 0x300
	if p.mouseBIOS(&r, x86state.SystemRegisters{}) != 0 || r.Rbx != 0xaa || p.keyboard.mouseRate != 100 {
		t.Fatal("initialize")
	}
	r.Rax = 0xc207
	r.Rbx = 0x12345678
	if p.mouseBIOS(&r, x86state.SystemRegisters{Es: x86state.Segment{Selector: 0x4321}}) != 0 || binary.LittleEndian.Uint32(p.ram[biosMouseData+8:]) != 0x43215678 {
		t.Fatal("far callback pointer")
	}
	r.Rax = 0xc202
	r.Rbx = 0x600
	if p.mouseBIOS(&r, x86state.SystemRegisters{}) != 0 || p.keyboard.mouseRate != 200 {
		t.Fatal("sample rate")
	}
	r.Rbx = 0x700
	if p.mouseBIOS(&r, x86state.SystemRegisters{}) != 2 || p.keyboard.mouseRate != 200 {
		t.Fatal("invalid rate changed device")
	}
	r.Rax = 0xc203
	r.Rbx = 0x300
	p.mouseBIOS(&r, x86state.SystemRegisters{})
	r.Rax = 0xc200
	r.Rbx = 0x100
	p.mouseBIOS(&r, x86state.SystemRegisters{})
	r.Rax = 0xc206
	r.Rbx = 0x12340000
	r.Rcx = 0xabcde000
	r.Rdx = 0xaabbcc00
	if p.mouseBIOS(&r, x86state.SystemRegisters{}) != 0 || r.Rbx != 0x12340020 || r.Rcx != 0xabcde003 || r.Rdx != 0xaabbccc8 {
		t.Fatalf("status %+v", r)
	}
	p.biosMouseByte(0x18)
	p.biosMouseByte(0xff)
	if p.ram[biosMouseData+12] != 0 {
		t.Fatal("partial packet dispatched")
	}
	p.biosMouseByte(2)
	if p.ram[biosMouseData+12] != 1 || binary.LittleEndian.Uint16(p.ram[biosMouseData+2:]) != 255 {
		t.Fatal("packet bytes lost")
	}
	r.Rax = 0xc207
	r.Rbx = 0
	p.mouseBIOS(&r, x86state.SystemRegisters{})
	if p.keyboard.mouseEnabled {
		t.Fatal("unlink did not disable mouse")
	}
}
