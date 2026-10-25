package cc

import (
	"encoding/binary"
	"testing"
	"time"

	"j5.nz/cc/hypervisor/x86state"
)

func TestPCIBIOSConfigurationAndEnumeration(t *testing.T) {
	p := &pc{pciIDE: newPCIIDE(), pciAddress: 0x80001810}
	call := func(r x86state.Registers, want byte) x86state.Registers {
		t.Helper()
		status, err := p.pciBIOS(&r)
		if err != nil || status != want {
			t.Fatalf("PCI BIOS status=%x err=%v, want %x", status, err, want)
		}
		if p.pciAddress != 0x80001810 {
			t.Fatal("firmware changed CF8 latch")
		}
		return r
	}
	r := call(x86state.Registers{Rax: 0xb102, Rcx: 0xcc01, Rdx: 0x1234}, 0)
	if r.Rbx != 8 {
		t.Fatalf("found BDF=%x", r.Rbx)
	}
	call(x86state.Registers{Rax: 0xb102, Rcx: 0xcc01, Rdx: 0x1234, Rsi: 1}, 0x86)
	call(x86state.Registers{Rax: 0xb102, Rdx: 0xffff}, 0x83)
	r = call(x86state.Registers{Rax: 0xb103, Rcx: 0x010180}, 0)
	if r.Rbx != 8 {
		t.Fatalf("class BDF=%x", r.Rbx)
	}
	for _, tc := range []struct{ function, offset, want uint64 }{
		{8, 1, 0xabcdef12}, {9, 2, 0xabcdcc01}, {10, 0, 0xcc011234},
	} {
		r = call(x86state.Registers{Rax: 0xb100 | tc.function, Rbx: 8, Rdi: tc.offset, Rcx: 0xabcdef00}, 0)
		if r.Rcx != tc.want {
			t.Fatalf("function %x read=%x want=%x", tc.function, r.Rcx, tc.want)
		}
	}
	// The device masks BAR alignment, even through the firmware write path.
	call(x86state.Registers{Rax: 0xb10d, Rbx: 8, Rdi: 0x20, Rcx: 0x0000dfff}, 0)
	r = call(x86state.Registers{Rax: 0xb10a, Rbx: 8, Rdi: 0x20}, 0)
	if r.Rcx != 0xdff1 {
		t.Fatalf("BAR readback=%x", r.Rcx)
	}
	r = call(x86state.Registers{Rax: 0xb10a, Rbx: 0x100}, 0)
	if r.Rcx != 0xffffffff {
		t.Fatalf("absent bus read=%x", r.Rcx)
	}
	for _, offset := range []uint64{1, 255, 256} {
		call(x86state.Registers{Rax: 0xb10a, Rbx: 8, Rdi: offset}, 0x87)
	}
	call(x86state.Registers{Rax: 0xb10e}, 0x81)
}

func TestPCIBIOSInterruptAndMappedFarCall(t *testing.T) {
	for _, protected := range []bool{false, true} {
		c := &biosLegacyCPU{}
		p := &pc{cpu: c, ram: make([]byte, 2<<20), pciIDE: newPCIIDE(), now: func() time.Time { return time.Unix(0, 0) }}
		p.installPCIFirmware()
		var sum byte
		for _, b := range p.ram[bios32Directory : bios32Directory+16] {
			sum += b
		}
		if sum != 0 || binary.LittleEndian.Uint32(p.ram[bios32Directory+4:]) != bios32Entry {
			t.Fatal("invalid BIOS32 directory")
		}
		c.regs = x86state.Registers{Rax: 0xb101, Rsp: 0x8000, Rflags: 0x247}
		if protected {
			// Alias only the PCI entry page; the BIOS must translate the guest PC.
			c.system.Cr0, c.system.Cr3 = 0x80000011, 0x1000
			binary.LittleEndian.PutUint32(p.ram[0x1000+768*4:], 0x2003)
			binary.LittleEndian.PutUint32(p.ram[0x2000:], 0xf6003)
			c.regs.Rip = 0xc0000202
		} else {
			c.system.Cs.Base = 0xf0000
			c.regs.Rip = 0x106a
			binary.LittleEndian.PutUint16(p.ram[0x8004:], 0x247)
		}
		for _, ax := range []uint64{0xb101, 0xb1ff} {
			c.regs.Rax = ax
			if err := p.bios(); err != nil {
				t.Fatal(err)
			}
			flags := c.regs.Rflags
			if !protected {
				flags = uint64(binary.LittleEndian.Uint16(p.ram[0x8004:]))
			}
			if ax == 0xb101 {
				if c.regs.Rax != 1 || c.regs.Rbx != 0x210 || c.regs.Rdx != 0x20494350 || c.regs.Rdi != pciBIOSEntry || flags != 0x246 {
					t.Fatalf("bad installation return: %+v flags=%x", c.regs, flags)
				}
			} else if c.regs.Rax != 0x81ff || flags != 0x247 {
				t.Fatalf("bad unsupported return: %+v flags=%x", c.regs, flags)
			}
		}
	}
}
