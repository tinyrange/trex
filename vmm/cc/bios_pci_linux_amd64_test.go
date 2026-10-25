//go:build linux && amd64

package cc

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"j5.nz/cc/hypervisor"
	"j5.nz/cc/hypervisor/x86state"
)

func TestBIOS32DirectoryNativeFarReturn(t *testing.T) {
	requireKVM(t)
	for _, tc := range []struct {
		name                      string
		service, function, status uint64
	}{
		{"PCI", 0x49435024, 0, 0}, {"unknown", 0x12345678, 0, 0x80}, {"function", 0x49435024, 1, 0x81},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			cpu, err := hypervisor.NewX86(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer cpu.Close()
			ram, err := cpu.MapRAM(0, 2<<20)
			if err != nil {
				t.Fatal(err)
			}
			p := &pc{cpu: cpu, ram: ram, now: time.Now}
			p.installPCIFirmware()
			// Far return reloads CS from a real GDT, including its 32-bit attribute.
			binary.LittleEndian.PutUint64(ram[0x7008:], 0x00cf9b000000ffff)
			binary.LittleEndian.PutUint64(ram[0x7010:], 0x00cf93000000ffff)
			s, err := cpu.SystemRegisters()
			if err != nil {
				t.Fatal(err)
			}
			seg := x86state.Segment{Limit: 0xffffffff, Selector: 16, Type: 3, Present: 1, Db: 1, S: 1, G: 1}
			s.Cs, s.Ds, s.Es, s.Fs, s.Gs, s.Ss = seg, seg, seg, seg, seg, seg
			s.Cs.Selector, s.Cs.Type, s.Cr0 = 8, 11, 0x11
			s.Gdt.Base, s.Gdt.Limit = 0x7000, 23
			if err := cpu.SetSystemRegisters(s); err != nil {
				t.Fatal(err)
			}
			copy(ram[0x8000:], []byte{0xe6, 0xf2, 0xeb, 0xfe})
			binary.LittleEndian.PutUint32(ram[0x9000:], 0x8000)
			binary.LittleEndian.PutUint32(ram[0x9004:], 8)
			if err := cpu.SetRegisters(x86state.Registers{Rip: bios32Entry, Rsp: 0x9000, Rax: tc.service, Rbx: tc.function, Rsi: 0x12345678, Rflags: 2}); err != nil {
				t.Fatal(err)
			}
			for {
				ex, err := p.run(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if ex.Reason == 0 {
					continue
				}
				if ex.Reason != hypervisor.X86ExitIO || ex.Port != 0xf2 {
					t.Fatalf("unexpected exit %+v", ex)
				}
				r, err := cpu.Registers()
				if err != nil {
					t.Fatal(err)
				}
				if r.Rax&255 != tc.status || r.Rsp != 0x9008 || r.Rsi != 0x12345678 {
					t.Fatalf("bad far return %+v", r)
				}
				if tc.status == 0 && (r.Rbx+r.Rdx != pciBIOSEntry || r.Rcx != 0x10000) {
					t.Fatalf("bad service extent %+v", r)
				}
				break
			}
		})
	}
}
