//go:build linux && amd64

package cc

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/tinyrange/trex/emulator/uefi"
	"github.com/tinyrange/trex/vmm"
	"j5.nz/cc/hypervisor"
	"j5.nz/cc/hypervisor/x86state"
)

func TestEFIExceptionDiagnostics(t *testing.T) {
	requireKVM(t)
	cases := []struct {
		name   string
		code   []byte
		vector int
		offset uint64
	}{
		{"UD", []byte{0x0f, 0x0b}, 6, 0},
		{"GP", []byte{0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0x80, 0x0f, 0x22, 0xd8}, 13, 10},
		{"PF", []byte{0x48, 0xa1, 0, 0, 0, 0, 1, 0, 0, 0}, 14, 0},
	}
	for _, count := range []int{1, 4} {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("%s/%d", tc.name, count), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				cpus, err := hypervisor.NewX86WithCPUs(ctx, count)
				if err != nil {
					t.Fatal(err)
				}
				defer cpus[0].Close()
				ram, err := cpus[0].MapRAM(0, 16<<20)
				if err != nil {
					t.Fatal(err)
				}
				p, err := newPCBoot(cpus[0], ram, vmm.Disk{Device: testBlock(t, make([]byte, 2048))}, time.Now, false)
				if err != nil {
					t.Fatal(err)
				}
				p.cpus, p.efi = cpus, &uefi.Firmware{}
				p.lastService = "diagnostic fixture"
				installEFIBootstrapTables(ram, uint64(len(ram)))
				binary.LittleEndian.PutUint64(ram[0x9008:], 0x00af9b000000ffff)
				binary.LittleEndian.PutUint64(ram[0x9010:], 0x00cf93000000ffff)
				s, err := cpus[0].SystemRegisters()
				if err != nil {
					t.Fatal(err)
				}
				seg := x86state.Segment{Limit: 0xffffffff, Selector: 16, Present: 1, S: 1, Type: 3, Db: 1, G: 1}
				s.Cs, s.Ds, s.Es, s.Ss, s.Fs, s.Gs = seg, seg, seg, seg, seg, seg
				s.Cs.Selector, s.Cs.Type, s.Cs.Db, s.Cs.L = 8, 11, 0, 1
				s.Cr0, s.Cr3, s.Cr4, s.Efer = 0x80000011, 0x1000, 0x620, 0x500
				s.Gdt = x86state.DescriptorTable{Base: 0x9000, Limit: 23}
				s.Idt = installEFIExceptionGates(ram)
				if err := cpus[0].SetSystemRegisters(s); err != nil {
					t.Fatal(err)
				}
				copy(ram[0x10000:], tc.code)
				if err := cpus[0].SetRegisters(x86state.Registers{Rip: 0x10000, Rsp: 0x20000, Rax: 0x12345678, Rflags: 2}); err != nil {
					t.Fatal(err)
				}
				d := newDriver(ctx, p, true)
				defer d.Close(context.Background())
				if err := d.Resume(ctx); err != nil {
					t.Fatal(err)
				}
				result, err := d.Wait(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if result.Clean {
					t.Fatalf("unexpected clean stop: %+v", result)
				}
				for _, want := range []string{fmt.Sprintf("EFI exception vector=%d", tc.vector), fmt.Sprintf("rip=%#x", 0x10000+tc.offset), "rsp=0x20000", `last_service="diagnostic fixture"`} {
					if !strings.Contains(result.Detail, want) {
						t.Fatalf("missing %s: %s", want, result.Detail)
					}
				}
				if tc.name == "PF" && !strings.Contains(result.Detail, "cr2=0x100000000") {
					t.Fatal(result.Detail)
				}
				if tc.name == "UD" && !strings.Contains(result.Detail, "rax=0x12345678") {
					t.Fatal(result.Detail)
				}
			})
		}
	}
}
