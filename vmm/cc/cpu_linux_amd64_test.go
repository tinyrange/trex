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

func TestLongModeCPU(t *testing.T) {
	requireKVM(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cpu, err := hypervisor.NewX86(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer cpu.Close()
	if err = configureCPUArchitecture(cpu, true); err != nil {
		t.Fatal(err)
	}
	ram, err := cpu.MapRAM(0, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	// Identity-map the first 2 MiB through all four paging levels.
	binary.LittleEndian.PutUint64(ram[0x1000:], 0x2003)
	binary.LittleEndian.PutUint64(ram[0x2000:], 0x3003)
	binary.LittleEndian.PutUint64(ram[0x3000:], 0x83)
	s, err := cpu.SystemRegisters()
	if err != nil {
		t.Fatal(err)
	}
	seg := x86state.Segment{Limit: 0xffffffff, Selector: 16, Type: 3, Present: 1, Db: 1, S: 1, G: 1}
	s.Cs, s.Ds, s.Es, s.Fs, s.Gs, s.Ss = seg, seg, seg, seg, seg, seg
	s.Cs.Selector, s.Cs.Type, s.Cs.Db, s.Cs.L = 8, 11, 0, 1
	s.Cr0, s.Cr3, s.Cr4, s.Efer = 0x80000011, 0x1000, 0x20, 0x500
	if err = cpu.SetSystemRegisters(s); err != nil {
		t.Fatal(err)
	}
	// Verify long-mode CPUID and a genuinely 64-bit value using native code.
	copy(ram[0x4000:], []byte{
		0xb8, 1, 0, 0, 0x80, 0x0f, 0xa2, // CPUID 80000001
		0x89, 0x14, 0x25, 0, 0x50, 0, 0, // mov [5000],edx
		0x48, 0xb8, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 1,
		0x48, 0x89, 0x04, 0x25, 8, 0x50, 0, 0,
		0xe6, 0xf2, 0xeb, 0xfe,
	})
	if err = cpu.SetRegisters(x86state.Registers{Rip: 0x4000, Rsp: 0x9000, Rflags: 2}); err != nil {
		t.Fatal(err)
	}
	ex, err := cpu.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ex.Reason != hypervisor.X86ExitIO || ex.Port != 0xf2 {
		t.Fatalf("unexpected exit %+v", ex)
	}
	features := binary.LittleEndian.Uint32(ram[0x5000:])
	if features&(1<<29) == 0 || features&((1<<26)|(1<<27)) != 0 {
		t.Fatalf("long-mode feature policy %#x", features)
	}
	if got := binary.LittleEndian.Uint64(ram[0x5008:]); got != 0x0123456789abcdef {
		t.Fatalf("64-bit store %#x", got)
	}
}
