//go:build linux && amd64

package cc

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"j5.nz/cc/hypervisor"
	"j5.nz/cc/hypervisor/x86state"
)

func TestRTCAllowsSplitLockProgress(t *testing.T) {
	requireKVM(t)
	cpu, err := hypervisor.NewX86(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer cpu.Close()
	ram, err := cpu.MapRAM(0, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	s, err := cpu.SystemRegisters()
	if err != nil {
		t.Fatal(err)
	}
	seg := x86state.Segment{Limit: 0xffffffff, Selector: 16, Type: 3, Present: 1, Db: 1, S: 1, G: 1}
	s.Cs, s.Ds, s.Es, s.Fs, s.Gs, s.Ss = seg, seg, seg, seg, seg, seg
	s.Cs.Selector, s.Cs.Type, s.Cr0 = 8, 11, 0x11
	if err = cpu.SetSystemRegisters(s); err != nil {
		t.Fatal(err)
	}
	// CMPXCHG8B crosses a cache-line boundary, as in NT10 x86's
	// stack-local privilege checks. Complete one operation then exit.
	copy(ram[0x4000:], []byte{0x31, 0xc0, 0x31, 0xd2, 0xbb, 0x1f, 0, 0, 0, 0x31, 0xc9, 0xbf, 0x3c, 0x50, 0, 0, 0xf0, 0x0f, 0xc7, 0x0f, 0xe6, 0xf2, 0xeb, 0xfe})
	if err = cpu.SetRegisters(x86state.Registers{Rip: 0x4000, Rsp: 0x9000, Rflags: 2}); err != nil {
		t.Fatal(err)
	}
	p := &pc{cpu: cpu, now: time.Now}
	p.cmos[0xa], p.cmos[0xb] = 6, 0x40 // 1024 Hz periodic interrupts.
	start := time.Now()
	for time.Since(start) < time.Second {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		ex, err := p.run(ctx)
		cancel()
		if errors.Is(err, context.DeadlineExceeded) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if ex.Reason == 0 {
			continue
		}
		if ex.Reason != hypervisor.X86ExitIO || ex.Port != 0xf2 {
			t.Fatalf("exit %+v", ex)
		}
		if got := binary.LittleEndian.Uint64(ram[0x503c:]); got != 0x1f {
			t.Fatalf("atomic result %#x", got)
		}
		return
	}
	r, _ := cpu.Registers()
	t.Errorf("no forward progress after %v at %#x", time.Since(start), r.Rip)
}
