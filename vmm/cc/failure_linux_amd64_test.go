//go:build linux && amd64

package cc

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/tinyrange/trex/vmm"
	"j5.nz/cc/hypervisor"
	"j5.nz/cc/hypervisor/x86state"
)

func TestTripleFaultDiagnostics(t *testing.T) {
	requireKVM(t)
	for _, count := range []int{1, 4} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cpus, err := hypervisor.NewX86WithCPUs(ctx, count)
			if err != nil {
				t.Fatal(err)
			}
			// Close is safe once driver.Close below has joined every worker.
			ram, err := cpus[0].MapRAM(0, 16<<20)
			if err != nil {
				cpus[0].Close()
				t.Fatal(err)
			}
			p, err := newPCBoot(cpus[0], ram, vmm.Disk{Device: testBlock(t, make([]byte, 2048))}, time.Now, false)
			if err != nil {
				cpus[0].Close()
				t.Fatal(err)
			}
			p.cpus = cpus
			p.lastService = "test before fault"
			p.efiTrace = []any{map[string]any{"service": "test boundary", "caller": "0x1234"}}
			s, err := cpus[0].SystemRegisters()
			if err != nil {
				cpus[0].Close()
				t.Fatal(err)
			}
			seg := x86state.Segment{Limit: 0xffffffff, Present: 1, S: 1, Type: 3, Db: 1, G: 1}
			s.Cs, s.Ds, s.Es, s.Ss, s.Fs, s.Gs = seg, seg, seg, seg, seg, seg
			s.Cs.Type = 11
			s.Cr0, s.Cr3, s.Cr4, s.Efer = 0x11, 0, 0, 0
			s.Idt = x86state.DescriptorTable{} // no exception handler, including #DF
			if err := cpus[0].SetSystemRegisters(s); err != nil {
				cpus[0].Close()
				t.Fatal(err)
			}
			if err := cpus[0].SetRegisters(x86state.Registers{Rip: 0x1000, Rsp: 0x8000, Rflags: 2}); err != nil {
				cpus[0].Close()
				t.Fatal(err)
			}
			copy(ram[0x1000:], []byte{0x0f, 0x0b}) // UD2 -> #UD -> #DF -> shutdown exit
			d := newDriver(ctx, p, true)
			defer d.Close(context.Background())
			if err := d.Resume(ctx); err != nil {
				t.Fatal(err)
			}
			result, err := d.Wait(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if result.Clean || result.Reason != "guest_failure" {
				t.Fatalf("unexpected result: %+v", result)
			}
			for _, text := range []string{"x86 triple fault", `last_service="test before fault"`, `recent_efi=[{"caller":"0x1234","service":"test boundary"}]`} {
				if !strings.Contains(result.Detail, text) {
					t.Fatalf("missing %q in %s", text, result.Detail)
				}
			}
			// Intel preserves the fault site; AMD may report reset state. The
			// retained history must survive either outcome, and neither outcome
			// can be interpreted as an INIT delivered by the guest.
			if strings.Contains(result.Detail, "rip=0x1000 ") {
				if !strings.Contains(result.Detail, "instruction_bytes=0f0b") {
					t.Fatal("missing original UD2 bytes", result.Detail)
				}
			} else if !strings.Contains(result.Detail, "rip=0xfff0 ") {
				t.Fatal("unexpected shutdown register state", result.Detail)
			}
			if count > 1 && !strings.HasPrefix(result.Detail, "CPU0:") {
				t.Fatal("missing faulting CPU", result.Detail)
			}
			t.Log(result.Detail)
		})
	}
}
