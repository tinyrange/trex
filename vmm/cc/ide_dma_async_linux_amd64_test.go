//go:build linux && amd64

package cc

import (
	"context"
	"encoding/binary"
	"github.com/tinyrange/trex/vmm"
	"j5.nz/cc/hypervisor"
	"testing"
	"time"
)

func TestIDEAsyncReadAllowsNativeExecution(t *testing.T) {
	requireKVM(t)
	data := make([]byte, 4096)
	// A real-mode guest performs a memory write and reports it through an IO
	// exit while its disk read is held. No timer sleeps stand in for execution.
	copy(data, []byte{0xfa, 0xc7, 0x06, 0x00, 0x80, 0x34, 0x12, 0xb0, 0x42, 0xe6, 0xf2, 0xeb, 0xfe})
	binary.LittleEndian.PutUint16(data[510:], 0xaa55)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cpu, err := hypervisor.NewX86(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer cpu.Close()
	ram, err := cpu.MapRAM(0, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	p, err := newPC(cpu, ram, vmm.Disk{Device: testBlock(t, data)}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	p.pciIDE = newPCIIDE()
	p.pciIDE.config[4] = 5
	p.ide.dmaEnabled = true
	binary.LittleEndian.PutUint32(p.pciIDE.bm[4:], 0x1000)
	held := holdDMA(t, p)
	// Cleanup must join before cpu.Close (testing cleanup runs after defers).
	defer func() { held.unblock(); _ = p.completeIDEDMARead(true) }()
	dmaPRD(p, 0, 0x20000, 512, true)
	dmaCommand(t, p, false, 1)
	dmaStart(t, p, false)
	awaitDMA(t, held.entered)
	for {
		ex, err := p.runDevices(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if ex.Reason == 0 {
			continue
		}
		if ex.Reason == hypervisor.X86ExitIO && ex.Port == 0xf2 {
			if ex.Data[0] != 0x42 || binary.LittleEndian.Uint16(ram[0x8000:]) != 0x1234 {
				t.Fatal("guest did not execute")
			}
			if p.dmaRead == nil || p.ide.pending {
				t.Fatal("disk was not still pending during guest execution")
			}
			break
		}
		if ex.Reason != hypervisor.X86ExitIO {
			t.Fatalf("unexpected exit: %+v", ex)
		}
		if err := p.handleIO(ex); err != nil {
			t.Fatal(err)
		}
	}
	held.unblock()
	if err := p.completeIDEDMARead(true); err != nil {
		t.Fatal(err)
	}
	if !p.ide.pending || p.ide.status() != 0x50 {
		t.Fatal("missing completion after native execution")
	}
}
