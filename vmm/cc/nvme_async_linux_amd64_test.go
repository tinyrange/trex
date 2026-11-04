//go:build linux && amd64

package cc

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/tinyrange/trex/vmm"
	"j5.nz/cc/hypervisor"
)

// A real vCPU must execute while NVMe ReadAt is blocked, then consume a
// coordinator-delivered completion. This catches accidentally leaving backing
// I/O (or a controller lock wait) in the MMIO/device loop.
func TestNVMeAsyncReadAllowsNativeExecution(t *testing.T) {
	requireKVM(t)
	data := make([]byte, 4096)
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
	held := &heldDMADevice{Device: p.disk.Device, entered: make(chan struct{}), release: make(chan struct{})}
	p.disk.Device = held
	p.nvme = newPCINVMe(p)
	c := p.nvme.controller
	c.EnableAsyncIO(func() { _ = cpu.Cancel() })
	defer func() { held.unblock(); c.CloseIO() }()
	wr := func(off, value uint64) {
		t.Helper()
		if err := c.WriteMMIO(off, 8, value); err != nil {
			t.Fatal(err)
		}
	}
	command := func(addr int, op byte, prp uint64, dw10, dw11 uint32) {
		b := ram[addr : addr+64]
		clear(b)
		b[0] = op
		binary.LittleEndian.PutUint32(b[4:], 1)
		binary.LittleEndian.PutUint64(b[24:], prp)
		binary.LittleEndian.PutUint32(b[40:], dw10)
		binary.LittleEndian.PutUint32(b[44:], dw11)
	}
	wr(0x24, 7|7<<16)
	wr(0x28, 0x1000)
	wr(0x30, 0x2000)
	wr(0x14, 1)
	command(0x1000, 5, 0x4000, 1|7<<16, 3)
	wr(0x1000, 1)
	command(0x1040, 1, 0x3000, 1|7<<16, 1|1<<16)
	wr(0x1000, 2)
	wr(0x1004, 2)
	command(0x3000, 2, 0x20000, 0, 0)
	wr(0x1008, 1)
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
			if c.IOReady() == nil || p.nvme.pending || ram[0x20000] != 0 {
				t.Fatal("NVMe read completed before backing I/O")
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
	awaitDMA(t, c.IOReady())
	// Both single and SMP loops use owner pollDevices for delivery.
	if _, _, _, err := p.pollDevices(); err != nil {
		t.Fatal(err)
	}
	if ram[0x20000] != data[0] || !p.nvme.pending || binary.LittleEndian.Uint16(ram[0x400e:]) != 1 {
		t.Fatal("missing NVMe DMA or successful completion after native execution")
	}
}
