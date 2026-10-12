//go:build linux && amd64

package cc

import (
	"context"
	"encoding/binary"
	"github.com/tinyrange/trex/vmm"
	"go.starlark.net/starlark"
	"j5.nz/cc/hypervisor"
	"testing"
	"time"
)

func TestNativeStepKeepsBIOSAndVideoPacketSemantics(t *testing.T) {
	requireKVM(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cpu, err := hypervisor.NewX86(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ram, err := cpu.MapRAM(0, 16<<20)
	if err != nil {
		cpu.Close()
		t.Fatal(err)
	}
	data := make([]byte, 512)
	copy(data, []byte{0xcd, 0x12, 0xa3, 0, 0x80, 0xb8, 0, 0x0f, 0xcd, 0x10, 0xa3, 2, 0x80, 0xeb, 0xfe})
	binary.LittleEndian.PutUint16(data[510:], 0xaa55)
	p, err := newPC(cpu, ram, vmm.Disk{Device: testBlock(t, data)}, time.Now)
	if err != nil {
		cpu.Close()
		t.Fatal(err)
	}
	d := newDriver(ctx, p, true)
	defer d.Close(context.Background())
	inspect := inspection{driver: d, ctx: ctx}
	// One multi-instruction request must stay in stepping mode across the
	// BIOS register commit, not merely when every step reconfigures debug.
	if _, err = inspect.step(nil, nil, starlark.Tuple{starlark.MakeInt(60)}, nil); err != nil {
		t.Fatal(err)
	}
	stopped := false
	for count := 0; count < 180; count++ {
		_, err = inspect.step(nil, nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		r, err := cpu.Registers()
		if err != nil {
			t.Fatal(err)
		}
		s, err := cpu.SystemRegisters()
		if err != nil {
			t.Fatal(err)
		}
		if s.Cs.Base+r.Rip == 0x7c0d {
			stopped = true
			break
		}
	}
	if !stopped || binary.LittleEndian.Uint16(ram[0x8000:]) != 640 || binary.LittleEndian.Uint16(ram[0x8002:]) != 0x5003 {
		t.Fatalf("step corrupts firmware results: stopped=%t bytes=%x", stopped, ram[0x8000:0x8004])
	}
	r, err := cpu.Registers()
	if err != nil {
		t.Fatal(err)
	}
	if r.Rsp != 0x7c00 {
		t.Fatalf("step leaked firmware stack: %x", r.Rsp)
	}
	// Bounds fail before execution and stepping cannot silently resume a VM.
	if _, err = inspect.step(nil, nil, starlark.Tuple{starlark.MakeInt(4097)}, nil); err == nil {
		t.Fatal("accepted unbounded step")
	}
	state, _ := d.Status(ctx)
	if state.Name != "paused" {
		t.Fatal("step changed lifecycle state", state)
	}
}
