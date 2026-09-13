//go:build linux && amd64

package cc

import (
	"context"
	"encoding/binary"
	"os"
	"testing"
	"time"

	"github.com/tinyrange/trex/vmm"
	"go.starlark.net/starlark"
	"j5.nz/cc/hypervisor"
)

func requireKVM(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/dev/kvm"); err != nil {
		t.Skip("KVM unavailable")
	}
}

func TestBIOSBootSectorDiskAndTimerHook(t *testing.T) {
	requireKVM(t)
	data := make([]byte, 4*512)
	// Read sector two through INT 13h, then wait for the INT 1Ch callback
	// to set a word. The boot sector reports a distinct success/failure port.
	code := []byte{
		0xb8, 1, 2, 0xbb, 0, 0x80, 0xb9, 2, 0, 0xba, 0x80, 0, 0xcd, 0x13,
		0x72, 0, 0x81, 0x3e, 0, 0x80, 0x34, 0x12, 0x75, 0,
		0xc7, 6, 0x70, 0, 0, 0x7d, 0xc7, 6, 0x72, 0, 0, 0,
		0x83, 0x3e, 0, 0x81, 0, 0x74, 0xf9,
		0xb0, 0x42, 0xe6, 0xf2, 0xeb, 0xfe,
		0xb0, 0xff, 0xe6, 0xf2, 0xeb, 0xfe,
	}
	code[15] = byte(49 - 16)
	code[23] = byte(49 - 24)
	copy(data, code)
	copy(data[0x100:], []byte{0x2e, 0xc7, 6, 0, 0x81, 1, 0, 0xcf})
	binary.LittleEndian.PutUint16(data[510:], 0xaa55)
	binary.LittleEndian.PutUint16(data[512:], 0x1234)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
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
	p, err := newPC(cpu, ram, vmm.Disk{Device: testBlock(t, data), CHS: &vmm.CHSGeometry{Cylinders: 1, Heads: 1, Sectors: 4}}, time.Now)
	if err != nil {
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
		if ex.Reason != hypervisor.X86ExitIO {
			t.Fatalf("exit %+v", ex)
		}
		if ex.Port == 0xf2 {
			if len(ex.Data) != 1 || ex.Data[0] != 0x42 {
				t.Fatalf("guest BIOS regression: %x", ex.Data)
			}
			return
		}
		if err := p.handleIO(ex); err != nil {
			r, _ := cpu.Registers()
			s, _ := cpu.SystemRegisters()
			t.Fatalf("%v last=%s regs=%+v cs=%+v ivt13=%x ticks=%d", err, p.lastService, r, s.Cs, ram[0x4c:0x50], binary.LittleEndian.Uint32(ram[0x46c:]))
		}
	}
}

func TestBackendLifecycle(t *testing.T) {
	requireKVM(t)
	data := make([]byte, 4*512)
	copy(data, []byte{0xeb, 0xfe})
	binary.LittleEndian.PutUint16(data[510:], 0xaa55)
	m := vmm.Machine{Architecture: "i386", Memory: 16 << 20, CPUs: 1, Disks: []vmm.Disk{{Device: testBlock(t, data), Bus: "ide", Unit: 0, Snapshot: true}}, StartPaused: true}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	b := &Backend{}
	raw, err := b.Start(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	d := raw.(*driver)
	defer d.Close(context.Background())
	state, _ := d.Status(ctx)
	if state.Running || state.Name != "paused" {
		t.Fatal(state)
	}
	for i := 0; i < 5; i++ {
		if err = d.Resume(ctx); err != nil {
			t.Fatal(err)
		}
		if err = d.Pause(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = d.Screenshot(ctx, "png"); err != nil {
		t.Fatal(err)
	}
	extension, err := d.Extension(ctx, "cc.v1")
	if err != nil {
		t.Fatal(err)
	}
	stateFn, err := extension.(starlark.HasAttrs).Attr("state")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = starlark.Call(&starlark.Thread{Name: "cc-state-test"}, stateFn, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err = d.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	result, err := d.Wait(ctx)
	if err != nil || !result.Clean || result.Reason != "stopped" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if err = d.Resume(ctx); err == nil {
		t.Fatal("resumed terminal VM")
	}
	if err = d.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err = d.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestBIOSMouseDetection(t *testing.T) {
	requireKVM(t)
	data := make([]byte, 4*512)
	// Exercise the same real-mode reset and ID interfaces used by NTDETECT.
	code := []byte{0xb8, 1, 0xc2, 0xcd, 0x15, 0x72, 0, 0x81, 0xfb, 0xaa, 0, 0x75, 0,
		0xb8, 4, 0xc2, 0xbb, 0xff, 0xff, 0xcd, 0x15, 0x72, 0, 0x80, 0xff, 0, 0x75, 0,
		0xb0, 0x42, 0xe6, 0xf2, 0xeb, 0xfe, 0xb0, 0xff, 0xe6, 0xf2, 0xeb, 0xfe}
	for _, offset := range []int{6, 12, 22, 27} {
		code[offset] = byte(34 - offset - 1)
	}
	copy(data, code)
	binary.LittleEndian.PutUint16(data[510:], 0xaa55)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
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
	p, err := newPC(cpu, ram, vmm.Disk{Device: testBlock(t, data), CHS: &vmm.CHSGeometry{Cylinders: 1, Heads: 1, Sectors: 4}}, time.Now)
	if err != nil {
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
		if ex.Reason != hypervisor.X86ExitIO {
			t.Fatalf("exit %+v", ex)
		}
		if ex.Port == 0xf2 {
			if len(ex.Data) != 1 || ex.Data[0] != 0x42 {
				t.Fatalf("mouse BIOS failed: %x", ex.Data)
			}
			return
		}
		if err := p.handleIO(ex); err != nil {
			r, _ := cpu.Registers()
			s, _ := cpu.SystemRegisters()
			t.Fatalf("%v last=%s regs=%+v cs=%+v", err, p.lastService, r, s.Cs)
		}
	}
}
