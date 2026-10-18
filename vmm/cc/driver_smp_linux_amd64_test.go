//go:build linux && amd64

package cc

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/tinyrange/trex/vmm"
	"j5.nz/cc/hypervisor"
	"j5.nz/cc/hypervisor/x86state"
)

func TestSMPPauseResumeAndClose(t *testing.T) {
	requireKVM(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cpus, err := hypervisor.NewX86WithCPUs(ctx, 4)
	if err != nil {
		t.Fatal(err)
	}
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
	for id, cpu := range cpus {
		if err := configureCPUTopology(cpu, true, id, 4); err != nil {
			cpus[0].Close()
			t.Fatal(err)
		}
	}
	// Each AP increments its own shared-memory counter after INIT/SIPI.
	copy(ram[0x8000:], []byte{0x66, 0xb8, 1, 0, 0, 0, 0x0f, 0xa2, 0x66, 0xc1, 0xeb, 24, 0x66, 0x67, 0xff, 0x04, 0x9d, 0, 0x90, 0, 0, 0xeb, 0xf5})
	var code []byte
	store := func(address, value uint32) {
		code = append(code, 0xc7, 5)
		code = binary.LittleEndian.AppendUint32(code, address)
		code = binary.LittleEndian.AppendUint32(code, value)
	}
	store(0xfee000f0, 0x1ff)
	store(0xfee00300, 0xc4500)
	store(0xfee00300, 0xc4608)
	code = append(code, 0xb0, 2, 0xe6, 0x92, 0xff, 5, 0, 0x90, 0, 0, 0xeb, 0xf4)
	copy(ram[0x1000:], code)
	s, err := cpus[0].SystemRegisters()
	if err != nil {
		cpus[0].Close()
		t.Fatal(err)
	}
	seg := x86state.Segment{Limit: 0xffffffff, Present: 1, S: 1, Type: 3, Db: 1, G: 1}
	s.Cs, s.Ds, s.Es, s.Ss, s.Fs, s.Gs = seg, seg, seg, seg, seg, seg
	s.Cs.Type = 11
	s.Cr0, s.Cr3, s.Cr4, s.Efer = 0x11, 0, 0, 0
	if err := cpus[0].SetSystemRegisters(s); err != nil {
		cpus[0].Close()
		t.Fatal(err)
	}
	if err := cpus[0].SetRegisters(x86state.Registers{Rip: 0x1000, Rflags: 2}); err != nil {
		cpus[0].Close()
		t.Fatal(err)
	}
	d := newDriver(ctx, p, true)
	defer d.Close(context.Background())
	read := func() [4]uint32 {
		var out [4]uint32
		for id := range out {
			out[id] = binary.LittleEndian.Uint32(ram[0x9000+id*4:])
		}
		return out
	}
	var prior [4]uint32
	for cycle := 0; cycle < 3; cycle++ {
		if err := d.Resume(ctx); err != nil {
			t.Fatal(err)
		}
		time.Sleep(30 * time.Millisecond)
		if err := d.Pause(ctx); err != nil {
			t.Fatal(err)
		}
		now := read()
		for id := range now {
			if now[id] <= prior[id] {
				t.Fatalf("CPU%d did not progress: %v -> %v", id, prior, now)
			}
		}
		time.Sleep(10 * time.Millisecond)
		if got := read(); got != now {
			t.Fatalf("CPU still running after Pause: %v -> %v", now, got)
		}
		prior = now
	}
	// Close must cancel and join actively executing CPUs before releasing RAM.
	if err := d.Resume(ctx); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(ctx); err != nil {
		t.Fatal(err)
	}
	result, err := d.Wait(ctx)
	if err != nil || result.Reason != "closed" {
		t.Fatalf("close result: %+v %v", result, err)
	}
}
