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

func TestUnownedSoftwareProbeAndNotificationPreserveGuestState(t *testing.T) {
	requireKVM(t)
	data := make([]byte, 512)
	copy(data, []byte{
		0xb8, 0xa0, 0x43, 0xf9, 0xcd, 0x68, 0xa3, 0, 0x80, 0x9c, 0x58, 0xa3, 2, 0x80,
		0xb8, 0x2c, 0x4f, 0xf8, 0xcd, 0x68, 0xa3, 4, 0x80, 0x9c, 0x58, 0xa3, 6, 0x80,
		0xb8, 0, 0x81, 0xf9, 0xcd, 0x4f, 0xa3, 8, 0x80, 0x9c, 0x58, 0xa3, 10, 0x80,
		0xb0, 1, 0xe6, 0xf2, 0xeb, 0xfe,
	})
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
	p, err := newPC(cpu, ram, vmm.Disk{Device: testBlock(t, data)}, time.Now)
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
			t.Fatal(ex)
		}
		if ex.Port == 0xf2 {
			break
		}
		if err = p.handleIO(ex); err != nil {
			t.Fatal(err)
		}
	}
	if ram[0xf1000+6*4] != 0xe6 {
		t.Fatal("exception vector was made inert")
	}
	word := func(offset int) uint16 { return binary.LittleEndian.Uint16(ram[0x8000+offset:]) }
	if word(0) != 0x43a0 || word(2)&1 != 1 || word(4) != 0x4f2c || word(6)&1 != 0 || word(8) != 0x8100 || word(10)&1 != 1 {
		t.Fatalf("absent hook claims provider or changes flags: %x", ram[0x8000:0x800c])
	}
	r, err := cpu.Registers()
	if err != nil {
		t.Fatal(err)
	}
	if r.Rsp != 0x7c00 {
		t.Fatal("software hook leaked stack", r.Rsp)
	}
}
