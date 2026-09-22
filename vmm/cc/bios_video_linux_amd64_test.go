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

func TestVideoFirmwareRegisterPacket(t *testing.T) {
	requireKVM(t)
	data := make([]byte, 512)
	copy(data, []byte{
		0xb8, 0x12, 0, 0xcd, 0x10, // mode 12
		0xb8, 0, 0x0f, 0xcd, 0x10, 0xa3, 0, 0x80, // query AX
		0x9c, 0x58, 0xa3, 2, 0x80, // returned flags
		0xb8, 0xff, 0xff, 0xcd, 0x10, 0x9c, 0x58, 0xa3, 4, 0x80,
		0xb8, 0, 0x1a, 0xcd, 0x10, 0xa3, 6, 0x80, 0x89, 0x1e, 8, 0x80,
		0xb0, 0x42, 0xe6, 0xf2, 0xeb, 0xfe,
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
			t.Fatalf("unexpected exit %+v", ex)
		}
		if ex.Port == 0xf2 {
			break
		}
		if err = p.handleIO(ex); err != nil {
			t.Fatal(err)
		}
	}
	word := func(offset int) uint16 { return binary.LittleEndian.Uint16(ram[0x8000+offset:]) }
	if word(0) != 0x5012 || word(2)&1 != 0 || word(4)&1 != 1 || word(6) != 0x1a || word(8) != 8 {
		t.Fatalf("video results %x", ram[0x8000:0x800a])
	}
	regs, err := cpu.Registers()
	if err != nil {
		t.Fatal(err)
	}
	if regs.Rsp != 0x7c00 {
		t.Fatalf("firmware stack leaked: %#x", regs.Rsp)
	}
}
