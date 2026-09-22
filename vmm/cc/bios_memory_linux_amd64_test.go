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

func TestBIOSMemoryRealMode(t *testing.T) {
	requireKVM(t)
	data := make([]byte, 512)
	// Call E801 and request the high-RAM E820 entry through the actual INT
	// dispatch/IRET path. Save returned sizes, signature and carry flags.
	copy(data, []byte{
		0x66, 0xb8, 0x01, 0xe8, 0, 0, 0xcd, 0x15,
		0xa3, 0, 0x80, 0x89, 0x1e, 2, 0x80, 0x9c, 0x58, 0xa3, 4, 0x80,
		0x66, 0xb8, 0x20, 0xe8, 0, 0,
		0x66, 0xbb, 2, 0, 0, 0,
		0x66, 0xb9, 24, 0, 0, 0,
		0x66, 0xba, 0x50, 0x41, 0x4d, 0x53,
		0xbf, 0, 0x81, 0xcd, 0x15,
		0x66, 0xa3, 8, 0x80, 0x66, 0x89, 0x1e, 12, 0x80,
		0x66, 0x89, 0x0e, 16, 0x80, 0x9c, 0x58, 0xa3, 20, 0x80,
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
	ram, err := cpu.MapRAM(0, 128<<20)
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
			t.Fatalf("unexpected exit: %+v", ex)
		}
		if ex.Port == 0xf2 {
			break
		}
		if err := p.handleIO(ex); err != nil {
			t.Fatal(err)
		}
	}
	u16 := func(p int) uint16 { return binary.LittleEndian.Uint16(ram[p:]) }
	u32 := func(p int) uint32 { return binary.LittleEndian.Uint32(ram[p:]) }
	u64 := func(p int) uint64 { return binary.LittleEndian.Uint64(ram[p:]) }
	if u16(0x8000) != 15*1024 || u16(0x8002) != 112*16 || u16(0x8004)&1 != 0 {
		t.Fatalf("E801 registers/flags %x", ram[0x8000:0x8006])
	}
	if u32(0x8008) != 0x534d4150 || u32(0x800c) != 0 || u32(0x8010) != 24 || u16(0x8014)&1 != 0 {
		t.Fatalf("E820 registers/flags %x", ram[0x8008:0x8016])
	}
	if u64(0x8100) != 1<<20 || u64(0x8108) != 127<<20 || u32(0x8110) != 1 || u32(0x8114) != 1 {
		t.Fatalf("E820 high-memory range %x", ram[0x8100:0x8118])
	}
}
