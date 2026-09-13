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

func TestBIOSDiskExtensionsAndLegacyCPU(t *testing.T) {
	requireKVM(t)
	data := make([]byte, 4*512)
	// Execute CPUID and both EDD calls in real guest code, retaining their
	// registers/flags in RAM. The final OUT is the decisive completion point.
	copy(data, []byte{
		0x66, 0x31, 0xc0, 0x0f, 0xa2, 0x66, 0xa3, 0x10, 0x80,
		0xb8, 0, 0x41, 0xbb, 0xaa, 0x55, 0xba, 0x80, 0, 0xcd, 0x13,
		0xa3, 0, 0x80, 0x89, 0x1e, 2, 0x80, 0x9c, 0x58, 0xa3, 4, 0x80,
		0xbe, 0, 0x7d, 0xb4, 0x42, 0xcd, 0x13, 0xa3, 6, 0x80, 0x9c, 0x58, 0xa3, 8, 0x80,
		0xb0, 0x42, 0xe6, 0xf2, 0xeb, 0xfe,
	})
	copy(data[0x100:], []byte{16, 0, 1, 0, 0, 0x81, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0})
	binary.LittleEndian.PutUint16(data[510:], 0xaa55)
	binary.LittleEndian.PutUint16(data[1024:], 0x1234)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cpu, err := hypervisor.NewX86(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer cpu.Close()
	if err := configureCPU(cpu); err != nil {
		t.Fatal(err)
	}
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
			t.Fatalf("unexpected exit: %+v", ex)
		}
		if ex.Port == 0xf2 {
			break
		}
		if err := p.handleIO(ex); err != nil {
			t.Fatal(err)
		}
	}
	word := func(offset int) uint16 { return binary.LittleEndian.Uint16(ram[offset:]) }
	if max := binary.LittleEndian.Uint32(ram[0x8010:]); max < 1 || max > 3 {
		t.Fatalf("legacy CPUID maximum %d", max)
	}
	if word(0x8000)>>8 != 0x21 || word(0x8002) != 0xaa55 || word(0x8004)&1 != 0 {
		t.Fatalf("EDD probe registers %x", ram[0x8000:0x8006])
	}
	if word(0x8006)>>8 != 0 || word(0x8008)&1 != 0 || word(0x8100) != 0x1234 {
		t.Fatalf("EDD read registers %x data %x", ram[0x8006:0x800a], ram[0x8100:0x8102])
	}
}
