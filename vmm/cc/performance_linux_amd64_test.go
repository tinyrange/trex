//go:build linux && amd64

package cc

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/tinyrange/trex/vmm"
	"j5.nz/cc/hypervisor"
)

// Measure the production PC execution path with repeated planar VGA writes.
// There is no browser, framebuffer capture, disk activity or guest scheduler.
func BenchmarkVGAExit(b *testing.B) {
	if _, err := os.Stat("/dev/kvm"); err != nil {
		b.Skip("KVM unavailable")
	}
	cpu, err := hypervisor.NewX86(context.Background())
	if err != nil {
		b.Fatal(err)
	}
	defer cpu.Close()
	ram, err := cpu.MapRAMRegions(16<<20, []hypervisor.RAMRegion{{Address: 0, Offset: 0, Size: 0xa0000}, {Address: 0xc0000, Offset: 0xc0000, Size: (16 << 20) - 0xc0000}})
	if err != nil {
		b.Fatal(err)
	}
	// mov ax,a000; mov es,ax; xor di,di; mov al,55; stosb; jmp stosb
	copy(ram[0x7c00:], []byte{0xb8, 0, 0xa0, 0x8e, 0xc0, 0x31, 0xff, 0xb0, 0x55, 0xaa, 0xeb, 0xfd})
	// newPC initializes the BIOS and starts at 7c00. It needs a valid disk.
	data := make([]byte, 4*512)
	copy(data, ram[0x7c00:0x7c00+12])
	binary.LittleEndian.PutUint16(data[510:], 0xaa55)
	p, err := newPC(cpu, ram, vmm.Disk{Device: testBlock(b, data), CHS: &vmm.CHSGeometry{Cylinders: 1, Heads: 1, Sectors: 4}}, time.Now)
	if err != nil {
		b.Fatal(err)
	}
	if err := p.vga.setMode(0x12); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		ex, err := p.run(ctx)
		cancel()
		if errors.Is(err, context.DeadlineExceeded) {
			continue
		}
		if err != nil {
			b.Fatal(err)
		}
		if ex.Reason == 0 {
			continue
		}
		if ex.Reason != hypervisor.X86ExitMMIO {
			b.Fatalf("unexpected exit: %+v", ex)
		}
		if err := p.vga.mmio(ex, cpu); err != nil {
			b.Fatal(err)
		}
		i++
	}
}
