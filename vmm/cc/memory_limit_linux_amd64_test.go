//go:build linux && amd64

package cc

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/tinyrange/trex/vmm"
	"github.com/tinyrange/trex/vmm/ramfb"
	"j5.nz/cc/hypervisor"
)

// Exercise the real backend mapping and Darwin firmware handoff, not merely
// the validation limit. mmap reserves 3GiB; this guest touches only a few pages.
func TestDarwinThreeGiBRAM(t *testing.T) {
	requireKVM(t)
	kernel := make([]byte, 4096)
	if _, err := darwinKernel(0x200000).ReadAt(kernel, 0); err != nil {
		t.Fatal(err)
	}
	copy(kernel[0x200:], []byte{
		0xc7, 0x05, 0x00, 0x10, 0x00, 0x80, 0x78, 0x56, 0x34, 0x12,
		0xc7, 0x05, 0x00, 0xf0, 0xff, 0xbf, 0x21, 0x43, 0x65, 0x87,
		0xb0, 0x42, 0xe6, 0xf2, 0xeb, 0xfe,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	m := vmm.Machine{Architecture: "x86_64", CPUs: 1, Memory: 3 << 30, StartPaused: true,
		DarwinBoot: &vmm.DarwinBoot{Kernel: darwinTestSource{bytes.NewReader(kernel)}},
		Disks:      []vmm.Disk{{Device: testBlock(t, make([]byte, 512)), Snapshot: true}}}
	raw, err := (&Backend{}).Start(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	d := raw.(*driver)
	defer d.Close(context.Background())
	err = d.call(ctx, func() error {
		// Check the advertised physical memory and final EFI usable range.
		regs, err := d.pc.cpu.Registers()
		if err != nil {
			return err
		}
		args := d.pc.ram[regs.Rax : regs.Rax+4096]
		u32, u64 := binary.LittleEndian.Uint32, binary.LittleEndian.Uint64
		if u64(args[1144:]) != 3<<30 {
			return fmt.Errorf("wrong physical memory: %d", u64(args[1144:]))
		}
		start, size := u32(args[1032:]), u32(args[1036:])
		last := d.pc.ram[start+size-40 : start+size]
		if u32(last) != 7 || u64(last[8:])+u64(last[24:])*4096 != 3<<30 {
			return fmt.Errorf("EFI RAM does not end before PCI window: %x", last)
		}
		for {
			ex, err := d.pc.run(ctx)
			if err != nil {
				return err
			}
			if ex.Reason == 0 {
				continue
			}
			if ex.Reason != hypervisor.X86ExitIO || ex.Port != 0xf2 || len(ex.Data) != 1 || ex.Data[0] != 0x42 {
				return fmt.Errorf("unexpected guest exit: %+v", ex)
			}
			break
		}
		if u32(d.pc.ram[0x80001000:]) != 0x12345678 || u32(d.pc.ram[0xbffff000:]) != 0x87654321 {
			return fmt.Errorf("guest high-RAM writes did not reach mapped backing")
		}
		if u32(d.pc.framebuffer) != ramfb.Magic {
			return fmt.Errorf("high RAM aliases framebuffer")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
