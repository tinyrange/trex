//go:build linux && amd64

package cc

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/tinyrange/trex/emulator/cpu"
	"github.com/tinyrange/trex/vmm"
	"github.com/tinyrange/trex/vmm/ramfb"
	"j5.nz/cc/hypervisor"
	"j5.nz/cc/hypervisor/x86state"
)

// Only a few mmap-backed pages are touched. Exercise actual KVM high-RAM
// writes, native virtual reads, and both firmware maps without allocating
// eight GiB of resident host memory just to test address arithmetic.
func TestDarwinEightGiBHighMemory(t *testing.T) {
	requireKVM(t)
	kernel := make([]byte, 4096)
	if _, err := darwinKernel(0x200000).ReadAt(kernel, 0); err != nil {
		t.Fatal(err)
	}
	copy(kernel[0x200:], []byte{
		0x48, 0xb8, 0x00, 0x10, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
		0xc7, 0x00, 0xef, 0xbe, 0xad, 0xde,
		0x48, 0xb8, 0x00, 0xf0, 0xff, 0x3f, 0x02, 0x00, 0x00, 0x00,
		0xc7, 0x00, 0xcd, 0xab, 0xfe, 0xca,
		0xb0, 0x42, 0xe6, 0xf2, 0xeb, 0xfe,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	raw, err := (&Backend{}).Start(ctx, vmm.Machine{Architecture: "x86_64", CPUs: 1, Memory: 8 << 30, StartPaused: true,
		DarwinBoot: &vmm.DarwinBoot{Kernel: darwinTestSource{bytes.NewReader(kernel)}},
		Disks:      []vmm.Disk{{Device: testBlock(t, make([]byte, 512)), Snapshot: true}}})
	if err != nil {
		t.Fatal(err)
	}
	d := raw.(*driver)
	defer d.Close(context.Background())
	err = d.call(ctx, func() error {
		p := d.pc
		u32, u64 := binary.LittleEndian.Uint32, binary.LittleEndian.Uint64
		regs, err := p.cpu.Registers()
		if err != nil {
			return err
		}
		args := p.ram[regs.Rax : regs.Rax+4096]
		if u64(args[1144:]) != 8<<30 {
			return fmt.Errorf("wrong total RAM")
		}
		start, size := u32(args[1032:]), u32(args[1036:])
		mm := p.ram[start : start+size]
		low, high := mm[len(mm)-80:len(mm)-40], mm[len(mm)-40:]
		if u32(low) != 7 || u64(low[8:])+u64(low[24:])*4096 != 3<<30 || u32(high) != 7 || u64(high[8:]) != 4<<30 || u64(high[24:])*4096 != 5<<30 {
			return fmt.Errorf("bad split EFI map: %x %x", low, high)
		}
		r := x86state.Registers{Rax: 0xe820, Rbx: 3, Rcx: 24, Rdx: 0x534d4150, Rdi: 0x8100}
		if !p.extendedMemory(&r, x86state.SystemRegisters{}) || r.Rbx != 0 || u64(p.ram[0x8100:]) != 4<<30 || u64(p.ram[0x8108:]) != 5<<30 {
			return fmt.Errorf("bad high E820 descriptor")
		}
		r = x86state.Registers{Rax: 0xe801}
		if !p.extendedMemory(&r, x86state.SystemRegisters{}) || r.Rbx != (3<<30-16<<20)>>16 {
			return fmt.Errorf("E801 claims PCI hole or overflows: %+v", r)
		}
		put := func(address, value uint64) { binary.LittleEndian.PutUint64(p.ram[address:], value) }
		put(0x1000, 0x2003)
		for i := uint64(0); i < 9; i++ {
			table := uint64(0x10000) + i*4096
			put(0x2000+i*8, table|3)
			for j := uint64(0); j < 512; j++ {
				put(table+j*8, (i<<30)+(j<<21)|0x83)
			}
		}
		s, err := p.cpu.SystemRegisters()
		if err != nil {
			return err
		}
		s.Cr0 |= 1 << 31
		s.Cr3 = 0x1000
		s.Cr4 |= 1 << 5
		s.Efer = 0x500
		s.Cs.L = 1
		s.Cs.Db = 0
		if err = p.cpu.SetSystemRegisters(s); err != nil {
			return err
		}
		for {
			ex, err := p.run(ctx)
			if err != nil {
				return err
			}
			if ex.Reason == 0 {
				continue
			}
			if ex.Reason != hypervisor.X86ExitIO || ex.Port != 0xf2 || len(ex.Data) != 1 || ex.Data[0] != 0x42 {
				return fmt.Errorf("unexpected high-RAM guest exit: %+v", ex)
			}
			break
		}
		for address, want := range map[uint64]uint32{0x100001000: 0xdeadbeef, 0x23ffff000: 0xcafeabcd} {
			b, err := p.memory(address, 4)
			if err != nil {
				return err
			}
			if u32(b) != want {
				return fmt.Errorf("wrong high physical value at %#x", address)
			}
			var out [4]byte
			if err = (efiMemory{p: p, system: &s}).ReadMemory(address, out[:], cpu.Read); err != nil {
				return err
			}
			if u32(out[:]) != want {
				return fmt.Errorf("wrong high virtual value at %#x", address)
			}
		}
		if _, err := p.memory(0xc0000000, 4); err == nil {
			return fmt.Errorf("PCI hole accepted as DMA RAM")
		}
		if u32(p.framebuffer) != ramfb.Magic {
			return fmt.Errorf("high RAM overwrote framebuffer")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
