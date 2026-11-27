package cc

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/tinyrange/trex/vmm"
	"github.com/tinyrange/trex/vmm/ramfb"
)

func TestLinuxHandoff(t *testing.T) {
	const payloadAt = 5 * 512
	const kernelAt = 4 << 20
	const memorySize = 16 << 20
	const initrdTop = 14 << 20
	const commandLine = "console=ttyS0"
	le := binary.LittleEndian
	kernel := make([]byte, payloadAt+16)
	le.PutUint32(kernel[0x1f4:], 1)
	le.PutUint16(kernel[0x1fe:], 0xaa55)
	copy(kernel[0x200:], "\xeb\x6aHdrS")
	le.PutUint16(kernel[0x206:], 0x20f)
	kernel[0x211], kernel[0x234] = 1, 1
	le.PutUint32(kernel[0x22c:], initrdTop-1)
	le.PutUint32(kernel[0x230:], 2<<20)
	le.PutUint16(kernel[0x236:], 1)
	le.PutUint32(kernel[0x238:], 2047)
	le.PutUint64(kernel[0x258:], kernelAt)
	le.PutUint32(kernel[0x260:], 8<<20)
	copy(kernel[payloadAt:], "original payload")
	initrd := []byte("original initrd")
	boot := &vmm.LinuxBoot{Kernel: bytes.NewReader(kernel), Initramfs: bytes.NewReader(initrd), CommandLine: commandLine}
	cpu := &darwinTestCPU{}
	p := &pc{cpu: cpu, ram: make([]byte, memorySize), framebuffer: make([]byte, ramfb.Size), acpi: &acpiPM{}, ports: make(map[uint16]byte)}
	if err := p.installLinux(boot, true); err != nil {
		t.Fatal(err)
	}
	r, s := cpu.regs, cpu.sys
	if r.Rip != kernelAt || r.Rsi != linuxZeroPage || r.Rflags != 2 || s.Cr0 != 0x11 || s.Cr4 != 0 || s.Efer != 0 || s.Cs.Selector != 0x10 || s.Ds.Selector != 0x18 || s.Cs.Db != 1 {
		t.Fatalf("wrong protected-mode entry: %+v, %+v", r, s)
	}
	params := p.ram[r.Rsi : r.Rsi+4096]
	initrdAt := le.Uint32(params[0x218:])
	if initrdAt != initrdTop-4096 || le.Uint32(params[0x21c:]) != uint32(len(initrd)) || !bytes.Equal(p.ram[initrdAt:int(initrdAt)+len(initrd)], initrd) {
		t.Fatal("initramfs bounds or contents differ")
	}
	if !bytes.Equal(p.ram[kernelAt:kernelAt+16], kernel[payloadAt:]) || le.Uint32(params[0x214:]) != kernelAt || le.Uint32(params[0x228:]) != linuxCommand || string(p.ram[linuxCommand:linuxCommand+len(commandLine)+1]) != commandLine+"\x00" {
		t.Fatal("kernel or command line placement differs")
	}
	if le.Uint64(params[0x70:]) != acpiRootPointer || params[0x1e8] != 3 || le.Uint64(params[0x2d0+2*20:]) != 1<<20 {
		t.Fatal("missing boot-time firmware addresses")
	}
	frame, err := ramfb.Capture(p.framebuffer)
	if err != nil || frame == nil {
		t.Fatalf("capture Linux framebuffer: %v", err)
	}
	size := frame.Bounds().Size()
	if params[0x0f] != 0x23 || le.Uint32(params[0x18:]) != ramfb.Address+ramfb.Pixels ||
		int(le.Uint16(params[0x12:])) != size.X || int(le.Uint16(params[0x14:])) != size.Y ||
		int(le.Uint16(params[0x24:])) != frame.Stride {
		t.Fatal("Linux screen info disagrees with the mapped framebuffer")
	}
	seedAt := le.Uint64(params[0x250:])
	if seedAt != linuxSetupData || le.Uint64(p.ram[seedAt:]) != 0 || le.Uint32(p.ram[seedAt+8:]) != 9 || le.Uint32(p.ram[seedAt+12:]) != 32 {
		t.Fatal("wrong bootloader RNG setup_data record")
	}

	boot.Initramfs = bytes.NewReader(make([]byte, 3<<20))
	if err := p.installLinux(boot, false); err == nil || !strings.Contains(err.Error(), "overlaps") {
		t.Fatalf("accepted initramfs overlapping decompressor workspace: %v", err)
	}
}
