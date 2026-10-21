package cc

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/boot/darwin"
	"github.com/tinyrange/trex/vmm"
	"github.com/tinyrange/trex/vmm/ramfb"
	"github.com/tinyrange/trex/windows/guid"
	"hash/crc32"
	"j5.nz/cc/hypervisor/x86state"
	"strings"
)

// installDarwin loads the supplied XNU image and constructs its firmware ABI.
// The original _pstart performs the 32->64-bit switch, using its own tables.
func (p *pc) installDarwin(boot *vmm.DarwinBoot) error {
	clock, ok := p.cpu.(interface {
		TSCFrequency() (uint64, error)
		ReadMSR(uint32) (uint64, error)
	})
	if !ok {
		return fmt.Errorf("cc: Darwin requires guest TSC frequency and performance-ratio observations")
	}
	tscHz, err := clock.TSCFrequency()
	if err != nil {
		return err
	}
	perf, err := clock.ReadMSR(0x198)
	if err != nil {
		return err
	}
	ratio := ((perf>>40)&31)*2 + ((perf >> 46) & 1)
	if tscHz == 0 || ratio == 0 {
		return fmt.Errorf("cc: unusable guest TSC/performance ratio")
	}
	busHz := tscHz * 2 / ratio
	img, err := darwin.Open(boot.Kernel)
	if err != nil {
		return err
	}
	align := func(v uint64) uint64 { return (v + 4095) &^ 4095 }
	top := align(img.End)
	argsAddr := top
	mapAddr := top + 4096
	dtAddr := top + 8192
	runtimeAddr := top + 0x10000
	runtimeEnd := runtimeAddr + 0x2000
	ramEnd := min(uint64(len(p.ram)), uint64(pciMemoryBase))
	// The original bootstrap maps the low 1GiB and addresses metadata with
	// 32-bit pointers. Check the complete arena before touching guest RAM.
	loadedEnd := runtimeEnd
	if img.Base < 0x100000 || runtimeEnd > 1<<30 || ramEnd%4096 != 0 || runtimeEnd > ramEnd || ramEnd-runtimeEnd < 128<<20 {
		return fmt.Errorf("cc: Darwin handoff must fit low 1GiB and leave 128MiB free RAM")
	}
	if err = img.Load(p.ram); err != nil {
		return err
	}
	// EFI system/configuration/runtime tables. Runtime functions return
	// EFI_UNSUPPORTED rather than pretending a persistent variable store exists.
	clear(p.ram[runtimeAddr:runtimeEnd])
	system, runtime, config, stub := runtimeAddr, runtimeAddr+256, runtimeAddr+512, runtimeAddr+4096
	put64 := func(addr, v uint64) { binary.LittleEndian.PutUint64(p.ram[addr:], v) }
	put32 := func(addr uint64, v uint32) { binary.LittleEndian.PutUint32(p.ram[addr:], v) }
	header := func(addr, signature uint64, size uint32) {
		put64(addr, signature)
		put32(addr+8, 0x2000a)
		put32(addr+12, size)
		put32(addr+16, 0)
		put32(addr+16, crc32.ChecksumIEEE(p.ram[addr:addr+uint64(size)]))
	}
	// movabs EFI_UNSUPPORTED,%rax; ret -- Microsoft x64 ABI.
	copy(p.ram[stub:], []byte{0x48, 0xb8, 3, 0, 0, 0, 0, 0, 0, 0x80, 0xc3})
	for i := uint64(0); i < 14; i++ {
		put64(runtime+24+i*8, stub|0xffffff8000000000)
	}
	header(runtime, 0x56524553544e5552, 136)
	acpi, _ := guid.Parse("{8868E871-E4F1-11D3-BC22-0080C73C8881}")
	copy(p.ram[config:], acpi[:])
	put64(config+16, 0xe0000)
	vendor := runtimeAddr + 768
	for i, c := range "TinyRangeX" {
		binary.LittleEndian.PutUint16(p.ram[vendor+uint64(i)*2:], uint16(c))
	}
	put64(system+24, vendor|0xffffff8000000000)
	put32(system+32, 1)
	put64(system+88, runtime|0xffffff8000000000)
	put64(system+104, 1)
	put64(system+112, config|0xffffff8000000000)
	header(system, 0x5453595320494249, 120)
	node := func(name string, props map[string][]byte, children ...darwin.Node) darwin.Node {
		props["name"] = darwin.CString(name)
		return darwin.Node{Properties: props, Children: children}
	}
	// XNU1699 registerNVRAMController derives IOPlatformUUID from this
	// 16-byte EFI identity. Without it, gethostuuid blocks core services
	// (including DiskArbitration and therefore kextd). This is a fresh virtual
	// machine identity, not an Apple hardware UUID or serial number.
	systemID := make([]byte, 16)
	if _, err := rand.Read(systemID); err != nil {
		return err
	}
	systemID[6] = (systemID[6] & 15) | 0x40
	systemID[8] = (systemID[8] & 63) | 0x80
	// XNU2782 early_random requires 64 firmware entropy bytes before the
	// first kernel log. PE_get_random_seed consumes /chosen/random-seed
	// and clears it in the guest tree. Supply fresh cryptographic entropy,
	// never a fixed seed, hardware identity, or caller SMC key.
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		return fmt.Errorf("cc: Darwin firmware entropy: %w", err)
	}
	memoryProps := map[string][]byte{"Kernel-__TEXT": darwin.Range(uint32(img.Base), uint32(img.End-img.Base))}
	tree := node("/", map[string][]byte{"compatible": darwin.CString("ACPI"), "model": darwin.CString("ACPI"), "board-id": darwin.CString("TREX-CCPC"), "#address-cells": darwin.U32(2), "#size-cells": darwin.U32(2)},
		node("chosen", map[string][]byte{"boot-args": darwin.CString(boot.CommandLine), "boot-file": darwin.CString("kernelcache"), "random-seed": seed}, node("memory-map", memoryProps)),
		node("efi", map[string][]byte{"firmware-abi": darwin.CString("EFI64"), "firmware-vendor": p.ram[vendor : vendor+20], "firmware-revision": darwin.U32(1)},
			node("platform", map[string][]byte{"FSBFrequency": darwin.U64(busHz), "system-id": systemID}),
			node("runtime-services", map[string][]byte{"table": darwin.U64(runtime | 0xffffff8000000000)}),
			node("configuration-table", map[string][]byte{}, node("8868E871-E4F1-11D3-BC22-0080C73C8881", map[string][]byte{"guid": acpi[:], "table": darwin.U64(0xe0000)}))))
	dt, err := tree.Encode()
	if err != nil {
		return err
	}
	if len(dt) > 0xe000 {
		return fmt.Errorf("cc: Darwin device tree exceeds metadata arena")
	}
	copy(p.ram[dtAddr:], dt)
	ranges := []darwin.MemoryRange{
		{Type: 0, Physical: 0, Pages: 1},
		{Type: 7, Physical: 0x1000, Pages: 0x9f, Attributes: 8},
		{Type: 0, Physical: 0xa0000, Pages: 0x60},
		{Type: 2, Physical: 0x100000, Pages: (runtimeAddr - 0x100000) / 4096, Attributes: 8},
		{Type: 6, Physical: runtimeAddr, Virtual: runtimeAddr | 0xffffff8000000000, Pages: 1, Attributes: 0x8000000000000008},
		{Type: 5, Physical: stub, Virtual: stub | 0xffffff8000000000, Pages: 1, Attributes: 0x8000000000000008},
	}
	ranges = append(ranges, darwin.MemoryRange{Type: 7, Physical: loadedEnd, Pages: (ramEnd - loadedEnd) / 4096, Attributes: 8})
	if uint64(len(p.ram)) > ramEnd {
		ranges = append(ranges, darwin.MemoryRange{Type: 7, Physical: highRAMBase, Pages: (uint64(len(p.ram)) - ramEnd) / 4096, Attributes: 8})
	}
	mmap, err := darwin.MemoryMap(ranges)
	if err != nil {
		return err
	}
	copy(p.ram[mapAddr:], mmap)
	displayMode := uint32(1) // GRAPHICS_MODE
	for _, arg := range strings.Fields(boot.CommandLine) {
		if arg == "-v" || arg == "-s" {
			displayMode = 2
		} // FB_TEXT_MODE
	}
	ba, err := (darwin.Arguments{CommandLine: boot.CommandLine, MemoryMap: uint32(mapAddr), MemoryMapSize: uint32(len(mmap)), DeviceTree: uint32(dtAddr), DeviceTreeSize: uint32(len(dt)), KernelAddress: uint32(img.Base), KernelSize: uint32(loadedEnd - img.Base), EFISystemTable: uint32(system), RuntimePageStart: uint32(runtimeAddr / 4096), RuntimePageCount: 2, RuntimeVirtualPage: (runtimeAddr | 0xffffff8000000000) / 4096, PhysicalMemorySize: uint64(len(p.ram)), FSBFrequency: busHz, Video: [6]uint32{ramfb.Address + ramfb.Pixels | 1, displayMode, 1280 * 4, 1280, 720, 32}}).Encode()
	if err != nil {
		return err
	}
	copy(p.ram[argsAddr:], ba)
	for i, v := range []uint32{ramfb.Magic, 1, 1280, 720, 1280 * 4, 1} {
		binary.LittleEndian.PutUint32(p.framebuffer[i*4:], v)
	}
	// Flat 32-bit protected mode, IF clear and paging off. XNU owns GDT and CR3.
	binary.LittleEndian.PutUint64(p.ram[0x9008:], 0x00cf9b000000ffff)
	binary.LittleEndian.PutUint64(p.ram[0x9010:], 0x00cf93000000ffff)
	s, err := p.cpu.SystemRegisters()
	if err != nil {
		return err
	}
	seg := x86state.Segment{Limit: 0xffffffff, Selector: 16, Present: 1, S: 1, Type: 3, Db: 1, G: 1}
	s.Cs, s.Ds, s.Es, s.Ss, s.Fs, s.Gs = seg, seg, seg, seg, seg, seg
	s.Cs.Selector = 8
	s.Cs.Type = 11
	s.Cr0 = 0x11
	s.Cr3 = 0
	s.Cr4 = 0
	s.Efer = 0
	s.Gdt = x86state.DescriptorTable{Base: 0x9000, Limit: 23}
	s.Idt = x86state.DescriptorTable{}
	if err = p.cpu.SetSystemRegisters(s); err != nil {
		return err
	}
	p.darwin = map[string]any{"entry": int64(img.Entry), "boot_args": int64(argsAddr), "kernel_base": int64(img.Base), "loaded_end": int64(loadedEnd)}
	p.darwinSymbols = img.Symbols
	return p.cpu.SetRegisters(x86state.Registers{Rip: img.Entry, Rax: argsAddr, Rsp: 0x90000, Rflags: 2})
}
