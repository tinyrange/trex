package cc

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/tinyrange/trex/boot/linux"
	"github.com/tinyrange/trex/vmm"
	"j5.nz/cc/hypervisor/x86state"
)

const (
	linuxGDT       = 0x10000
	linuxSetupData = 0x11000
	linuxStack     = 0x20000
	linuxZeroPage  = 0x90000
	linuxCommand   = linuxZeroPage + 4096
	linuxHighStart = 0x100000
)

// installLinux builds the x86 protected-mode handoff for the original
// decompressor. See https://docs.kernel.org/arch/x86/boot.html.
func (p *pc) installLinux(boot *vmm.LinuxBoot) error {
	image, err := linux.OpenBZImage(boot.Kernel)
	if err != nil {
		return err
	}
	if uint32(len(boot.CommandLine)) > image.CommandLineMax {
		return fmt.Errorf("Linux command line exceeds the kernel's %d-byte limit", image.CommandLineMax)
	}

	entry := uint64(linuxHighStart)
	runtimeStart := max(entry, image.PreferredAddress)
	if image.Relocatable {
		mask := uint64(image.KernelAlignment) - 1
		if runtimeStart >= pciMemoryBase {
			return fmt.Errorf("Linux preferred address is outside low PC RAM")
		}
		entry = (runtimeStart + mask) &^ mask
		runtimeStart = entry
	}
	lowEnd := min(uint64(len(p.ram)), uint64(pciMemoryBase))
	payloadEnd := entry + uint64(image.Payload.Size())
	if payloadEnd > lowEnd || runtimeStart >= lowEnd || uint64(image.InitSize) > lowEnd-runtimeStart {
		return fmt.Errorf("Linux initialization area does not fit in low PC RAM")
	}
	kernelEnd := max(payloadEnd, runtimeStart+uint64(image.InitSize))

	var initrdStart, initrdSize uint64
	if boot.Initramfs != nil {
		initrdSize = uint64(boot.Initramfs.Size())
		initrdTop := min(lowEnd, uint64(image.InitrdAddressMax)+1)
		if initrdSize > initrdTop {
			return fmt.Errorf("Linux initramfs does not fit below %#x", initrdTop)
		}
		initrdStart = (initrdTop - initrdSize) &^ 4095
		if initrdStart < kernelEnd {
			return fmt.Errorf("Linux initramfs overlaps the kernel initialization area")
		}
	}

	var params [4096]byte
	image.CopySetup(&params)
	le := binary.LittleEndian
	params[0x210] = 0xff                 // unregistered boot loader
	params[0x211] &^= 0x80               // no real-mode heap
	le.PutUint16(params[0x1fa:], 0xffff) // normal video mode
	le.PutUint32(params[0x214:], uint32(entry))
	le.PutUint32(params[0x218:], uint32(initrdStart))
	le.PutUint32(params[0x21c:], uint32(initrdSize))
	le.PutUint32(params[0x228:], linuxCommand)
	le.PutUint64(params[0x250:], linuxSetupData)
	if p.acpi != nil {
		le.PutUint64(params[0x70:], acpiRootPointer)
	}
	regions := pcMemoryMap(uint64(len(p.ram)))
	params[0x1e8] = byte(len(regions))
	for i, region := range regions {
		record := params[0x2d0+20*i:]
		le.PutUint64(record, region.base)
		le.PutUint64(record[8:], region.size)
		le.PutUint32(record[16:], region.kind)
	}

	if _, err := io.ReadFull(io.NewSectionReader(image.Payload, 0, image.Payload.Size()), p.ram[entry:payloadEnd]); err != nil {
		return fmt.Errorf("load Linux protected-mode payload: %w", err)
	}
	if boot.Initramfs != nil {
		if _, err := io.ReadFull(io.NewSectionReader(boot.Initramfs, 0, int64(initrdSize)), p.ram[initrdStart:initrdStart+initrdSize]); err != nil {
			return fmt.Errorf("load Linux initramfs: %w", err)
		}
	}
	copy(p.ram[linuxZeroPage:], params[:])
	p.ram[linuxCommand+copy(p.ram[linuxCommand:], boot.CommandLine)] = 0
	// A fresh bootloader seed lets Linux initialize its RNG before userspace
	// even on a virtual CPU without hardware random instructions.
	seed := p.ram[linuxSetupData : linuxSetupData+16+32]
	clear(seed[:16])
	le.PutUint32(seed[8:], 9) // SETUP_RNG_SEED
	le.PutUint32(seed[12:], uint32(len(seed)-16))
	rand.Read(seed[16:])
	clear(p.ram[linuxGDT : linuxGDT+16])
	le.PutUint64(p.ram[linuxGDT+16:], 0x00cf9b000000ffff)
	le.PutUint64(p.ram[linuxGDT+24:], 0x00cf93000000ffff)

	s, err := p.cpu.SystemRegisters()
	if err != nil {
		return err
	}
	data := x86state.Segment{Selector: 0x18, Limit: 0xffffffff, Type: 3, Present: 1, Db: 1, S: 1, G: 1}
	s.Cs = data
	s.Cs.Selector, s.Cs.Type = 0x10, 11
	s.Ds, s.Es, s.Ss, s.Fs, s.Gs = data, data, data, data, data
	s.Gdt, s.Idt = x86state.DescriptorTable{Base: linuxGDT, Limit: 31}, x86state.DescriptorTable{}
	s.Cr0, s.Cr2, s.Cr3, s.Cr4, s.Efer = 0x11, 0, 0, 0, 0
	// Keep the software-visible gate enabled as well as the reset CPU state.
	p.ports[0x92] |= 2
	if err := p.cpu.SetSystemRegisters(s); err != nil {
		return err
	}
	return p.cpu.SetRegisters(x86state.Registers{Rip: entry, Rsi: linuxZeroPage, Rsp: linuxStack, Rflags: 2})
}
