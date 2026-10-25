package cc

import (
	"encoding/binary"

	"j5.nz/cc/hypervisor"
	"j5.nz/cc/hypervisor/x86state"
)

const (
	bios32Directory = 0xf6000
	bios32Entry     = 0xf6100
	pciBIOSEntry    = 0xf6200
)

// Both entry points use the BIOS32 far-call ABI. They remain callable through
// a guest's own virtual mapping of ROM, as used by Windows 9x's PCI enumerator.
func (p *pc) installPCIFirmware() {
	header := p.ram[bios32Directory : bios32Directory+16]
	copy(header, "_32_")
	binary.LittleEndian.PutUint32(header[4:], bios32Entry)
	header[9] = 1
	var checksum byte
	for _, b := range header {
		checksum += b
	}
	header[10] = -checksum
	// Directory lookup: $PCI, function BL=0. Return the physical ROM base,
	// service extent, and entry offset. Unknown service/function returns AL.
	copy(p.ram[bios32Entry:], []byte{
		0x3d, 0x24, 0x50, 0x43, 0x49, // cmp eax,$PCI
		0x75, 0x16, // jne absent
		0x84, 0xdb, 0x75, 0x15, // test bl,bl; jne bad function
		0xbb, 0, 0, 0x0f, 0, // mov ebx,0xf0000
		0xb9, 0, 0, 1, 0, // mov ecx,0x10000
		0xba, 0, 0x62, 0, 0, // mov edx,0x6200
		0x30, 0xc0, 0xcb, // xor al,al; retf
		0xb0, 0x80, 0xcb, // absent: mov al,80h; retf
		0xb0, 0x81, 0xcb, // bad function: mov al,81h; retf
	})
	copy(p.ram[pciBIOSEntry:], []byte{0xe6, biosPort, 0xcb})
}

// Use the same bus and device write semantics as configuration mechanism 1.
// Firmware accesses must not overwrite the caller's CF8 address latch.
func (p *pc) pciBIOSConfig(bdf, offset uint16, size uint8, write bool, value uint32) (uint32, error) {
	previous := p.pciAddress
	defer func() { p.pciAddress = previous }()
	p.pciAddress = 0x80000000 | uint32(bdf)<<8 | uint32(offset&0xfc)
	var data [4]byte
	binary.LittleEndian.PutUint32(data[:], value)
	err := p.pciIO(hypervisor.X86Exit{Port: 0xcfc + offset&3, Size: size, Count: 1, Write: write, Data: data[:size]})
	return binary.LittleEndian.Uint32(data[:]), err
}

// Status is returned in AH and CF by the real-mode and protected-mode callers.
// There is one PCI bus; devices with fixed IRQs do not expose a routing table.
func (p *pc) pciBIOS(r *x86state.Registers) (byte, error) {
	if byte(r.Rax>>8) != 0xb1 {
		return 0x81, nil
	}
	switch function := byte(r.Rax); function {
	case 1:
		r.Rax = r.Rax&^255 | 1 // configuration mechanism 1
		setLow(&r.Rbx, 0x0210)
		r.Rcx &^= 255      // last bus = 0
		r.Rdx = 0x20494350 // PCI signature
		r.Rdi = pciBIOSEntry
		return 0, nil
	case 2, 3:
		if function == 2 && uint16(r.Rdx) == 0xffff {
			return 0x83, nil
		}
		instance := uint16(r.Rsi)
		for bdf := uint16(0); bdf < 256; bdf++ {
			id, err := p.pciBIOSConfig(bdf, 0, 4, false, 0)
			if err != nil {
				return 0, err
			}
			if uint16(id) == 0xffff {
				continue
			}
			match := id == uint32(uint16(r.Rcx))<<16|uint32(uint16(r.Rdx))
			if function == 3 {
				class, err := p.pciBIOSConfig(bdf, 8, 4, false, 0)
				if err != nil {
					return 0, err
				}
				match = class>>8 == uint32(r.Rcx)
			}
			if match {
				if instance == 0 {
					setLow(&r.Rbx, bdf)
					return 0, nil
				}
				instance--
			}
		}
		return 0x86, nil
	case 8, 9, 10, 11, 12, 13:
		size := uint8(1 << ((function - 8) % 3))
		offset := uint16(r.Rdi)
		if offset >= 256 || offset%uint16(size) != 0 {
			return 0x87, nil
		}
		value, err := p.pciBIOSConfig(uint16(r.Rbx), offset, size, function >= 11, uint32(r.Rcx))
		if err != nil {
			return 0, err
		}
		if function < 11 {
			switch size {
			case 1:
				r.Rcx = r.Rcx&^255 | uint64(byte(value))
			case 2:
				setLow(&r.Rcx, uint16(value))
			case 4:
				r.Rcx = uint64(value)
			}
		}
		return 0, nil
	default:
		return 0x81, nil
	}
}
