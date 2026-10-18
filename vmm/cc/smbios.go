package cc

import (
	"encoding/binary"
	"fmt"
)

const smbios3GUID = "{F2FD1544-9794-4A2C-992E-E5BBCF20E394}"

// smbiosTable describes the virtual platform, never the host's hardware IDs.
// The UUID is the boot disk's GPT identity and remains stable across boots.
func smbiosTable(memory uint64, cpus int, uuid [16]byte) []byte {
	var table []byte
	add := func(typ byte, handle uint16, body []byte, names ...string) {
		b := []byte{typ, byte(len(body) + 4), byte(handle), byte(handle >> 8)}
		b = append(b, body...)
		for _, name := range names {
			b = append(b, name...)
			b = append(b, 0)
		}
		if len(names) == 0 {
			b = append(b, 0)
		}
		b = append(b, 0)
		table = append(table, b...)
	}
	// BIOS Information, SMBIOS 3.0 (24-byte formatted area).
	b := make([]byte, 20)
	b[0], b[1], b[4] = 1, 2, 3
	binary.LittleEndian.PutUint64(b[6:], 1<<7) // PCI supported.
	b[15] = 1 << 3                             // UEFI supported, no unsupported Secure Boot claim.
	b[16], b[17], b[18], b[19] = 1, 0, 0xff, 0xff
	add(0, 0, b, "TinyRange", "TinyRange UEFI 1.0", "01/01/2026")
	// System Information: manufacturer, product, version, serial and UUID.
	b = make([]byte, 23)
	b[0], b[1], b[2], b[3] = 1, 2, 3, 4
	copy(b[4:20], uuid[:])
	b[20], b[21], b[22] = 6, 5, 6 // power switch, SKU, family
	serial := fmt.Sprintf("TREX-%x", uuid)
	add(1, 1, b, "TinyRange", "Virtual PC", "1.0", serial, "Virtual-PC", "TinyRange")
	b = make([]byte, 11)
	b[0], b[1], b[2], b[3] = 1, 2, 3, 4
	b[5] = 1 // hosting board
	binary.LittleEndian.PutUint16(b[7:], 3)
	b[9] = 10 // motherboard
	add(2, 2, b, "TinyRange", "Virtual Mainboard", "1.0", serial)
	b = make([]byte, 18)
	b[0], b[1], b[2], b[3] = 1, 3, 2, 3 // desktop chassis
	b[5], b[6], b[7], b[8] = 3, 3, 3, 3 // safe states, no security lockout
	add(3, 3, b, "TinyRange", "1.0", serial)
	b = make([]byte, 38)
	b[0], b[1], b[2], b[3] = 1, 3, 2, 2 // central processor, unknown family
	b[12] = 3                           // version string
	b[20], b[21] = 0x41, 2              // populated/enabled, unknown socket upgrade
	for _, off := range []int{22, 24, 26} {
		binary.LittleEndian.PutUint16(b[off:], 0xffff)
	}
	b[31], b[32], b[33] = byte(cpus), byte(cpus), byte(cpus)
	binary.LittleEndian.PutUint16(b[34:], 1<<2) // 64-bit capable
	add(4, 4, b, "CPU0", "TinyRange", "TinyRangeX Virtual CPU")
	b = make([]byte, 19)
	b[0], b[1], b[2] = 3, 3, 3 // system board, system memory, no ECC
	binary.LittleEndian.PutUint32(b[3:], 0x80000000)
	binary.LittleEndian.PutUint16(b[7:], 0xfffe)
	binary.LittleEndian.PutUint16(b[9:], 1)
	binary.LittleEndian.PutUint64(b[11:], memory)
	add(16, 16, b)
	b = make([]byte, 36)
	binary.LittleEndian.PutUint16(b, 16)
	binary.LittleEndian.PutUint16(b[2:], 0xfffe)
	binary.LittleEndian.PutUint16(b[4:], 64)
	binary.LittleEndian.PutUint16(b[6:], 64)
	mib := memory >> 20
	if mib < 0x7fff {
		binary.LittleEndian.PutUint16(b[8:], uint16(mib))
	} else {
		binary.LittleEndian.PutUint16(b[8:], 0x7fff)
		binary.LittleEndian.PutUint32(b[24:], uint32(mib))
	}
	b[10], b[12], b[13], b[14] = 2, 1, 2, 2 // other form factor, locators, unknown memory type
	add(17, 17, b, "RAM0", "Virtual Memory")
	b = make([]byte, 7) // System Boot Information, no boot error.
	add(32, 32, b)
	add(127, 127, nil)
	return table
}

func smbios3Entry(address uint64, size uint32) []byte {
	b := make([]byte, 24)
	copy(b, "_SM3_")
	b[6], b[7], b[8], b[9], b[10] = 24, 3, 0, 0, 1
	binary.LittleEndian.PutUint32(b[12:], size)
	binary.LittleEndian.PutUint64(b[16:], address)
	var checksum byte
	for _, v := range b {
		checksum -= v
	}
	b[5] = checksum
	return b
}

func (p *pc) installSMBIOS(uuid [16]byte) error {
	table := smbiosTable(uint64(len(p.ram)), max(1, len(p.cpus)), uuid)
	// Publish entry and records as one reserved allocation; update the absolute
	// table address only after the firmware allocator chooses guest RAM.
	blob := append(make([]byte, 24), table...)
	base, err := p.efi.InstallConfigurationTable(smbios3GUID, blob, 0)
	if err != nil {
		return err
	}
	return (efiMemory{p: p}).WriteMemory(base, smbios3Entry(base+24, uint32(len(table))))
}
