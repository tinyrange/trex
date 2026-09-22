package cc

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"j5.nz/cc/hypervisor"
)

type acpiTestCPU struct{ hypervisor.X86 }

func (*acpiTestCPU) SetIRQ(uint32, bool) error { return nil }

func TestACPIFirmwareTables(t *testing.T) {
	p := &pc{ram: make([]byte, 1<<20), cpu: &acpiTestCPU{}, now: time.Now}
	if err := p.installACPI(); err != nil {
		t.Fatal(err)
	}
	checksum := func(data []byte) {
		t.Helper()
		var sum byte
		for _, b := range data {
			sum += b
		}
		if sum != 0 {
			t.Fatalf("invalid checksum for %.8s", data)
		}
	}
	root := p.ram[0xe0000 : 0xe0000+36]
	checksum(root[:20])
	checksum(root)
	get := func(address uint64, signature string) []byte {
		t.Helper()
		if address < 0xe1000 || address+36 > 0xf0000 {
			t.Fatalf("invalid table address %#x", address)
		}
		length := uint64(binary.LittleEndian.Uint32(p.ram[address+4:]))
		if length < 36 || address+length > 0xf0000 {
			t.Fatalf("invalid table length %d", length)
		}
		data := p.ram[address : address+length]
		if string(data[:4]) != signature {
			t.Fatalf("table %q, want %q", data[:4], signature)
		}
		checksum(data)
		return data
	}
	rsdt := get(uint64(binary.LittleEndian.Uint32(root[16:])), "RSDT")
	xsdt := get(binary.LittleEndian.Uint64(root[24:]), "XSDT")
	for i := 0; i < 2; i++ {
		if uint64(binary.LittleEndian.Uint32(rsdt[36+i*4:])) != binary.LittleEndian.Uint64(xsdt[36+i*8:]) {
			t.Fatal("root tables disagree")
		}
	}
	fadt := get(binary.LittleEndian.Uint64(xsdt[36:]), "FACP")
	if binary.LittleEndian.Uint16(fadt[46:]) != 9 || binary.LittleEndian.Uint32(fadt[76:]) != acpiPMBase+8 || fadt[91] != 4 || binary.LittleEndian.Uint16(fadt[109:]) != 3 {
		t.Fatal("incorrect fixed device description")
	}
	dsdt := get(binary.LittleEndian.Uint64(fadt[140:]), "DSDT")
	for _, name := range []string{"CPU0", "PCI0", "KBD0", "MOU0", "IDE0", "_S5_"} {
		if !bytes.Contains(dsdt, []byte(name)) {
			t.Fatalf("missing %s", name)
		}
	}
	// Each fixed device is scoped under PCI0. Top-level sibling devices
	// trigger XP x64's IRQ arbiter before its PCI routing interface exists.
	if bytes.Count(dsdt, []byte{'\\', 0x2e, '_', 'S', 'B', '_', 'P', 'C', 'I', '0'}) != 7 {
		t.Fatal("fixed devices must be children of the PCI root")
	}
	madt := get(binary.LittleEndian.Uint64(xsdt[44:]), "APIC")
	if binary.LittleEndian.Uint32(madt[36:]) != 0xfee00000 {
		t.Fatal("incorrect APIC address")
	}
}

func TestEmptyPCIConfiguration(t *testing.T) {
	p := &pc{acpi: &acpiPM{}}
	data := []byte{0xff, 0xff, 0xff, 0xff}
	ex := hypervisor.X86Exit{Port: 0xcf8, Size: 4, Count: 1, Write: true, Data: data}
	if err := p.handleIO(ex); err != nil {
		t.Fatal(err)
	}
	ex.Write = false
	if err := p.handleIO(ex); err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(data) != 0x80fffffc {
		t.Fatalf("configuration address %#x", data)
	}
	for _, width := range []uint8{1, 2, 4} {
		for port := uint16(0xcfc); port+uint16(width) <= 0xd00; port++ {
			clear(data)
			ex.Port, ex.Size, ex.Data = port, width, data[:width]
			if err := p.handleIO(ex); err != nil {
				t.Fatal(err)
			}
			for _, value := range ex.Data {
				if value != 0xff {
					t.Fatal("absent PCI function did not float high")
				}
			}
		}
	}
}

func TestACPIFixedRegisters(t *testing.T) {
	now := time.Unix(0, 0)
	level := false
	a := &acpiPM{started: now, control: 1, setIRQ: func(irq uint32, on bool) error {
		if irq != 9 {
			t.Fatalf("IRQ %d", irq)
		}
		level = on
		return nil
	}}
	io := func(offset uint16, width int, write bool, value uint32) uint32 {
		t.Helper()
		data := make([]byte, 4)
		binary.LittleEndian.PutUint32(data, value)
		if err := a.io(hypervisor.X86Exit{Port: acpiPMBase + offset, Size: uint8(width), Count: 1, Write: write, Data: data[:width]}, now); err != nil {
			t.Fatal(err)
		}
		return binary.LittleEndian.Uint32(data)
	}
	now = now.Add(time.Second)
	if got := io(8, 4, false, 0); got != 3579545 {
		t.Fatalf("timer %d", got)
	}
	io(2, 2, true, 1)
	now = now.Add(2 * time.Second)
	io(8, 4, false, 0)
	if !level || io(0, 2, false, 0)&1 == 0 {
		t.Fatal("missing timer carry event")
	}
	io(0, 1, true, 1)
	if level {
		t.Fatal("W1C failed to lower SCI")
	}
	a.status |= 1 << 8
	io(2, 2, true, 1<<8)
	if !level {
		t.Fatal("power-button event did not assert SCI")
	}
	io(1, 1, true, 1)
	if level {
		t.Fatal("byte acknowledgement failed")
	}
	now = now.Add(2 * time.Second)
	if got := io(8, 4, false, 0); got != uint32(uint64(5*3579545)&0xffffff) {
		t.Fatalf("timer rollover %#x", got)
	}
	io(4, 2, true, 5<<10|1<<13)
	if !a.poweroff || io(4, 2, false, 0)&0x2001 != 1 {
		t.Fatal("S5/SCI_EN/SLP_EN semantics")
	}
}

func TestACPIHPETDescription(t *testing.T) {
	p := &pc{ram: make([]byte, 1<<20), cpu: &acpiTestCPU{}, now: time.Now, hpet: &hpet{}}
	if err := p.installACPI(); err != nil {
		t.Fatal(err)
	}
	xsdt := binary.LittleEndian.Uint64(p.ram[0xe0018:])
	if binary.LittleEndian.Uint32(p.ram[xsdt+4:]) != 60 {
		t.Fatal("HPET missing from XSDT")
	}
	address := binary.LittleEndian.Uint64(p.ram[xsdt+52:])
	table := p.ram[address : address+56]
	var sum byte
	for _, b := range table {
		sum += b
	}
	if sum != 0 || string(table[:4]) != "HPET" || binary.LittleEndian.Uint32(table[36:]) != uint32(hpetCapabilities&0xffffffff) || binary.LittleEndian.Uint64(table[44:]) != hpetAddress {
		t.Fatalf("invalid HPET table %x", table)
	}
	fadt := binary.LittleEndian.Uint64(p.ram[xsdt+36:])
	dsdt := binary.LittleEndian.Uint64(p.ram[fadt+140:])
	aml := p.ram[dsdt : dsdt+uint64(binary.LittleEndian.Uint32(p.ram[dsdt+4:]))]
	resource := []byte{0x86, 9, 0, 1, 0, 0, 0xd0, 0xfe, 0, 4, 0, 0}
	if !bytes.Contains(aml, []byte("HPET")) || !bytes.Contains(aml, resource) {
		t.Fatal("missing HPET fixed memory resource")
	}
}
