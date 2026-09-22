package cc

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/tinyrange/trex/firmware/acpi"
	"j5.nz/cc/hypervisor"
)

const acpiPMBase = 0x400

// acpiPM implements the fixed ACPI registers against the platform clock.
// The platform starts in ACPI mode; there is no SMM ownership transition.
type acpiPM struct {
	started                 time.Time
	ticks                   uint64
	status, enable, control uint16
	irq                     bool
	poweroff                bool
	setIRQ                  func(uint32, bool) error
}

func (a *acpiPM) poll(now time.Time) error {
	elapsed := now.Sub(a.started)
	if elapsed < 0 {
		elapsed = 0
	}
	ticks := uint64(elapsed/time.Second)*3579545 + uint64(elapsed%time.Second)*3579545/uint64(time.Second)
	if ticks>>23 != a.ticks>>23 {
		a.status |= 1
	}
	a.ticks = ticks
	return a.updateIRQ()
}

func (a *acpiPM) updateIRQ() error {
	level := a.control&1 != 0 && a.status&a.enable&0x501 != 0
	if level == a.irq {
		return nil
	}
	if err := a.setIRQ(9, level); err != nil {
		return err
	}
	a.irq = level
	return nil
}

func (a *acpiPM) io(ex hypervisor.X86Exit, now time.Time) error {
	if err := a.poll(now); err != nil {
		return err
	}
	for i := uint32(0); i < ex.Count; i++ {
		for j := uint16(0); j < uint16(ex.Size); j++ {
			pos := int(i)*int(ex.Size) + int(j)
			offset := ex.Port - acpiPMBase + j
			value := byte(0)
			switch {
			case offset < 2:
				shift := offset * 8
				value = byte(a.status >> shift)
				if ex.Write {
					a.status &^= uint16(ex.Data[pos]) << shift
				}
			case offset < 4:
				shift := (offset - 2) * 8
				value = byte(a.enable >> shift)
				if ex.Write {
					a.enable = (a.enable &^ (0xff << shift)) | uint16(ex.Data[pos])<<shift
					a.enable &= 0x501
				}
			case offset < 6:
				shift := (offset - 4) * 8
				value = byte(a.control >> shift)
				if ex.Write {
					a.control = (a.control &^ (0xff << shift)) | uint16(ex.Data[pos])<<shift
					a.control = a.control&0x3c00 | 1
				}
			case offset >= 8 && offset < 12:
				value = byte((a.ticks & 0xffffff) >> ((offset - 8) * 8))
			}
			if !ex.Write {
				ex.Data[pos] = value
			}
		}
		if ex.Write && a.control&0x2000 != 0 {
			if a.control>>10&7 == 5 {
				a.poweroff = true
			}
			a.control &^= 0x2000 // SLP_EN is write-only.
		}
	}
	return a.updateIRQ()
}

// installACPI describes only devices present in this platform. Tables live
// in the E820-reserved firmware window, outside the BIOS interrupt stubs.
func (p *pc) installACPI() error {
	cursor := uint32(0xe1000)
	put := func(data []byte) (uint32, error) {
		address := cursor
		if len(data) > 0xf0000-int(cursor) {
			return 0, fmt.Errorf("ACPI tables exceed firmware window")
		}
		copy(p.ram[cursor:], data)
		cursor = (cursor + uint32(len(data)) + 15) &^ 15
		return address, nil
	}
	table := func(signature string, revision int, body []byte) (uint32, error) {
		data, err := acpi.Table(signature, body, revision, "TREXOS", "CCPC    ", 1, "TREX", 1)
		if err != nil {
			return 0, err
		}
		return put(data)
	}
	facs := make([]byte, 64)
	copy(facs, "FACS")
	binary.LittleEndian.PutUint32(facs[4:], 64)
	facs[32] = 1
	facsAddr, err := put(facs)
	if err != nil {
		return err
	}
	aml, err := acpi.LegacyProcessorAML("CPU0", 0)
	if err != nil {
		return err
	}
	pciAML, err := (acpi.PCIRoot{Legacy: true, MemoryBase: 0xc0000000, MemorySize: 0x3ec00000}).AML()
	if err != nil {
		return err
	}
	aml = append(aml, pciAML...)
	for _, dev := range []acpi.ISADevice{
		{Name: "PIC0", ID: "PNP0000", Ports: [][2]uint16{{0x20, 2}, {0xa0, 2}}, IRQs: []uint8{2}},
		{Name: "TIM0", ID: "PNP0100", Ports: [][2]uint16{{0x40, 4}}, IRQs: []uint8{0}},
		{Name: "RTC0", ID: "PNP0B00", Ports: [][2]uint16{{0x70, 2}}, IRQs: []uint8{8}},
		{Name: "KBD0", ID: "PNP0303", Ports: [][2]uint16{{0x60, 1}, {0x64, 1}}, IRQs: []uint8{1}},
		{Name: "MOU0", ID: "PNP0F13", IRQs: []uint8{12}},
		{Name: "IDE0", ID: "PNP0600", Ports: [][2]uint16{{0x1f0, 8}, {0x3f6, 1}}, IRQs: []uint8{14}},
		{Name: "PM00", ID: "PNP0C02", Ports: [][2]uint16{{acpiPMBase, 12}}},
	} {
		if dev.Name == "IDE0" && p.pciIDE != nil {
			continue // PCI enumerates this controller and owns its resources.
		}
		// Fixed legacy devices belong below the root bus. Windows starts
		// that bus and obtains its routing interface before assigning the
		// children's interrupt resources.
		dev.Parent = `\_SB.PCI0`
		data, err := dev.AML()
		if err != nil {
			return err
		}
		aml = append(aml, data...)
	}
	if p.hpet != nil {
		data, err := (acpi.ISADevice{Name: "HPET", ID: "PNP0103", Parent: `\_SB.PCI0`, Memory: [][2]uint32{{hpetAddress, 0x400}}}).AML()
		if err != nil {
			return err
		}
		aml = append(aml, data...)
	}
	// Name (\_S5, Package (4) {5,5,0,0}). No unsupported sleep states.
	aml = append(aml, 8, '\\', '_', 'S', '5', '_', 0x12, 8, 4, 0x0a, 5, 0x0a, 5, 0, 0)
	dsdt, err := table("DSDT", 2, aml)
	if err != nil {
		return err
	}
	// ACPI 2.0 FADT, using its legacy I/O register addresses.
	fadt := make([]byte, 244-36)
	binary.LittleEndian.PutUint32(fadt[0:], facsAddr)
	binary.LittleEndian.PutUint32(fadt[4:], dsdt)
	fadt[9] = 1 // Desktop.
	binary.LittleEndian.PutUint16(fadt[10:], 9)
	binary.LittleEndian.PutUint32(fadt[20:], acpiPMBase)
	binary.LittleEndian.PutUint32(fadt[28:], acpiPMBase+4)
	binary.LittleEndian.PutUint32(fadt[40:], acpiPMBase+8)
	fadt[52], fadt[53], fadt[55] = 4, 2, 4
	binary.LittleEndian.PutUint16(fadt[60:], 0xffff) // No C2/C3.
	binary.LittleEndian.PutUint16(fadt[62:], 0xffff)
	fadt[72] = 0x32                                       // CMOS century register.
	binary.LittleEndian.PutUint16(fadt[73:], 3)           // Legacy devices and 8042 present.
	binary.LittleEndian.PutUint32(fadt[76:], 1|1<<2|1<<5) // WBINVD, C1, no fixed sleep button.
	binary.LittleEndian.PutUint64(fadt[96:], uint64(facsAddr))
	binary.LittleEndian.PutUint64(fadt[104:], uint64(dsdt))
	fadtAddr, err := table("FACP", 3, fadt)
	if err != nil {
		return err
	}
	madt := binary.LittleEndian.AppendUint32(nil, 0xfee00000)
	madt = binary.LittleEndian.AppendUint32(madt, 1) // Dual PIC present.
	madt = append(madt, 0, 8, 0, 0, 1, 0, 0, 0)      // CPU0, local APIC ID0, enabled.
	madt = append(madt, 1, 12, 0, 0)
	madt = binary.LittleEndian.AppendUint32(madt, 0xfec00000)
	madt = binary.LittleEndian.AppendUint32(madt, 0)
	madt = append(madt, 2, 10, 0, 0, 2, 0, 0, 0, 0, 0)    // PIT IRQ0 -> GSI2.
	madt = append(madt, 2, 10, 0, 9, 9, 0, 0, 0, 0x0d, 0) // SCI high/level.
	madt = append(madt, 4, 6, 0xff, 0, 0, 1)              // NMI on LINT1.
	madtAddr, err := table("APIC", 1, madt)
	if err != nil {
		return err
	}
	roots := []uint32{fadtAddr, madtAddr}
	if p.hpet != nil {
		body := make([]byte, 20)
		binary.LittleEndian.PutUint32(body, uint32(hpetCapabilities&0xffffffff))
		body[5] = 64 // System-memory GAS, 64-bit registers.
		binary.LittleEndian.PutUint64(body[8:], hpetAddress)
		binary.LittleEndian.PutUint16(body[17:], 128)
		address, err := table("HPET", 1, body)
		if err != nil {
			return err
		}
		roots = append(roots, address)
	}
	var root32, root64 []byte
	for _, address := range roots {
		root32 = binary.LittleEndian.AppendUint32(root32, address)
		root64 = binary.LittleEndian.AppendUint64(root64, uint64(address))
	}
	rsdt, err := table("RSDT", 1, root32)
	if err != nil {
		return err
	}
	xsdt, err := table("XSDT", 1, root64)
	if err != nil {
		return err
	}
	rsdp, err := acpi.RootPointerTables(rsdt, uint64(xsdt), "TREXOS")
	if err != nil {
		return err
	}
	copy(p.ram[0xe0000:], rsdp)
	p.acpi = &acpiPM{started: p.now(), control: 1, setIRQ: p.cpu.SetIRQ}
	return nil
}
